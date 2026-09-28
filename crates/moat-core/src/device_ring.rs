//! Device ring: steady-state same-user key-package lane.
//!
//! Two responsibilities:
//!
//! - **The ring itself** — an ordinary MLS group spanning every device
//!   sharing one DID, tracked here as [`RingMembership`]. This module only
//!   reports on it ([`DeviceRingState::ring_id`]) and queries its live
//!   membership directly via `MoatSession::get_group_members` (see
//!   [`DeviceRingState::ring_joined_siblings`]); creating the ring and
//!   adding devices to it is handled in `moat-core/src/pairing.rs`.
//! - **The steady-state key-package lane** — once two devices share a ring,
//!   siblings exchange fresh MLS key packages over the stealth
//!   (`EventKind::SiblingMsg`) lane so any of them can add the others to
//!   *user* conversations without a shared-pool draw. See [`CoordMsg`],
//!   [`KpPool`], and [`DeviceRingState::on_sibling_msg`].
//!
//! # Signing-key identity
//!
//! Every KeyPackage a device offers over the KP lane must carry that
//! device's *identity* signing key (`env.key_bundle`), so KPs are minted
//! with [`MoatSession::replenish_key_package`], never `generate_key_package`,
//! which would mint a fresh throwaway keypair.
//!
//! This is load-bearing. A leaf's signing key is what the app later signs
//! with to author into that group, and the app only ever holds one such
//! key. A leaf created from a KP with any other signing key is unusable:
//! every subsequent `encrypt_event` into that group fails with "Own member
//! not found in group". Reusing the signing key shares nothing else — init
//! and encryption keys stay unique per KP, so the single-use pool semantics
//! are unaffected.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::{encrypt_for_stealth, try_decrypt_stealth, Error, Event, MoatCredential, MoatSession, Result};

// ─── Group classification ───────────────────────────────────────────────────

/// Classification of an MLS group by its role within the Moat multi-device system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    /// A user-facing conversation (default for all existing groups).
    #[default]
    User,
    /// The N-party device ring spanning all devices with the same DID.
    Ring,
}

// ─── Coordination messages ──────────────────────────────────────────────────

/// Steady-state key-package-lane messages, stealth-delivered as
/// `EventKind::SiblingMsg` payloads (see [`DeviceRingState::on_sibling_msg`]).
/// Always addressed to one specific sibling by device id.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordMsg {
    /// Owner ships a batch of fresh MLS key packages over the ring to a
    /// specific consumer for use in same-user `add_device` operations.
    /// Each entry carries its own monotonic `seq` so the consumer can dedupe
    /// replays and reject out-of-order delivery.
    KpBatch {
        /// Device id of the intended recipient (16 bytes). Other ring
        /// members ignore the batch.
        #[serde_as(as = "Base64")]
        recipient_device_id: Vec<u8>,
        kps: Vec<OfferedKp>,
    },
    /// Consumer asks the owner to top up the local pool of the owner's
    /// key packages. `count` is a hint; the owner caps at `KP_BATCH_CAP`.
    KpRequest {
        /// Device id of the owner the consumer wants more KPs from.
        #[serde_as(as = "Base64")]
        owner_device_id: Vec<u8>,
        count: u32,
    },
    /// Same-user fan-out: a sibling added the new sibling (`owner_device_id`)
    /// to one of the sender's user conversations using a KP drawn from the
    /// new sibling's ring-borne pool.  The Welcome embeds the MLS init
    /// secret the recipient must already hold locally (it generated the KP
    /// in `build_kp_batch`).  Other ring members ignore this message.
    UserConvWelcome {
        /// Device id of the intended recipient (16 bytes).  The Welcome
        /// only makes sense to the device whose init key is referenced.
        #[serde_as(as = "Base64")]
        owner_device_id: Vec<u8>,
        /// MLS group id of the user conversation the recipient is joining.
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        /// Raw MLS Welcome bytes.
        #[serde_as(as = "Base64")]
        welcome: Vec<u8>,
    },
}

/// A single key package entry inside a `CoordMsg::KpBatch`. The `seq` is
/// owner-issued and strictly monotonic per owner globally — consumers
/// dedupe by tracking the highest `seq` they've ingested per `(consumer,
/// owner)` pair and enforce single-use via a separate `used_kps` set.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferedKp {
    /// Owner-allocated 16-byte identifier for this KP (also serves as the
    /// key the owner's local keystore indexes the init-key material by).
    #[serde_as(as = "Base64")]
    pub rkey: Vec<u8>,
    /// Monotonic owner-global sequence number. Larger = newer.
    pub seq: u64,
    /// Serialized MLS KeyPackage bytes.
    #[serde_as(as = "Base64")]
    pub key_package: Vec<u8>,
}

/// Encode a [`CoordMsg`] to bytes suitable for use as `Event.payload`.
pub fn encode_coord_msg(msg: &CoordMsg) -> Vec<u8> {
    serde_json::to_vec(msg).expect("CoordMsg serialization should never fail")
}

/// Decode a [`CoordMsg`] from `Event.payload` bytes.
pub fn decode_coord_msg(bytes: &[u8]) -> Result<CoordMsg> {
    serde_json::from_slice(bytes).map_err(|e| Error::Deserialization(e.to_string()))
}

// ─── State types ────────────────────────────────────────────────────────────

/// Stable 16-byte device identifier (the `device_id` field of `MoatCredential`).
pub type DeviceId = [u8; 16];

/// Target number of an owner's key packages a consumer maintains locally.
pub const KP_POOL_TARGET: usize = 8;

/// Low-water mark: when the local pool of an owner's KPs drops to this
/// value, the consumer issues a `CoordMsg::KpRequest` to refill.
pub const KP_POOL_LOW_WATER: usize = 2;

/// Maximum number of [`OfferedKp`] entries the owner ships in a single
/// [`CoordMsg::KpBatch`].  Larger refills are split across multiple
/// messages so each fits inside the 4 KB padding bucket.
pub const KP_BATCH_CAP: usize = 4;

/// Target number of *our own* published key packages that still have a live
/// init key, maintained on the public `social.moat.keyPackage` pool.
///
/// Distinct from [`KP_POOL_TARGET`], which is the consumer-side pool of a
/// *sibling's* packages received over the same-user stealth lane. This one is
/// about staying invitable at all.
pub const KP_SELF_POOL_TARGET: usize = 4;

/// Low-water mark for our own live published packages. Dropping to or below
/// this triggers replenishment on the next tick, independently of whether we
/// have processed a Welcome.
///
/// The independence is the point. Every other replenishment site fires only
/// *after* a successful `process_welcome`, which makes an exhausted pool
/// terminal: a device with no live package cannot be invited to anything, so
/// it never processes a Welcome, so it never republishes. Peers keep drawing
/// its spent packages — indistinguishable on the PDS from live ones — and
/// building Welcomes it cannot process. See `pooled-invite-keys.md`.
pub const KP_SELF_LOW_WATER: usize = 2;

/// Consumer-side pool of one owner's KPs, plus the dedupe / single-use
/// state needed to defend against replay, out-of-order delivery, and
/// adversarial pool reinsertion.
///
/// One [`KpPool`] is kept per `(consumer, owner)` pair — i.e. on a
/// device's `DeviceRingState`, one [`KpPool`] per *owner* device id we
/// can claim KPs from.  See `protocol_model_ring_transport.rs` for the
/// invariants this represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KpPool {
    /// KPs received from this owner that have not yet been claimed.  New
    /// entries are appended on `ingest_kp_batch`; claims drain in
    /// monotonic `seq` order.
    pub local_pool: Vec<OfferedKp>,

    /// Highest `seq` we have *ever* observed from this owner (used or
    /// not).  Replay defence: a `KpBatch` whose entries are all
    /// `seq <= highest_seq_observed` is dropped on ingest.
    pub highest_seq_observed: u64,

    /// `seq`s the consumer has actually claimed.  Single-use enforcement:
    /// `claim_kp` refuses to return an entry whose `seq` is in this set,
    /// even if a buggy refill / replay re-inserts it.  Grows monotonically
    /// — see `same-user-key-distribution.md` for the storage tradeoff.
    pub used_kps: std::collections::HashSet<u64>,
}

/// Device-level ring membership: either not yet part of a ring, or a
/// confirmed MLS member of one. The ring is created and devices are added
/// to it exactly once, directly, by `pairing.rs` — there is nothing to
/// discover or reconcile here.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RingMembership {
    /// No ring known.
    #[default]
    Solo,

    /// We are an MLS member of a ring.
    InRing {
        #[serde_as(as = "Base64")]
        ring_id: Vec<u8>,
        created_at: i64,
        our_leaf: u32,
    },
}

/// Top-level state owned by the host.  Serialized as JSON for persistence.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRingState {
    ring: RingMembership,
    /// Cursor (rkey) for incremental own-PDS stealth scan.
    own_events_cursor: Option<String>,

    /// Owner-global monotonic counter for `OfferedKp.seq`.  Incremented
    /// every time we publish a KP into a `KpBatch` (any recipient).  See
    /// `same-user-key-distribution.md` — a single per-owner counter is
    /// simpler than per-(owner, recipient) and consumer dedupe doesn't
    /// care about gaps caused by other consumers' batches.
    next_kp_seq: u64,

    /// Per-owner pool we draw KPs from when adding the owner to a user
    /// conversation.  Key is the owner's hex-encoded `device_id`.
    kp_pools: HashMap<String, KpPool>,
}

// ─── Event / command surface ────────────────────────────────────────────────

/// Per-step environment: identifying data the state machine needs on every call.
///
/// Re-supplied each `tick()` because the host already knows them; threading
/// them through avoids storing redundant copies inside `DeviceRingState`.
pub struct StepEnv<'a> {
    pub my_did: &'a str,
    pub credential: &'a MoatCredential,
    pub key_bundle: &'a [u8],
    pub now_ms: i64,
    /// Per-sibling stealth address records (`scan_pubkey` + `device_id`),
    /// used to address `EventKind::SiblingMsg` KP-lane traffic. Excludes
    /// our own device.
    pub sibling_stealth: &'a [SiblingStealth],
}

/// Sibling key package fed into [`DeviceRingState::tick`].
#[derive(Debug, Clone)]
pub struct KeyPackageInput {
    /// Raw TLS-serialised MLS key package.
    pub key_package: Vec<u8>,
}

/// Per-sibling stealth address record fed into [`DeviceRingState::tick`].
///
/// Used by the same-user KP lane: the ring driver needs each sibling's
/// `scan_pubkey` to stealth-encrypt `EventKind::SiblingMsg` payloads to
/// them, keyed by their stable `device_id`.
///
/// The host populates this list by fetching `social.moat.stealthAddress`
/// records under our own DID and filtering out our own device.
#[derive(Debug, Clone)]
pub struct SiblingStealth {
    pub scan_pubkey: [u8; 32],
    pub device_id: DeviceId,
}

/// Own-PDS event fed into [`DeviceRingState::tick`] for stealth scan.
#[derive(Debug, Clone)]
pub struct OwnEventInput {
    /// Record rkey, used to advance the cursor across calls.
    pub rkey: String,
    /// Raw stealth-encrypted ciphertext as fetched from the PDS.
    pub ciphertext: Vec<u8>,
}

/// Inputs to a single ring-driver tick (convenience bundle).
pub struct TickInputs<'a> {
    pub key_packages: &'a [KeyPackageInput],
    /// Per-sibling stealth address records, used to address same-user KP
    /// lane messages. Should exclude our own device.
    pub sibling_stealth: &'a [SiblingStealth],
    pub own_events: &'a [OwnEventInput],
    pub stealth_privkey: &'a [u8; 32],
    pub credential: &'a MoatCredential,
    pub key_bundle: &'a [u8],
    pub now_ms: i64,
    pub my_did: &'a str,
}

/// Side effect requested by the ring state machine.  The host interprets
/// these in terms of its own I/O layer (PDS publish, persistence).
#[derive(Debug, Clone)]
pub enum RingCommand {
    /// Publish a stealth-encrypted sibling event for a specific sibling.
    /// The payload inside is an `EventKind::SiblingMsg` event (steady-state
    /// `KpBatch` / `KpRequest` / `UserConvWelcome` CoordMsg JSON); the
    /// recipient's own-PDS stealth scan picks it up.  Stealth delivery is
    /// epoch-free and order-insensitive.
    PublishStealthEvent {
        tag: [u8; 16],
        ciphertext: Vec<u8>,
    },
    /// We just consumed our init key processing a Welcome — replenish our
    /// published key package so we stay invitable.
    ReplenishKeyPackage,
    /// Register a newly-classified group with the host's metadata store and
    /// candidate-tag set.
    RegisterGroup {
        group_id: Vec<u8>,
        kind: GroupKind,
    },
    /// Every tick with a sibling: add siblings to conversations they're not in.
    PollForNewDevices,
}

impl RingCommand {
    /// Short stable name for this command, for host debug logs and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            RingCommand::PublishStealthEvent { .. } => "publish_stealth_event",
            RingCommand::ReplenishKeyPackage => "replenish_key_package",
            RingCommand::RegisterGroup { .. } => "register_group",
            RingCommand::PollForNewDevices => "poll_for_new_devices",
        }
    }
}

/// Render a command list as `name xN, name xM` for a one-line log.
pub fn summarize_ring_commands(cmds: &[RingCommand]) -> String {
    if cmds.is_empty() {
        return "none".to_string();
    }
    let mut counts: Vec<(&'static str, usize)> = Vec::new();
    for c in cmds {
        match counts.iter_mut().find(|(k, _)| *k == c.kind()) {
            Some((_, n)) => *n += 1,
            None => counts.push((c.kind(), 1)),
        }
    }
    counts
        .into_iter()
        .map(|(k, n)| if n == 1 { k.to_string() } else { format!("{k} x{n}") })
        .collect::<Vec<_>>()
        .join(", ")
}

// ─── State machine impl ────────────────────────────────────────────────────

impl DeviceRingState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ring group id, if any.
    pub fn ring_id(&self) -> Option<&[u8]> {
        match &self.ring {
            RingMembership::InRing { ring_id, .. } => Some(ring_id.as_slice()),
            _ => None,
        }
    }

    pub fn ring_created_at(&self) -> Option<i64> {
        match &self.ring {
            RingMembership::InRing { created_at, .. } => Some(*created_at),
            _ => None,
        }
    }

    /// Record that we are now an MLS member of `ring_id`, looking up our own
    /// leaf index from the group's member list. Called once, host-side, when
    /// a pairing exchange completes (qr-pairing.md Phase 3): the new device
    /// from `PairingCommand::PersistRing`, the existing device right after a
    /// successful `PairingSession::approve()` (which has no command of its
    /// own for this — the existing device already knows it just
    /// created/joined `ring_id`).
    pub fn record_ring_membership(
        &mut self,
        mls: &MoatSession,
        ring_id: Vec<u8>,
        now_ms: i64,
    ) -> Result<()> {
        let our_leaf = mls
            .get_group_members(&ring_id)?
            .into_iter()
            .find(|(_, cred)| cred.as_ref().map(|c| *c.device_id()) == Some(*mls.device_id()))
            .map(|(leaf, _)| leaf)
            .ok_or_else(|| {
                Error::GroupLoad("own device not found in ring member list after pairing".into())
            })?;
        self.ring = RingMembership::InRing { ring_id, created_at: now_ms, our_leaf };
        Ok(())
    }

    /// One-line, human-readable snapshot of ring membership, for host debug
    /// logs.
    ///
    /// Deliberately lives here rather than in each host: `moat-cli` and the
    /// Dart `DeviceRingService` both need it, and a hand-rolled match in each
    /// would drift the moment a variant is added. Format is for humans and is
    /// not stable — do not parse it.
    pub fn debug_summary(&self) -> String {
        let ring = match &self.ring {
            RingMembership::Solo => "solo".to_string(),
            RingMembership::InRing { ring_id, our_leaf, .. } => {
                format!("in_ring(leaf={our_leaf},id={})", &hex::encode(ring_id)[..8.min(ring_id.len() * 2)])
            }
        };
        format!("ring={ring} kp_pools={} cursor={:?}", self.kp_pools.len(), self.own_events_cursor)
    }

    pub fn own_events_cursor(&self) -> Option<&str> {
        self.own_events_cursor.as_deref()
    }

    pub fn set_own_events_cursor(&mut self, rkey: String) {
        self.own_events_cursor = Some(rkey);
    }

    pub fn allocate_kp_seqs(&mut self, count: usize) -> Vec<u64> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            self.next_kp_seq = self.next_kp_seq.saturating_add(1);
            out.push(self.next_kp_seq);
        }
        out
    }

    /// Highest `seq` we have issued so far (next allocation will be
    /// `highest + 1`).  Mostly for tests / debugging.
    pub fn highest_issued_kp_seq(&self) -> u64 {
        self.next_kp_seq
    }

    /// Number of unclaimed KPs we hold for this owner.
    pub fn kp_pool_size(&self, owner: &DeviceId) -> usize {
        let key = hex::encode(owner);
        self.kp_pools.get(&key).map(|p| p.local_pool.len()).unwrap_or(0)
    }

    /// Ingest a batch of [`OfferedKp`]s received from `owner`.  Drops
    /// entries with `seq <= highest_seq_observed` (replay defence) and
    /// any whose `seq` is already in `used_kps` (consumer flag defence).
    /// Survivors are appended to `local_pool`.
    pub fn ingest_kp_batch(&mut self, owner: &DeviceId, batch: Vec<OfferedKp>) {
        let key = hex::encode(owner);
        let pool = self.kp_pools.entry(key).or_default();
        let mut highest = pool.highest_seq_observed;
        for kp in batch {
            if kp.seq <= highest {
                continue;
            }
            if pool.used_kps.contains(&kp.seq) {
                // Already consumed under this seq — shouldn't usually happen
                // since seqs only repeat via adversarial reinsertion, but be
                // defensive.
                continue;
            }
            highest = kp.seq;
            pool.local_pool.push(kp);
        }
        pool.highest_seq_observed = highest;
    }

    /// Claim the lowest-`seq` unused KP from the owner's pool, mark it
    /// used, and return it.  Returns `None` if the pool is empty or every
    /// entry is somehow already in `used_kps` (the latter would be an
    /// adversarial / buggy state).
    pub fn claim_kp(&mut self, owner: &DeviceId) -> Option<OfferedKp> {
        let key = hex::encode(owner);
        let pool = self.kp_pools.get_mut(&key)?;
        // Entries are appended in monotonic seq order by `ingest_kp_batch`,
        // so the first not-yet-used position is the lowest seq.
        let idx = pool
            .local_pool
            .iter()
            .position(|kp| !pool.used_kps.contains(&kp.seq))?;
        let kp = pool.local_pool.remove(idx);
        pool.used_kps.insert(kp.seq);
        Some(kp)
    }

    /// Returns the number of KPs we should request from `owner` if the
    /// pool is at or below the low-water mark, else `None`.  Refill
    /// target is `KP_POOL_TARGET`; the count is the gap from current
    /// pool size up to target.
    pub fn kp_request_if_low(&self, owner: &DeviceId) -> Option<u32> {
        let len = self.kp_pool_size(owner);
        if len <= KP_POOL_LOW_WATER {
            Some((KP_POOL_TARGET - len) as u32)
        } else {
            None
        }
    }

    /// Process own-PDS stealth events, then settle periodic work.
    pub fn tick(&mut self, mls: &MoatSession, inputs: TickInputs<'_>) -> Vec<RingCommand> {
        let env = StepEnv {
            my_did: inputs.my_did,
            credential: inputs.credential,
            key_bundle: inputs.key_bundle,
            now_ms: inputs.now_ms,
            sibling_stealth: inputs.sibling_stealth,
        };
        let mut cmds = Vec::new();
        for ev in inputs.own_events {
            if let Some(plaintext) = try_decrypt_stealth(inputs.stealth_privkey, &ev.ciphertext) {
                cmds.extend(self.on_stealth_payload(mls, &env, &plaintext));
            }
            if !ev.rkey.is_empty() {
                self.own_events_cursor = Some(ev.rkey.clone());
            }
        }
        cmds.extend(self.on_tick(mls, &env, inputs.key_packages));
        cmds
    }

    // ─── Event handlers ───────────────────────────────────────────────────

    /// Decode a stealth-decrypted own-PDS payload as an `EventKind::SiblingMsg`
    /// and dispatch it. Anything else (padding noise, a foreign payload) is
    /// silently ignored — this scan used to also catch ring/coord Welcome
    /// envelopes, which no longer arrive this way (see the module docs).
    fn on_stealth_payload(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        plaintext: &[u8],
    ) -> Vec<RingCommand> {
        let unpadded = crate::padding::unpad(plaintext);
        if unpadded.first() == Some(&b'{') {
            if let Ok(ev) = Event::from_bytes(&unpadded) {
                if matches!(ev.kind, crate::EventKind::SiblingMsg) {
                    let sender: DeviceId = match ev
                        .sender_device_id
                        .as_deref()
                        .and_then(|b| b.try_into().ok())
                    {
                        Some(id) => id,
                        None => return Vec::new(),
                    };
                    let msg = match decode_coord_msg(&ev.payload) {
                        Ok(m) => m,
                        Err(_) => return Vec::new(),
                    };
                    return self.on_sibling_msg(mls, env, sender, msg);
                }
            }
        }
        Vec::new()
    }

    /// Handle a stealth-delivered sibling CoordMsg (`EventKind::SiblingMsg`).
    ///
    /// `sender` comes from the unauthenticated `Event.sender_device_id`
    /// field — the stealth layer proves only that the publisher could write
    /// to our own repo.  For `KpBatch` (the payload that could trick us
    /// into adding a foreign device to user conversations) every entry is
    /// therefore validated: the KP signature must verify and its embedded
    /// credential must claim our DID and the sender's device id, and the
    /// sender must be a confirmed ring member.  (Hardening TODO, tracked in
    /// `same-user-key-distribution.md`: pin the KP signature key to the
    /// sender's ring leaf credential.)  A forged `KpRequest` is at most a
    /// top-up nuisance; a forged `UserConvWelcome` fails init-key lookup.
    fn on_sibling_msg(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        sender: DeviceId,
        msg: CoordMsg,
    ) -> Vec<RingCommand> {
        let my_device_id = *mls.device_id();
        match msg {
            CoordMsg::KpBatch { recipient_device_id, kps } => {
                if recipient_device_id.as_slice() != &my_device_id[..] {
                    // Addressed to another sibling (shouldn't decrypt for
                    // us at all, but be defensive).
                    return Vec::new();
                }
                if !self.ring_joined_siblings(mls).contains(&sender) {
                    // Not (yet) a confirmed ring member.  Drop; once the
                    // ring Welcome lands, the low-water `KpRequest` path
                    // refills the pool on a later tick.
                    return Vec::new();
                }
                let verified: Vec<OfferedKp> = kps
                    .into_iter()
                    .filter(|kp| {
                        matches!(
                            mls.extract_credential_from_key_package(&kp.key_package),
                            Ok(Some(ref c)) if c.did() == env.my_did && *c.device_id() == sender
                        )
                    })
                    .collect();
                if verified.is_empty() {
                    return Vec::new();
                }
                self.ingest_kp_batch(&sender, verified);
                self.maybe_emit_kp_request(mls, env, &sender)
            }
            CoordMsg::KpRequest { owner_device_id, count } => {
                if owner_device_id.as_slice() != &my_device_id[..] {
                    return Vec::new();
                }
                self.fulfil_kp_request(mls, env, sender, count)
            }
            CoordMsg::UserConvWelcome { owner_device_id, group_id, welcome } => {
                if owner_device_id.as_slice() != &my_device_id[..] {
                    return Vec::new();
                }
                // The init key for this Welcome lives in our local keystore
                // (we generated it in `build_kp_batch` and shipped the
                // public KP via `CoordMsg::KpBatch`).  `process_welcome`
                // consumes it.  No `ReplenishKeyPackage` is emitted: the
                // consumed key was a pool init key, not a PDS-pool one, so
                // the cross-user `social.moat.keyPackage` pool is
                // untouched.  A replayed Welcome fails init-key lookup and
                // is dropped by `process_welcome`.
                match mls.process_welcome(&welcome) {
                    Ok(joined_group_id) => {
                        // Guard against a mismatched payload: the Welcome
                        // should land us in exactly the advertised group.
                        if joined_group_id != group_id {
                            return Vec::new();
                        }
                        vec![RingCommand::RegisterGroup {
                            group_id,
                            kind: GroupKind::User,
                        }]
                    }
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    /// If the consumer's pool of `owner`'s KPs is at or below the
    /// low-water mark, emit a `CoordMsg::KpRequest` to the owner via the
    /// stealth lane.  No-op if not in a ring or if the pool is above the
    /// mark.
    fn maybe_emit_kp_request(
        &self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        owner: &DeviceId,
    ) -> Vec<RingCommand> {
        let count = match self.kp_request_if_low(owner) {
            Some(c) => c,
            None => return Vec::new(),
        };
        if !matches!(self.ring, RingMembership::InRing { .. }) {
            return Vec::new();
        }
        let request = CoordMsg::KpRequest {
            owner_device_id: owner.to_vec(),
            count,
        };
        encrypt_sibling_msg(mls, env, owner, &request)
            .map(|cmd| vec![cmd])
            .unwrap_or_default()
    }

    /// Public version of [`maybe_emit_kp_request`] for the host's same-user
    /// fan-out path: forces an unconditional `KpRequest` to `owner` when
    /// the host has discovered it cannot draw a KP from the pool.  Caps
    /// the request at `KP_POOL_TARGET` (the natural batch ceiling).  No-op
    /// if not in a ring.
    pub fn emit_kp_request_for(
        &self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        owner: &DeviceId,
    ) -> Vec<RingCommand> {
        if !matches!(self.ring, RingMembership::InRing { .. }) {
            return Vec::new();
        }
        let request = CoordMsg::KpRequest {
            owner_device_id: owner.to_vec(),
            count: KP_POOL_TARGET as u32,
        };
        encrypt_sibling_msg(mls, env, owner, &request)
            .map(|cmd| vec![cmd])
            .unwrap_or_default()
    }

    /// Stealth-encrypt an arbitrary [`CoordMsg`] to a specific sibling and
    /// return the stealth-publish command the host can interpret.  Used by
    /// the same-user fan-out path to publish [`CoordMsg::UserConvWelcome`]
    /// without re-implementing the envelope framing in the host.  Returns
    /// `None` if not in a ring or if the sibling's stealth record is not
    /// known.
    pub fn encrypt_for_sibling(
        &self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        recipient: &DeviceId,
        msg: &CoordMsg,
    ) -> Option<RingCommand> {
        if !matches!(self.ring, RingMembership::InRing { .. }) {
            return None;
        }
        encrypt_sibling_msg(mls, env, recipient, msg)
    }

    /// Device ids of siblings confirmed as live MLS members of our ring.
    ///
    /// Queries `MoatSession::get_group_members` directly: the ring's own
    /// MLS membership is the source of truth for "who is a confirmed
    /// sibling", so no separate peer bookkeeping is needed. Returns an
    /// empty list if we are not in a ring, or if `ring_id` doesn't resolve
    /// to a real local MLS group (e.g. in tests that set a synthetic ring
    /// id without actually creating the group).
    pub fn ring_joined_siblings(&self, mls: &MoatSession) -> Vec<DeviceId> {
        let ring_id = match &self.ring {
            RingMembership::InRing { ring_id, .. } => ring_id,
            RingMembership::Solo => return Vec::new(),
        };
        let my_device_id = *mls.device_id();
        mls.get_group_members(ring_id)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, cred)| cred.map(|c| *c.device_id()))
            .filter(|id| *id != my_device_id)
            .collect()
    }

    /// Owner-side response to a `KpRequest` from `consumer`: generate
    /// `count` fresh KPs (capped at `KP_BATCH_CAP` per batch, splitting
    /// across multiple emits if more are asked for), allocate monotonic
    /// seqs, and emit one `CoordMsg::KpBatch` per chunk via the stealth
    /// lane.
    fn fulfil_kp_request(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        consumer: DeviceId,
        count: u32,
    ) -> Vec<RingCommand> {
        if !matches!(self.ring, RingMembership::InRing { .. }) {
            return Vec::new();
        }
        let mut cmds = Vec::new();
        let mut remaining = count as usize;
        while remaining > 0 {
            let take = remaining.min(KP_BATCH_CAP);
            let batch = match self.build_kp_batch(mls, env, take) {
                Some(b) => b,
                None => break,
            };
            let msg = CoordMsg::KpBatch {
                recipient_device_id: consumer.to_vec(),
                kps: batch,
            };
            if let Some(cmd) = encrypt_sibling_msg(mls, env, &consumer, &msg) {
                cmds.push(cmd);
            }
            remaining -= take;
        }
        cmds
    }

    /// Generate `count` fresh KPs and wrap them as `OfferedKp`s with
    /// monotonic owner-global seqs.  Init keys land in our local keystore
    /// so we can decrypt the Welcomes the consumer will eventually send back.
    ///
    /// `replenish_key_package`, not `generate_key_package`: each KP must carry
    /// our *identity* signing key.  See the module note on signing-key identity.
    fn build_kp_batch(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        count: usize,
    ) -> Option<Vec<OfferedKp>> {
        let seqs = self.allocate_kp_seqs(count);
        let mut out = Vec::with_capacity(count);
        for seq in seqs {
            let kp_bytes = mls
                .replenish_key_package(env.credential, env.key_bundle)
                .ok()?;
            let mut rkey = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut rkey);
            out.push(OfferedKp {
                rkey: rkey.to_vec(),
                seq,
                key_package: kp_bytes,
            });
        }
        Some(out)
    }

    /// For every confirmed ring-member sibling, fire a `CoordMsg::KpRequest`
    /// if our local pool of that sibling's KPs is at or below the low-water
    /// mark.  Duplicate requests are tolerated (owner ships an extra
    /// batch; consumer dedupes by `highest_seq_observed`).
    fn emit_low_water_kp_requests(
        &self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
    ) -> Vec<RingCommand> {
        if !matches!(self.ring, RingMembership::InRing { .. }) {
            return Vec::new();
        }
        let mut cmds = Vec::new();
        for owner in self.ring_joined_siblings(mls) {
            cmds.extend(self.maybe_emit_kp_request(mls, env, &owner));
        }
        cmds
    }

    /// Publish fresh key packages when the number of *published* packages we
    /// can still be invited with runs low.
    ///
    /// The only replenishment path that does not depend on having processed a
    /// Welcome, and therefore the only one that can rescue a device whose pool
    /// is already exhausted. See [`KP_SELF_LOW_WATER`].
    ///
    /// Counts the intersection of two things, which is what makes it
    /// trustworthy: the package must be **on the PDS** (it comes from the
    /// tick's own-DID fetch, the same one used for sibling discovery, so it is
    /// free) *and* we must still hold its init key
    /// ([`MoatSession::holds_init_key`]). Counting only local bundles would
    /// miss a package that was minted but never published — a failed PDS write
    /// would leave the device believing it was invitable when nothing usable
    /// was actually reachable. Counting only published records is worse still,
    /// since spent and live records are indistinguishable on the PDS.
    ///
    /// Emits one [`RingCommand::ReplenishKeyPackage`] per package needed; the
    /// host mints and publishes each. Runs on every tick regardless of ring
    /// membership — a device with no siblings at all still has to stay
    /// invitable by cross-user contacts.
    ///
    /// Transient over-publication is possible and deliberate: freshly
    /// published packages take a tick or two to appear in the fetch, so a
    /// device may top up twice. That deepens the pool, which is the direction
    /// `pooled-invite-keys.md` wants anyway, and it is self-limiting once the
    /// writes land.
    fn replenish_own_key_packages(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        key_packages: &[KeyPackageInput],
    ) -> Vec<RingCommand> {
        let my_device_id = *mls.device_id();
        let usable = key_packages
            .iter()
            .filter(|kp| {
                mls.extract_credential_from_key_package(&kp.key_package)
                    .ok()
                    .flatten()
                    .map(|c| c.did() == env.my_did && *c.device_id() == my_device_id)
                    .unwrap_or(false)
            })
            .filter(|kp| mls.holds_init_key(&kp.key_package))
            .count();

        if usable > KP_SELF_LOW_WATER {
            return Vec::new();
        }
        (usable..KP_SELF_POOL_TARGET)
            .map(|_| RingCommand::ReplenishKeyPackage)
            .collect()
    }

    fn on_tick(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        key_packages: &[KeyPackageInput],
    ) -> Vec<RingCommand> {
        let mut cmds = Vec::new();

        // Keep ourselves invitable.
        cmds.extend(self.replenish_own_key_packages(mls, env, key_packages));

        // Top up KP pools that are at-or-below low-water.
        cmds.extend(self.emit_low_water_kp_requests(mls, env));

        // PollForNewDevices fires on every tick while we have at least one
        // confirmed ring sibling — this drives the per-conversation
        // add_device fan-out on the inviting side. `poll_for_new_devices`
        // is idempotent — it skips conversations that already contain a
        // given sibling — so firing it unconditionally here is safe.
        if !self.ring_joined_siblings(mls).is_empty() {
            cmds.push(RingCommand::PollForNewDevices);
        }

        cmds
    }
}

/// Encode `msg`, wrap it in an `EventKind::SiblingMsg` envelope carrying our
/// device id, pad to the standard bucket, stealth-encrypt to `recipient`'s
/// `scan_pubkey` (looked up from `env.sibling_stealth`), and return the
/// generic stealth-publish command.  This is the steady-state carrier for
/// the same-user KP lane — epoch-free and order-insensitive, unlike MLS
/// application messages over the ring (see `same-user-key-distribution.md`).
///
/// Returns `None` if the recipient's stealth record is not (yet) known; the
/// consumer-driven `KpRequest` refill path makes a skipped send self-healing
/// on a later tick.
fn encrypt_sibling_msg(
    mls: &MoatSession,
    env: &StepEnv<'_>,
    recipient: &DeviceId,
    msg: &CoordMsg,
) -> Option<RingCommand> {
    let scan_pubkey = env
        .sibling_stealth
        .iter()
        .find(|s| s.device_id == *recipient)?
        .scan_pubkey;
    let event = Event::sibling_msg(mls.device_id().to_vec(), encode_coord_msg(msg));
    let event_bytes = event.to_bytes().ok()?;
    // A `CoordMsg` that outgrew the largest bucket cannot be published:
    // there is no bucket to round it up to. Dropping the command is the
    // existing failure mode for this helper (every step above uses `?` on
    // an Option), and the only oversized payload it can build is a
    // `KpBatch`, whose size the caller controls.
    let padded = crate::padding::pad_to_bucket(&event_bytes).ok()?;
    let ciphertext = encrypt_for_stealth(&[scan_pubkey], &padded).ok()?;
    Some(RingCommand::PublishStealthEvent {
        tag: rand::random(),
        ciphertext,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MoatCredential, MoatSession};

    fn make_credential(did: &str, name: &str, dev_id: [u8; 16]) -> MoatCredential {
        MoatCredential::new(did, name, dev_id)
    }

    #[test]
    fn empty_state_is_solo() {
        let s = DeviceRingState::new();
        assert!(matches!(s.ring, RingMembership::Solo));
    }

    #[test]
    fn ring_state_roundtrip_json() {
        let mut s = DeviceRingState::new();
        s.ring = RingMembership::InRing {
            ring_id: vec![1u8; 32],
            created_at: 12345,
            our_leaf: 0,
        };
        let json = serde_json::to_string(&s).expect("serialize");
        let restored: DeviceRingState = serde_json::from_str(&json).expect("deserialize");
        match restored.ring {
            RingMembership::InRing { ring_id, created_at, our_leaf } => {
                assert_eq!(ring_id, vec![1u8; 32]);
                assert_eq!(created_at, 12345);
                assert_eq!(our_leaf, 0);
            }
            other => panic!("expected InRing, got {other:?}"),
        }
    }

    /// Raw MLS-level reproduction of a three-device ring: D2 creates a
    /// 2-party ring and adds D1; then D1 (an existing ring member, NOT the
    /// ring creator) adds D3.  Confirms both that D3's Welcome processes
    /// successfully AND that D3's reconstructed view includes all three
    /// devices — i.e. the ratchet-tree extension gives a joiner full
    /// visibility into pre-existing members from a single Welcome, with no
    /// separate fetch needed. Exercises `MoatSession` directly, the same way
    /// `pairing.rs` drives ring creation and adds.
    #[test]
    fn third_device_add_by_non_creator_member_succeeds_at_mls_layer() {
        let d1 = MoatSession::new();
        let d2 = MoatSession::new();
        let d3 = MoatSession::new();
        let d1_cred = make_credential("did:plc:user", "d1", *d1.device_id());
        let d2_cred = make_credential("did:plc:user", "d2", *d2.device_id());
        let d3_cred = make_credential("did:plc:user", "d3", *d3.device_id());
        let (d1_kp, d1_kb) = d1.generate_key_package(&d1_cred).expect("d1 kp");
        let (_d2_kp, d2_kb) = d2.generate_key_package(&d2_cred).expect("d2 kp");
        let (d3_kp, _d3_kb) = d3.generate_key_package(&d3_cred).expect("d3 kp");

        // D2 creates the ring and adds D1.
        let ring_id = d2.create_group(&d2_cred, &d2_kb).expect("create ring");
        let wr1 = d2.add_device(&ring_id, &d2_kb, &d1_kp).expect("d2 add d1");
        let joined_by_d1 = d1.process_welcome(&wr1.welcome).expect("d1 join");
        assert_eq!(joined_by_d1, ring_id);

        // D1 (not the creator) adds D3.
        let wr2 = d1.add_device(&ring_id, &d1_kb, &d3_kp).expect("d1 add d3");
        let joined_by_d3 = d3.process_welcome(&wr2.welcome).expect("d3 join");
        assert_eq!(joined_by_d3, ring_id);

        let members = d3.get_group_members(&ring_id).expect("d3 members");
        assert_eq!(
            members.len(),
            3,
            "d3 must see all three devices (d1, d2, d3) from d1's Welcome alone, got {} members",
            members.len()
        );
    }

    #[test]
    fn record_ring_membership_sets_ring_id_and_own_leaf() {
        let d1 = MoatSession::new();
        let d2 = MoatSession::new();
        let d1_cred = make_credential("did:plc:user", "d1", *d1.device_id());
        let d2_cred = make_credential("did:plc:user", "d2", *d2.device_id());
        let (_d1_kp, d1_kb) = d1.generate_key_package(&d1_cred).expect("d1 kp");
        let (d2_kp, _d2_kb) = d2.generate_key_package(&d2_cred).expect("d2 kp");

        let ring_id = d1.create_group(&d1_cred, &d1_kb).expect("create ring");
        let wr = d1.add_device(&ring_id, &d1_kb, &d2_kp).expect("d1 add d2");
        let joined = d2.process_welcome(&wr.welcome).expect("d2 join");
        assert_eq!(joined, ring_id);

        let mut d1_state = DeviceRingState::new();
        d1_state
            .record_ring_membership(&d1, ring_id.clone(), 1_000)
            .expect("d1 record membership");
        let mut d2_state = DeviceRingState::new();
        d2_state
            .record_ring_membership(&d2, ring_id.clone(), 2_000)
            .expect("d2 record membership");

        assert_eq!(d1_state.ring_id(), Some(ring_id.as_slice()));
        assert_eq!(d2_state.ring_id(), Some(ring_id.as_slice()));
        assert_eq!(d1_state.ring_created_at(), Some(1_000));
        assert_eq!(d2_state.ring_created_at(), Some(2_000));

        let d1_members = d1.get_group_members(&ring_id).expect("d1 members");
        let d1_leaf = d1_members
            .iter()
            .find(|(_, cred)| cred.as_ref().map(|c| *c.device_id()) == Some(*d1.device_id()))
            .map(|(leaf, _)| *leaf)
            .expect("d1 in own member list");
        let d2_leaf = d1_members
            .iter()
            .find(|(_, cred)| cred.as_ref().map(|c| *c.device_id()) == Some(*d2.device_id()))
            .map(|(leaf, _)| *leaf)
            .expect("d2 in member list");
        assert_ne!(d1_leaf, d2_leaf, "the two devices must occupy distinct leaves");

        match d1_state.ring {
            RingMembership::InRing { our_leaf, .. } => assert_eq!(our_leaf, d1_leaf),
            ref other => panic!("expected InRing, got {other:?}"),
        }
        match d2_state.ring {
            RingMembership::InRing { our_leaf, .. } => assert_eq!(our_leaf, d2_leaf),
            ref other => panic!("expected InRing, got {other:?}"),
        }
    }

    #[test]
    fn record_ring_membership_errors_if_device_is_not_actually_a_member() {
        let mut outsider_state = DeviceRingState::new();
        let outsider = MoatSession::new();
        let creator = MoatSession::new();
        let creator_cred = make_credential("did:plc:user", "creator", *creator.device_id());
        let (_kp, kb) = creator.generate_key_package(&creator_cred).expect("kp");
        let ring_id = creator.create_group(&creator_cred, &kb).expect("create ring");

        let result = outsider_state.record_ring_membership(&outsider, ring_id, 0);
        assert!(
            result.is_err(),
            "a device that isn't actually a member of the ring must not be recorded as one"
        );
    }

    #[test]
    fn coord_msg_roundtrip_kp_batch() {
        let msg = CoordMsg::KpBatch {
            recipient_device_id: vec![3u8; 16],
            kps: vec![
                OfferedKp {
                    rkey: vec![1u8; 16],
                    seq: 1,
                    key_package: vec![0xAA; 64],
                },
                OfferedKp {
                    rkey: vec![2u8; 16],
                    seq: 2,
                    key_package: vec![0xBB; 64],
                },
            ],
        };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::KpBatch { recipient_device_id, kps } => {
                assert_eq!(recipient_device_id, vec![3u8; 16]);
                assert_eq!(kps.len(), 2);
                assert_eq!(kps[0].seq, 1);
                assert_eq!(kps[1].seq, 2);
                assert_eq!(kps[0].key_package, vec![0xAA; 64]);
                assert_eq!(kps[1].key_package, vec![0xBB; 64]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn coord_msg_roundtrip_kp_request() {
        let msg = CoordMsg::KpRequest {
            owner_device_id: vec![9u8; 16],
            count: 4,
        };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::KpRequest { owner_device_id, count } => {
                assert_eq!(owner_device_id, vec![9u8; 16]);
                assert_eq!(count, 4);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn coord_msg_roundtrip_user_conv_welcome() {
        let msg = CoordMsg::UserConvWelcome {
            owner_device_id: vec![7u8; 16],
            group_id: vec![3u8; 32],
            welcome: vec![0xAB; 256],
        };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::UserConvWelcome { owner_device_id, group_id, welcome } => {
                assert_eq!(owner_device_id, vec![7u8; 16]);
                assert_eq!(group_id, vec![3u8; 32]);
                assert_eq!(welcome, vec![0xAB; 256]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// A realistic batch of `KP_BATCH_CAP` real-sized MLS key packages
    /// fits inside the 4 KB padding bucket. Typical MLS key packages with
    /// the moat ciphersuite serialize to ~400-500 bytes; we pad to ~700 here
    /// to give headroom for credential and ciphersuite metadata.
    #[test]
    fn coord_msg_kp_batch_fits_in_4k_bucket() {
        let kp_size = 700; // generous upper bound for an MLS_128_X25519_AES128GCM KP
        let kps = (0..KP_BATCH_CAP as u64)
            .map(|i| OfferedKp {
                rkey: vec![i as u8; 16],
                seq: i + 1,
                key_package: vec![0xCC; kp_size],
            })
            .collect();
        let msg = CoordMsg::KpBatch {
            recipient_device_id: vec![5u8; 16],
            kps,
        };
        let bytes = encode_coord_msg(&msg);
        // 4 KB bucket - leave room for the outer Event JSON wrapper.
        assert!(
            bytes.len() <= 4096,
            "kp_batch with cap=4 must fit in 4 KB bucket (got {} bytes)",
            bytes.len()
        );
    }

    fn kp(seq: u64) -> OfferedKp {
        OfferedKp {
            rkey: vec![seq as u8; 16],
            seq,
            key_package: vec![0xAA; 8],
        }
    }

    #[test]
    fn allocate_kp_seqs_is_strictly_monotonic() {
        let mut s = DeviceRingState::new();
        assert_eq!(s.allocate_kp_seqs(3), vec![1, 2, 3]);
        assert_eq!(s.allocate_kp_seqs(2), vec![4, 5]);
        assert_eq!(s.highest_issued_kp_seq(), 5);
        assert!(s.allocate_kp_seqs(0).is_empty());
        assert_eq!(s.highest_issued_kp_seq(), 5);
    }

    #[test]
    fn ingest_kp_batch_appends_and_dedupes_by_seq() {
        let mut s = DeviceRingState::new();
        let owner: DeviceId = [9u8; 16];

        s.ingest_kp_batch(&owner, vec![kp(1), kp(2), kp(3)]);
        assert_eq!(s.kp_pool_size(&owner), 3);

        // Replay of same batch: all dropped.
        s.ingest_kp_batch(&owner, vec![kp(1), kp(2), kp(3)]);
        assert_eq!(s.kp_pool_size(&owner), 3);

        // Mixed: 2 is dup, 4/5 are new.
        s.ingest_kp_batch(&owner, vec![kp(2), kp(4), kp(5)]);
        assert_eq!(s.kp_pool_size(&owner), 5);

        // A seq lower than highest_seq_observed never makes it back in.
        s.ingest_kp_batch(&owner, vec![kp(3)]);
        assert_eq!(s.kp_pool_size(&owner), 5);
    }

    #[test]
    fn claim_kp_returns_lowest_seq_and_marks_used() {
        let mut s = DeviceRingState::new();
        let owner: DeviceId = [9u8; 16];

        s.ingest_kp_batch(&owner, vec![kp(2), kp(1), kp(3)]);
        // Despite ingest order, `local_pool` ordering means the first
        // entry not yet claimed has the lowest seq (because ingest only
        // accepts strictly-increasing seqs, so order in `local_pool`
        // matches insertion order which matches monotonic seq).
        let first = s.claim_kp(&owner).unwrap();
        assert_eq!(first.seq, 2);
        let second = s.claim_kp(&owner).unwrap();
        assert_eq!(second.seq, 3);
        assert!(s.claim_kp(&owner).is_none());

        // Used set should contain both consumed seqs.
        let key = hex::encode(owner);
        let pool = &s.kp_pools[&key];
        assert!(pool.used_kps.contains(&2));
        assert!(pool.used_kps.contains(&3));
    }

    #[test]
    fn claim_kp_refuses_adversarial_reinsertion() {
        let mut s = DeviceRingState::new();
        let owner: DeviceId = [9u8; 16];

        s.ingest_kp_batch(&owner, vec![kp(1), kp(2)]);
        let claimed = s.claim_kp(&owner).unwrap();
        assert_eq!(claimed.seq, 1);

        // Adversarially shove seq=1 back into the local_pool.  Because
        // `claim_kp` consults `used_kps`, it must refuse to return it.
        let key = hex::encode(owner);
        s.kp_pools.get_mut(&key).unwrap().local_pool.push(kp(1));

        let next = s.claim_kp(&owner).unwrap();
        assert_eq!(next.seq, 2);
        // And nothing left — the reinserted kp(1) is gated by used_kps.
        assert!(s.claim_kp(&owner).is_none());
    }

    #[test]
    fn kp_request_if_low_fires_at_or_below_low_water() {
        let mut s = DeviceRingState::new();
        let owner: DeviceId = [9u8; 16];

        // Empty pool → request full target.
        assert_eq!(s.kp_request_if_low(&owner), Some(KP_POOL_TARGET as u32));

        // Below low-water (1 < 2).
        s.ingest_kp_batch(&owner, vec![kp(1)]);
        assert_eq!(
            s.kp_request_if_low(&owner),
            Some((KP_POOL_TARGET - 1) as u32)
        );

        // At low-water exactly (2 == 2).
        s.ingest_kp_batch(&owner, vec![kp(2)]);
        assert_eq!(
            s.kp_request_if_low(&owner),
            Some((KP_POOL_TARGET - 2) as u32)
        );

        // Above low-water (3 > 2) — no request.
        s.ingest_kp_batch(&owner, vec![kp(3)]);
        assert!(s.kp_request_if_low(&owner).is_none());
    }

    /// Phase E deferred-add path: drain the pool, confirm `claim_kp`
    /// stalls and the host gets a `KpRequest`, simulate the owner
    /// shipping a fresh `KpBatch`, and confirm `claim_kp` succeeds with
    /// a sane seq.  This is the protocol-level fix to the
    /// three-device-history-sync race: the consumer never has to
    /// fetch from the PDS, and a stalled add unblocks deterministically
    /// once the next batch arrives over the ring.
    #[test]
    fn same_user_fan_out_deferred_add_unblocks_on_next_batch() {
        let mut s = DeviceRingState::new();
        let owner: DeviceId = [9u8; 16];

        // 1. Seed an initial batch.
        s.ingest_kp_batch(&owner, vec![kp(1), kp(2)]);
        assert_eq!(s.kp_pool_size(&owner), 2);

        // 2. The host drains the pool to 0 via concurrent fan-outs.
        let _ = s.claim_kp(&owner).unwrap();
        let _ = s.claim_kp(&owner).unwrap();
        assert!(s.claim_kp(&owner).is_none());

        // 3. Pool-exhaustion forces the same-user fan-out path into the
        //    deferred branch.  The host calls `emit_kp_request_for`
        //    (instead of looking at `kp_request_if_low`, which would
        //    also fire here).  We don't have an MoatSession + StepEnv
        //    in this unit test, so we exercise the predicate
        //    underneath: at-or-below the low-water mark, a request is
        //    due.
        assert!(s.kp_request_if_low(&owner).is_some());

        // 4. The owner sees the KpRequest, builds a fresh KpBatch with
        //    monotonic seqs, and ships it.  Consumer ingests it.
        s.ingest_kp_batch(&owner, vec![kp(3), kp(4), kp(5)]);
        assert_eq!(s.kp_pool_size(&owner), 3);

        // 5. The previously stalled add retries on the next tick and
        //    succeeds.  Lowest unused seq is 3 (1 and 2 are in
        //    `used_kps`, 3/4/5 are fresh).
        let claimed = s.claim_kp(&owner).unwrap();
        assert_eq!(claimed.seq, 3);

        // 6. The single-use invariant survives the round trip: seqs 1
        //    and 2 stay refused even if some adversarial actor were to
        //    splice them back into the pool.
        let key = hex::encode(owner);
        assert!(s.kp_pools[&key].used_kps.contains(&1));
        assert!(s.kp_pools[&key].used_kps.contains(&2));
        assert!(s.kp_pools[&key].used_kps.contains(&3));
    }

    #[test]
    fn exhausted_key_package_pool_triggers_replenishment() {
        // The unit-level statement of the deadlock: a device whose live count
        // has hit zero must ask for more without needing to receive anything
        // first. `generate_key_package` mints one, so burn it to get to zero.
        let mls = MoatSession::new();
        // Device id must come from the session, not be invented: the driver
        // filters the pool on `mls.device_id()`, and the host builds its
        // credential the same way (`app.rs::ring_tick_inner`).
        let cred = make_credential("did:plc:user", "d1", *mls.device_id());
        let (kp, _bundle) = mls.generate_key_package(&cred).expect("kp");
        assert!(mls.holds_init_key(&kp));

        // Burn our published key's init secret the same way an inviter
        // would: another session builds a group and adds us with it.
        let outsider = MoatSession::new();
        let out_cred = make_credential("did:plc:other", "out", [2u8; 16]);
        let (_okp, out_bundle) = outsider.generate_key_package(&out_cred).expect("outsider kp");
        let out_group = outsider.create_group(&out_cred, &out_bundle).expect("group");
        let wr = outsider
            .add_member(&out_group, &out_bundle, &kp)
            .expect("add");
        mls.process_welcome(&wr.welcome).expect("burn our init key");
        assert!(!mls.holds_init_key(&kp), "pool is now exhausted");

        let mut state = DeviceRingState::new();
        let env = StepEnv {
            my_did: "did:plc:user",
            credential: &cred,
            key_bundle: &_bundle,
            now_ms: 0,
            sibling_stealth: &[],
        };

        // The spent package is still "published" — it is in the pool snapshot
        // and indistinguishable there from a live one. It must not count.
        let published = vec![KeyPackageInput { key_package: kp.clone() }];
        let cmds = state.replenish_own_key_packages(&mls, &env, &published);
        assert_eq!(
            cmds.len(),
            KP_SELF_POOL_TARGET,
            "an exhausted pool must refill to target, not to one"
        );
        assert!(cmds.iter().all(|c| matches!(c, RingCommand::ReplenishKeyPackage)));

        // Mint and publish enough live ones, and it goes quiet — this runs
        // every tick, so a false positive would republish forever.
        let mut pool = vec![KeyPackageInput { key_package: kp }];
        for _ in 0..KP_SELF_POOL_TARGET {
            let fresh = mls.replenish_key_package(&cred, &_bundle).expect("mint");
            pool.push(KeyPackageInput { key_package: fresh });
        }
        assert!(state.replenish_own_key_packages(&mls, &env, &pool).is_empty());

        // Minted but *not* published must not count: a failed PDS write has to
        // keep looking like an empty pool, which is why the count intersects
        // the fetch rather than reading local storage.
        let unpublished_only = vec![KeyPackageInput { key_package: vec![0u8; 4] }];
        assert_eq!(
            state
                .replenish_own_key_packages(&mls, &env, &unpublished_only)
                .len(),
            KP_SELF_POOL_TARGET,
        );
    }

    // ── Phase D: low-water + emit gating ──────────────────────────────────

    #[test]
    fn emit_low_water_kp_requests_is_noop_outside_ring() {
        // The emitter returns Vec::new() early on the `RingMembership::InRing`
        // guard.
        let s = DeviceRingState::new();

        let mls = crate::MoatSession::new();
        let credential = make_credential("did:plc:test", "dev", [1u8; 16]);
        let env = StepEnv {
            my_did: "did:plc:test",
            credential: &credential,
            key_bundle: &[],
            now_ms: 0,
            sibling_stealth: &[],
        };
        assert!(s.emit_low_water_kp_requests(&mls, &env).is_empty());
    }

    #[test]
    fn maybe_emit_kp_request_gated_by_low_water_predicate() {
        // The `kp_request_if_low` predicate fires at-or-below LOW_WATER.
        // Above that threshold, no request would be emitted even if we
        // were in a ring.  Verifies the gate before exercising the (heavy)
        // encrypt path in beacon integration tests.
        let mut s = DeviceRingState::new();
        let owner: DeviceId = [9u8; 16];

        // Empty pool — should fire.
        assert!(s.kp_request_if_low(&owner).is_some());

        // Fill to LOW_WATER — still fires (at-or-below).
        s.ingest_kp_batch(&owner, vec![kp(1), kp(2)]);
        assert!(s.kp_request_if_low(&owner).is_some());

        // Fill one above — no longer fires.
        s.ingest_kp_batch(&owner, vec![kp(3)]);
        assert!(s.kp_request_if_low(&owner).is_none());
    }

    #[test]
    fn kp_pool_state_persists_through_json_roundtrip() {
        let mut s = DeviceRingState::new();
        let owner: DeviceId = [9u8; 16];
        let _ = s.allocate_kp_seqs(3);
        s.ingest_kp_batch(&owner, vec![kp(10), kp(11)]);
        let _ = s.claim_kp(&owner);

        let json = serde_json::to_string(&s).unwrap();
        let parsed: DeviceRingState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.highest_issued_kp_seq(), 3);
        assert_eq!(parsed.kp_pool_size(&owner), 1); // one claimed, one left
    }

    // ── Stealth carrier for the KP lane ─────────────────────────────────────

    /// A device fixture for stealth-lane tests: a real MoatSession plus
    /// stealth keypair, credential, and key bundle.
    struct StealthDevice {
        mls: MoatSession,
        cred: MoatCredential,
        key_bundle: Vec<u8>,
        stealth_priv: [u8; 32],
        stealth_pub: [u8; 32],
    }

    fn make_stealth_device(did: &str, name: &str) -> StealthDevice {
        let mls = MoatSession::new();
        let cred = make_credential(did, name, *mls.device_id());
        let (_kp, key_bundle) = mls.generate_key_package(&cred).expect("kp");
        let (stealth_priv, stealth_pub) = crate::generate_stealth_keypair();
        StealthDevice { mls, cred, key_bundle, stealth_priv, stealth_pub }
    }

    fn env_for<'a>(dev: &'a StealthDevice, siblings: &'a [SiblingStealth]) -> StepEnv<'a> {
        StepEnv {
            my_did: dev.cred.did(),
            credential: &dev.cred,
            key_bundle: &dev.key_bundle,
            now_ms: 0,
            sibling_stealth: siblings,
        }
    }

    /// Establish a real 2-member MLS ring between `creator` and `joiner`
    /// (creator creates the ring, adds joiner).  Returns the ring's group
    /// id.  Confirmed ring membership is read directly off the MLS group
    /// (see `ring_joined_siblings`), so stealth-lane tests need a real
    /// ring rather than synthetic bookkeeping.
    fn establish_ring(creator: &StealthDevice, joiner: &StealthDevice) -> Vec<u8> {
        let ring_id = creator
            .mls
            .create_group(&creator.cred, &creator.key_bundle)
            .expect("create ring");
        let joiner_kp = joiner
            .mls
            .replenish_key_package(&joiner.cred, &joiner.key_bundle)
            .expect("joiner kp");
        let wr = creator
            .mls
            .add_device(&ring_id, &creator.key_bundle, &joiner_kp)
            .expect("add joiner");
        joiner.mls.process_welcome(&wr.welcome).expect("joiner processes welcome");
        ring_id
    }

    fn mark_in_ring(s: &mut DeviceRingState, ring_id: Vec<u8>) {
        s.ring = RingMembership::InRing { ring_id, created_at: 0, our_leaf: 0 };
    }

    /// Decrypt every stealth-publish command addressed to `dev` and feed the
    /// plaintexts through `on_stealth_payload`, returning the
    /// commands the receiver emits in response.
    fn deliver_stealth(
        cmds: &[RingCommand],
        dev: &StealthDevice,
        state: &mut DeviceRingState,
        env: &StepEnv<'_>,
    ) -> Vec<RingCommand> {
        let mut out = Vec::new();
        for cmd in cmds {
            if let RingCommand::PublishStealthEvent { ciphertext, .. } = cmd {
                if let Some(pt) = try_decrypt_stealth(&dev.stealth_priv, ciphertext) {
                    out.extend(state.on_stealth_payload(&dev.mls, env, &pt));
                }
            }
        }
        out
    }

    /// End-to-end over the stealth lane: consumer emits a KpRequest, owner
    /// decrypts it and ships KpBatches back, consumer ingests and can claim.
    /// No MLS group carries any of this traffic — no epochs involved.
    #[test]
    fn kp_request_and_batch_roundtrip_over_stealth() {
        let did = "did:plc:user";
        let owner = make_stealth_device(did, "owner");
        let consumer = make_stealth_device(did, "consumer");
        let owner_id = *owner.mls.device_id();
        let consumer_id = *consumer.mls.device_id();

        let ring_id = establish_ring(&owner, &consumer);
        let mut owner_state = DeviceRingState::new();
        mark_in_ring(&mut owner_state, ring_id.clone());
        let mut consumer_state = DeviceRingState::new();
        mark_in_ring(&mut consumer_state, ring_id);

        let owner_sib = [SiblingStealth { scan_pubkey: consumer.stealth_pub, device_id: consumer_id }];
        let consumer_sib = [SiblingStealth { scan_pubkey: owner.stealth_pub, device_id: owner_id }];
        let owner_env = env_for(&owner, &owner_sib);
        let consumer_env = env_for(&consumer, &consumer_sib);

        // 1. Consumer requests KPs from the owner (pool empty).
        let req_cmds = consumer_state.emit_kp_request_for(&consumer.mls, &consumer_env, &owner_id);
        assert_eq!(req_cmds.len(), 1, "one stealth publish for the request");
        assert!(matches!(req_cmds[0], RingCommand::PublishStealthEvent { .. }));

        // The request is addressed to the owner: the consumer must not be
        // able to decrypt its own publish (no mark-own bookkeeping needed).
        if let RingCommand::PublishStealthEvent { ciphertext, .. } = &req_cmds[0] {
            assert!(try_decrypt_stealth(&consumer.stealth_priv, ciphertext).is_none());
        }

        // 2. Owner decrypts the request and responds with KpBatches.
        let batch_cmds = deliver_stealth(&req_cmds, &owner, &mut owner_state, &owner_env);
        assert!(
            batch_cmds.iter().all(|c| matches!(c, RingCommand::PublishStealthEvent { .. })),
            "owner responds only with stealth publishes"
        );
        assert!(!batch_cmds.is_empty(), "owner shipped at least one batch");

        // 3. Consumer ingests the batches; pool fills; claim succeeds.
        let _ = deliver_stealth(&batch_cmds, &consumer, &mut consumer_state, &consumer_env);
        assert_eq!(consumer_state.kp_pool_size(&owner_id), KP_POOL_TARGET);
        assert!(consumer_state.claim_kp(&owner_id).is_some());

        // 4. Replay of the same batches is fully absorbed (order-insensitive
        //    lane; dedupe by seq).
        let _ = deliver_stealth(&batch_cmds, &consumer, &mut consumer_state, &consumer_env);
        assert_eq!(consumer_state.kp_pool_size(&owner_id), KP_POOL_TARGET - 1);
    }

    /// Batches whose KPs don't verify against the claimed sender are dropped:
    /// the embedded credential must carry our DID and the sender's device id.
    #[test]
    fn kp_batch_with_mismatched_credential_is_rejected() {
        let did = "did:plc:user";
        let owner = make_stealth_device(did, "owner");
        let consumer = make_stealth_device(did, "consumer");
        let imposter = make_stealth_device("did:plc:other", "imposter");
        let owner_id = *owner.mls.device_id();
        let consumer_id = *consumer.mls.device_id();

        let ring_id = establish_ring(&owner, &consumer);
        let mut consumer_state = DeviceRingState::new();
        mark_in_ring(&mut consumer_state, ring_id);
        let consumer_sib = [SiblingStealth { scan_pubkey: owner.stealth_pub, device_id: owner_id }];
        let consumer_env = env_for(&consumer, &consumer_sib);

        // A batch claiming to come from `owner` but carrying KPs generated
        // under the imposter's credential (wrong DID + wrong device id).
        let (bad_kp, _) = imposter.mls.generate_key_package(&imposter.cred).expect("kp");
        let forged = CoordMsg::KpBatch {
            recipient_device_id: consumer_id.to_vec(),
            kps: vec![OfferedKp { rkey: vec![1u8; 16], seq: 1, key_package: bad_kp }],
        };
        let cmds = consumer_state.on_sibling_msg(&consumer.mls, &consumer_env, owner_id, forged);
        assert!(cmds.is_empty());
        assert_eq!(consumer_state.kp_pool_size(&owner_id), 0, "forged KP must not enter the pool");

        // Sanity: a genuine batch from the owner is accepted.
        let (good_kp, _) = owner.mls.generate_key_package(&owner.cred).expect("kp");
        let genuine = CoordMsg::KpBatch {
            recipient_device_id: consumer_id.to_vec(),
            kps: vec![OfferedKp { rkey: vec![2u8; 16], seq: 2, key_package: good_kp }],
        };
        let _ = consumer_state.on_sibling_msg(&consumer.mls, &consumer_env, owner_id, genuine);
        assert_eq!(consumer_state.kp_pool_size(&owner_id), 1);
    }

    /// Batches arriving before the sender is a confirmed ring member are
    /// dropped (and the pool stays empty until the low-water request path
    /// refills it after the join completes).
    #[test]
    fn kp_batch_from_unjoined_peer_is_dropped() {
        let did = "did:plc:user";
        let owner = make_stealth_device(did, "owner");
        let consumer = make_stealth_device(did, "consumer");
        let owner_id = *owner.mls.device_id();
        let consumer_id = *consumer.mls.device_id();

        let mut consumer_state = DeviceRingState::new();
        // NOTE: `ring_id` here does not correspond to any real MLS group,
        // so `owner` cannot resolve as a confirmed member — deliberately:
        // this is what "not (yet) a confirmed ring member" looks like now
        // that membership is read straight off the MLS group.
        mark_in_ring(&mut consumer_state, vec![0xEE; 32]);
        let consumer_env = env_for(&consumer, &[]);

        let (kp_bytes, _) = owner.mls.generate_key_package(&owner.cred).expect("kp");
        let batch = CoordMsg::KpBatch {
            recipient_device_id: consumer_id.to_vec(),
            kps: vec![OfferedKp { rkey: vec![1u8; 16], seq: 1, key_package: kp_bytes }],
        };
        let cmds = consumer_state.on_sibling_msg(&consumer.mls, &consumer_env, owner_id, batch);
        assert!(cmds.is_empty());
        assert_eq!(consumer_state.kp_pool_size(&owner_id), 0);
    }

    /// Same-user fan-out end to end: the owner ships KPs over stealth, the
    /// consumer claims one to `add_device` the owner into a user group, and
    /// the resulting `UserConvWelcome` travels back over stealth.  The owner
    /// joins the group and emits `RegisterGroup { kind: User }`.
    #[test]
    fn user_conv_welcome_roundtrip_over_stealth() {
        let did = "did:plc:user";
        let owner = make_stealth_device(did, "owner");
        let consumer = make_stealth_device(did, "consumer");
        let owner_id = *owner.mls.device_id();
        let consumer_id = *consumer.mls.device_id();

        let ring_id = establish_ring(&owner, &consumer);
        let mut owner_state = DeviceRingState::new();
        mark_in_ring(&mut owner_state, ring_id.clone());
        let mut consumer_state = DeviceRingState::new();
        mark_in_ring(&mut consumer_state, ring_id);

        let owner_sib = [SiblingStealth { scan_pubkey: consumer.stealth_pub, device_id: consumer_id }];
        let consumer_sib = [SiblingStealth { scan_pubkey: owner.stealth_pub, device_id: owner_id }];
        let owner_env = env_for(&owner, &owner_sib);
        let consumer_env = env_for(&consumer, &consumer_sib);

        // Owner mints a batch; consumer ingests it.
        let batch = owner_state.build_kp_batch(&owner.mls, &owner_env, 1).expect("batch");
        consumer_state.ingest_kp_batch(&owner_id, batch);
        assert!(consumer_state.kp_pool_size(&owner_id) > 0);

        // Consumer has a user conversation and fans the owner out into it.
        let group_id = consumer
            .mls
            .create_group(&consumer.cred, &consumer.key_bundle)
            .expect("group");
        let claimed = consumer_state.claim_kp(&owner_id).expect("claim");
        let wr = consumer
            .mls
            .add_device(&group_id, &consumer.key_bundle, &claimed.key_package)
            .expect("add");
        let welcome_msg = CoordMsg::UserConvWelcome {
            owner_device_id: owner_id.to_vec(),
            group_id: group_id.clone(),
            welcome: wr.welcome,
        };
        let cmds = consumer_state
            .encrypt_for_sibling(&consumer.mls, &consumer_env, &owner_id, &welcome_msg)
            .map(|c| vec![c])
            .expect("stealth encrypt");

        // Owner decrypts, processes the Welcome, and registers the group.
        let out = deliver_stealth(&cmds, &owner, &mut owner_state, &owner_env);
        assert!(
            out.iter().any(|c| matches!(
                c,
                RingCommand::RegisterGroup { group_id: g, kind: GroupKind::User } if *g == group_id
            )),
            "owner must register the joined user conversation, got {out:?}"
        );

        // Replayed Welcome fails init-key lookup and is absorbed silently.
        let out2 = deliver_stealth(&cmds, &owner, &mut owner_state, &owner_env);
        assert!(out2.is_empty(), "replayed Welcome must be a no-op, got {out2:?}");

        // Joining is only half the job: the fanned-in device must also be able
        // to *author* in the group, which requires its leaf to carry the
        // identity signing key it will sign with. Regression guard for the
        // signing-key mismatch described in the module note.
        let ev = Event::sibling_msg(owner_id.to_vec(), b"hello".to_vec());
        owner
            .mls
            .encrypt_event(&group_id, &owner.key_bundle, &ev)
            .expect("fanned-in device must be able to encrypt into the group it joined");
    }
}
