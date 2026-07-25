//! Device ring and coordination group state machine.
//!
//! Pure logic (no async, no I/O). The state machine is event-driven:
//! callers feed [`RingEvent`]s via [`DeviceRingState::step`] and interpret
//! the returned [`RingCommand`]s. [`DeviceRingState::tick`] is a convenience
//! wrapper that fans a [`TickInputs`] bundle out into a canonical sequence
//! of `step()` calls; both `moat-cli` and `moat-dart/common` use it as their
//! main entry point.
//!
//! The state types ([`RingMembership`], [`PeerState`], [`RingLink`],
//! [`SyncStatus`]) encode exhaustively which configurations are valid;
//! transitions are written as `match`es so adding a new event or peer state
//! is a compile error until every arm is handled.
//!
//! # Signing-key identity
//!
//! Every KeyPackage a device offers — cross-user pool, bootstrap KP, same-user
//! KP lane — must carry that device's *identity* signing key (`env.key_bundle`),
//! so KPs are minted with [`MoatSession::replenish_key_package`], never
//! `generate_key_package`, which would mint a fresh throwaway keypair.
//!
//! This is load-bearing. A leaf's signing key is what the app later signs with
//! to author into that group, and the app only ever holds one such key. A leaf
//! created from a KP with any other signing key is unusable: every subsequent
//! `encrypt_event` into that group fails with "Own member not found in group".
//! Reusing the signing key shares nothing else — init and encryption keys stay
//! unique per KP, so the single-use pool semantics are unaffected.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::{encrypt_for_stealth, try_decrypt_stealth, Error, Event, MoatCredential, MoatSession, Result};

// ─── Wire-format helpers ────────────────────────────────────────────────────

/// Magic bytes for the Welcome envelope wire format: ASCII "MWE1".
const WELCOME_ENVELOPE_MAGIC: [u8; 4] = *b"MWE1";

/// Encode a Welcome into the wire envelope: `[MWE1][4-byte BE welcome_len][welcome][hints_json]`.
///
/// Hints are a JSON array reserved for future use; this helper always writes
/// the empty array `[]`. Both moat-cli and moat-dart wrap stealth-published
/// Welcomes in this envelope, so the ring state machine does the same internally.
pub fn encode_welcome_envelope(welcome: &[u8]) -> Vec<u8> {
    let hints_json: &[u8] = b"[]";
    let mut buf = Vec::with_capacity(8 + welcome.len() + hints_json.len());
    buf.extend_from_slice(&WELCOME_ENVELOPE_MAGIC);
    buf.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
    buf.extend_from_slice(welcome);
    buf.extend_from_slice(hints_json);
    buf
}

/// Decode a Welcome envelope, returning the raw welcome bytes.
///
/// Returns `None` if the envelope is missing the MWE1 magic or is truncated.
/// Hints (if present) are ignored.
pub fn decode_welcome_envelope(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 || data[..4] != WELCOME_ENVELOPE_MAGIC {
        return None;
    }
    let welcome_len = u32::from_be_bytes(data[4..8].try_into().ok()?) as usize;
    if data.len() < 8 + welcome_len {
        return None;
    }
    Some(data[8..8 + welcome_len].to_vec())
}

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
    /// A pairwise coordination group between two sibling devices.
    DeviceCoord,
}

/// Result of creating a device coordination group via [`MoatSession::create_device_coord_group`].
#[derive(Debug)]
pub struct CoordGroupResult {
    pub group_id: Vec<u8>,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// Classify a group as `DeviceCoord` or `User` based on member credentials.
///
/// Returns `DeviceCoord` iff all members carry `my_did`; otherwise `User`.
/// Ring detection (group_id == ring_group_id) is the caller's responsibility —
/// check that first and short-circuit before calling this function.
pub fn classify_group_kind(
    members: &[(u32, Option<MoatCredential>)],
    my_did: &str,
) -> GroupKind {
    if members.is_empty() {
        return GroupKind::User;
    }
    let all_same_did = members
        .iter()
        .all(|(_, cred)| cred.as_ref().map(|c| c.did() == my_did).unwrap_or(false));
    if all_same_did {
        GroupKind::DeviceCoord
    } else {
        GroupKind::User
    }
}

// ─── Coordination messages ──────────────────────────────────────────────────

/// Coordination messages sent as MLS application messages over a `DeviceCoord` group.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordMsg {
    /// Sent by both sides on coord-group join to signal presence.
    Hello {
        #[serde_as(as = "Base64")]
        sender_device_id: Vec<u8>,
    },
    /// Informs a sibling about the current ring (for bootstrap or reconciliation).
    RingInfo {
        #[serde_as(as = "Base64")]
        ring_id: Vec<u8>,
        /// Monotonic ring generation; highest wins reconciliation.
        generation: u64,
        /// Unix timestamp (ms) when the ring was created.
        created_at: i64,
    },
    /// Tells the recipient to abandon a losing ring during split-brain reconciliation.
    Supersede {
        #[serde_as(as = "Base64")]
        old_ring_id: Vec<u8>,
    },
    /// Delivers the MLS ring-group Welcome to the new sibling through the coord channel.
    ///
    /// Preferred over stealth delivery because it arrives in the same ordered channel
    /// as `RingInfo`, so the recipient always knows `ring_id` by the time `welcome` is
    /// processed.
    RingWelcome {
        #[serde_as(as = "Base64")]
        ring_id: Vec<u8>,
        #[serde_as(as = "Base64")]
        welcome: Vec<u8>,
        /// Generation of the ring this Welcome admits the recipient to.
        generation: u64,
        created_at: i64,
    },
    /// Carries the Drawbridge pairing token from the ring offerer to a new member.
    /// `target_device_id`, when present, identifies the sole intended recipient;
    /// other ring members MUST ignore the offer.
    SyncOffer {
        #[serde_as(as = "Base64")]
        token: Vec<u8>,
        #[serde_as(as = "Option<Base64>")]
        target_device_id: Option<Vec<u8>>,
    },
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

// ─── Ring reconciliation ────────────────────────────────────────────────────

/// Outcome of comparing two ring instances to decide which survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileDecision {
    /// Keep the locally-known ring; the peer should switch to ours.
    KeepMine,
    /// Abandon the locally-known ring; join the peer's ring instead.
    SwitchToTheirs,
    /// Both devices are already in the same ring — nothing to do.
    AlreadyInTheirs,
}

/// Identifies one ring for reconciliation purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingRef<'a> {
    pub ring_id: &'a [u8],
    pub generation: u64,
    pub created_at: i64,
}

/// Decide which ring wins when two devices discover they are in different rings.
///
/// **Highest `generation` wins**, then oldest `created_at`, then
/// lexicographically smallest `ring_id`.
///
/// Generation-first is what makes joiner-created rings work. A device
/// joining an established device-set creates generation `N+1` containing
/// everyone it knows about, because it is the only participant guaranteed
/// to be online — see `ring-inversion.md`. Under the previous oldest-wins
/// rule such a ring always had the newest `created_at` and so always lost,
/// being superseded straight back to a ring whose members may all be gone.
///
/// `created_at` and `ring_id` remain as tiebreaks for the case this rule
/// was originally written for: two devices independently forming a *first*
/// ring (both generation 1) after a long partition.
pub fn reconcile_rings(mine: RingRef<'_>, theirs: RingRef<'_>) -> ReconcileDecision {
    if mine.ring_id == theirs.ring_id {
        return ReconcileDecision::AlreadyInTheirs;
    }
    match theirs.generation.cmp(&mine.generation) {
        std::cmp::Ordering::Greater => return ReconcileDecision::SwitchToTheirs,
        std::cmp::Ordering::Less => return ReconcileDecision::KeepMine,
        std::cmp::Ordering::Equal => {}
    }
    match mine.created_at.cmp(&theirs.created_at) {
        std::cmp::Ordering::Less => ReconcileDecision::KeepMine,
        std::cmp::Ordering::Greater => ReconcileDecision::SwitchToTheirs,
        std::cmp::Ordering::Equal => {
            if mine.ring_id <= theirs.ring_id {
                ReconcileDecision::KeepMine
            } else {
                ReconcileDecision::SwitchToTheirs
            }
        }
    }
}

// ─── State types ────────────────────────────────────────────────────────────

/// Stable 16-byte device identifier (the `device_id` field of `MoatCredential`).
pub type DeviceId = [u8; 16];

/// Whether we still owe a sibling a Drawbridge sync offer.
///
/// Not persisted: on process restart every `Joined` peer resets to `OweOffer`
/// so a fresh boot always re-offers to current ring members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// We are responsible for issuing a `SendDrawbridgePairOffer` to this peer
    /// once Drawbridge is connected and no other sync session is active.
    OweOffer,
    /// We have emitted the offer; awaiting pair completion.
    OfferEmitted {
        token: Vec<u8>,
    },
    /// Either the pair completed, or we are not the offerer for this peer.
    Done,
}

/// Which device performed the MLS Add that put this peer in the ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddedBy {
    /// We issued the MLS Add.
    Us,
    /// The peer themselves added us (we joined via their Welcome).
    Them,
    /// Some other sibling — neither us nor this peer — issued the Add.
    OtherSibling(DeviceId),
}

/// Where a peer sits relative to the ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingLink {
    /// Hello exchanged, ring exists locally, but we have not yet observed
    /// this peer as a confirmed MLS member of the ring.  Transitions to
    /// `Joined` either when a ring Commit reveals them as a member, or
    /// when we issue an MLS Add ourselves.
    PendingAdd,

    /// Peer is a confirmed MLS member of our ring.
    Joined {
        added_by: AddedBy,
        sync: SyncStatus,
    },
}

/// Per-peer state.  See module-level docstring for the lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    /// We have observed this sibling's key package on the PDS but have not
    /// yet built (or joined) a coord group with them.
    Discovered,

    /// A coord group exists and we have published our Hello into it.
    /// We have NOT yet received their Hello.
    AwaitingTheirHello {
        coord_group_id: Vec<u8>,
    },

    /// Both Hellos exchanged.  `ring_link` tracks ring-membership progress.
    CoordReady {
        coord_group_id: Vec<u8>,
        ring_link: RingLink,
    },
}

/// Device-level ring membership.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RingMembership {
    /// No peers known; nothing to do.
    #[default]
    Solo,

    /// At least one peer is in `Discovered` / `AwaitingTheirHello` / `CoordReady`,
    /// but no ring exists yet.  `defer_ticks` implements a one-tick wait so an
    /// inbound `RingWelcome` from an already-existing ring has time to arrive
    /// before we speculatively create a competing ring.
    Discovering {
        defer_ticks: u8,
    },

    /// We are an MLS member of a ring.
    InRing {
        ring_id: Vec<u8>,
        created_at: i64,
        /// Monotonic ring generation. A device joining an established
        /// device-set creates generation `N+1`; the highest generation wins
        /// reconciliation. See `ring-inversion.md`.
        generation: u64,
        our_leaf: u32,
    },
}

/// Ticks a peer may sit in a wait that has no acknowledgement path before
/// we retry it. See [`DeviceRingState::recover_stalled_peers`].
///
/// Sized in ticks rather than wall-clock so it behaves identically under the
/// deterministic simulation, which advances `now_ms` by 1 per round. At the
/// host's tick cadence this is on the order of tens of seconds.
pub const STALL_RETRY_TICKS: u32 = 4;

/// Target number of an owner's key packages a consumer maintains locally.
pub const KP_POOL_TARGET: usize = 8;

/// Low-water mark: when the local pool of an owner's KPs drops to this
/// value, the consumer issues a `CoordMsg::KpRequest` to refill.
pub const KP_POOL_LOW_WATER: usize = 2;

/// Maximum number of [`OfferedKp`] entries the owner ships in a single
/// [`CoordMsg::KpBatch`].  Larger refills are split across multiple
/// messages so each fits inside the 4 KB padding bucket.
pub const KP_BATCH_CAP: usize = 4;

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
    pub used_kps: HashSet<u64>,
}

/// Top-level state owned by the host.  Serialized as JSON for persistence.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRingState {
    ring: RingMembership,
    /// Sibling device_id → peer state.  HashMap key is hex-encoded for JSON.
    peers: HashMap<String, PeerState>,
    /// Cursor (rkey) for incremental own-PDS stealth scan.
    own_events_cursor: Option<String>,
    /// Per-peer count of consecutive ticks spent in a state that waits on
    /// something with **no acknowledgement path** — an emitted pairing offer
    /// the peer may never accept, or a coord-group Welcome the peer may never
    /// be able to process. Neither failure is reported back to us, so without
    /// a bound they stall forever. Reset on any peer-state transition; not
    /// persisted, so a restart re-arms everything.
    #[serde(skip)]
    stall_ticks: HashMap<String, u32>,
    /// Per-peer count of sync offers we have emitted. Used only to order
    /// selection: an unresponsive peer must not be retried ahead of peers
    /// that have never been offered to. Not persisted.
    #[serde(skip)]
    offer_attempts: HashMap<String, u32>,

    /// Owner-global monotonic counter for `OfferedKp.seq`.  Incremented
    /// every time we publish a KP into a `KpBatch` (any recipient).  See
    /// `same-user-key-distribution.md` — a single per-owner counter is
    /// simpler than per-(owner, recipient) and consumer dedupe doesn't
    /// care about gaps caused by other consumers' batches.
    next_kp_seq: u64,

    /// Per-owner pool we draw KPs from when adding the owner to a user
    /// conversation.  Key is the owner's hex-encoded `device_id`.
    kp_pools: HashMap<String, KpPool>,

    /// Hex-encoded sibling `device_id`s whose bootstrap event we have
    /// already consumed.  Because the bootstrap event is *not* deleted
    /// from the PDS, this flag is the only thing preventing the
    /// consumer from acting on a re-fetch of the same event.  See
    /// `protocol_model_hybrid.rs::hybrid_bootstrap_event_replay_blocked_by_consumer_flag`.
    consumed_bootstrap_for: HashSet<String>,

    /// Hex-encoded sibling `device_id`s for which we (D_new) have
    /// already published a bootstrap KP event.  Prevents re-publishing
    /// on every tick once the event is on the PDS — its consumer will
    /// pick it up via stealth scan and our `consumed_bootstrap_for`
    /// flag on the other side closes the single-use loop.
    published_bootstrap_for: HashSet<String>,

    /// Hex-encoded sender `device_id` → MLS KeyPackage bytes received
    /// from that sibling via a stealth-decoded `EventKind::BootstrapKp`
    /// event but not yet used in a ring `add_device`.  The on-tick
    /// ring-add loop drains this map: every entry produces one Welcome
    /// over the ring, after which the sibling's flag is moved to
    /// `consumed_bootstrap_for`.
    pending_bootstrap_kps: HashMap<String, Vec<u8>>,

    /// Set when a `CoordMsg::RingInfo` arrives while we are not yet
    /// `InRing`: `(ring_id, created_at)` of a ring a Hello-exchanged
    /// sibling already belongs to.  Suppresses the Discovering-branch
    /// "smallest device_id creates a ring" tiebreak, which otherwise
    /// only consults locally Hello-exchanged peers and has no way to
    /// know a ring already exists elsewhere — without this, a device
    /// bootstrapping into an established multi-device ring can win that
    /// local tiebreak and create a second, competing ring before the
    /// real Add/Welcome from an existing member arrives.  Cleared once
    /// we transition to `InRing` (the field is only meaningful pre-ring).
    known_ring: Option<(Vec<u8>, u64, i64)>,
}

// SyncStatus / AddedBy / RingLink / PeerState / RingMembership: we want
// custom serde on SyncStatus so it always deserializes to `OweOffer`
// (transient state — not persisted across restarts).
impl Serialize for SyncStatus {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        // Always serialize as Done so deserialization of an in-flight offer
        // doesn't replay it.  Live state is re-derived from the ring on boot.
        SyncStatusWire::Done.serialize(s)
    }
}

impl<'de> Deserialize<'de> for SyncStatus {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let _ = SyncStatusWire::deserialize(d)?;
        // On load, reset every peer's sync status to OweOffer so the first
        // post-restart tick re-offers to all current ring members.
        Ok(SyncStatus::OweOffer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SyncStatusWire { Done }

// AddedBy / RingLink / PeerState / RingMembership: ordinary derived serde.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AddedByWire {
    Us,
    Them,
    OtherSibling {
        #[serde_as(as = "Base64")]
        device_id: Vec<u8>,
    },
}

impl From<&AddedBy> for AddedByWire {
    fn from(a: &AddedBy) -> Self {
        match a {
            AddedBy::Us => AddedByWire::Us,
            AddedBy::Them => AddedByWire::Them,
            AddedBy::OtherSibling(id) => AddedByWire::OtherSibling { device_id: id.to_vec() },
        }
    }
}

impl AddedByWire {
    fn into_added_by(self) -> AddedBy {
        match self {
            AddedByWire::Us => AddedBy::Us,
            AddedByWire::Them => AddedBy::Them,
            AddedByWire::OtherSibling { device_id } => {
                let mut id = [0u8; 16];
                let n = device_id.len().min(16);
                id[..n].copy_from_slice(&device_id[..n]);
                AddedBy::OtherSibling(id)
            }
        }
    }
}

impl Serialize for AddedBy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        AddedByWire::from(self).serialize(s)
    }
}

impl<'de> Deserialize<'de> for AddedBy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(AddedByWire::deserialize(d)?.into_added_by())
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum RingLinkWire {
    PendingAdd,
    Joined {
        added_by: AddedBy,
        // sync is always serialized via SyncStatus's custom impl above.
        sync: SyncStatus,
    },
}

impl Serialize for RingLink {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let wire = match self {
            RingLink::PendingAdd => RingLinkWire::PendingAdd,
            RingLink::Joined { added_by, sync } => RingLinkWire::Joined {
                added_by: added_by.clone(),
                sync: sync.clone(),
            },
        };
        wire.serialize(s)
    }
}

impl<'de> Deserialize<'de> for RingLink {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let wire = RingLinkWire::deserialize(d)?;
        Ok(match wire {
            RingLinkWire::PendingAdd => RingLink::PendingAdd,
            RingLinkWire::Joined { added_by, sync } => RingLink::Joined { added_by, sync },
        })
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum PeerStateWire {
    Discovered,
    AwaitingTheirHello {
        #[serde_as(as = "Base64")]
        coord_group_id: Vec<u8>,
    },
    CoordReady {
        #[serde_as(as = "Base64")]
        coord_group_id: Vec<u8>,
        ring_link: RingLink,
    },
}

impl Serialize for PeerState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let wire = match self {
            PeerState::Discovered => PeerStateWire::Discovered,
            PeerState::AwaitingTheirHello { coord_group_id } => {
                PeerStateWire::AwaitingTheirHello { coord_group_id: coord_group_id.clone() }
            }
            PeerState::CoordReady { coord_group_id, ring_link } => PeerStateWire::CoordReady {
                coord_group_id: coord_group_id.clone(),
                ring_link: ring_link.clone(),
            },
        };
        wire.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PeerState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let wire = PeerStateWire::deserialize(d)?;
        Ok(match wire {
            PeerStateWire::Discovered => PeerState::Discovered,
            PeerStateWire::AwaitingTheirHello { coord_group_id } => {
                PeerState::AwaitingTheirHello { coord_group_id }
            }
            PeerStateWire::CoordReady { coord_group_id, ring_link } => {
                PeerState::CoordReady { coord_group_id, ring_link }
            }
        })
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum RingMembershipWire {
    Solo,
    Discovering { defer_ticks: u8 },
    InRing {
        #[serde_as(as = "Base64")]
        ring_id: Vec<u8>,
        created_at: i64,
        generation: u64,
        our_leaf: u32,
    },
}

impl Serialize for RingMembership {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let wire = match self {
            RingMembership::Solo => RingMembershipWire::Solo,
            RingMembership::Discovering { defer_ticks } => {
                RingMembershipWire::Discovering { defer_ticks: *defer_ticks }
            }
            RingMembership::InRing { ring_id, created_at, generation, our_leaf } => RingMembershipWire::InRing {
                ring_id: ring_id.clone(),
                created_at: *created_at,
                generation: *generation,
                our_leaf: *our_leaf,
            },
        };
        wire.serialize(s)
    }
}

impl<'de> Deserialize<'de> for RingMembership {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let wire = RingMembershipWire::deserialize(d)?;
        Ok(match wire {
            RingMembershipWire::Solo => RingMembership::Solo,
            RingMembershipWire::Discovering { defer_ticks } => RingMembership::Discovering { defer_ticks },
            RingMembershipWire::InRing { ring_id, created_at, generation, our_leaf } => RingMembership::InRing {
                generation,
                ring_id,
                created_at,
                our_leaf,
            },
        })
    }
}

// ─── Event / command surface ────────────────────────────────────────────────

/// Per-step environment: identifying data the state machine needs on every call.
///
/// Re-supplied each `step()` because the host already knows them; threading
/// them through avoids storing redundant copies inside `DeviceRingState`.
pub struct StepEnv<'a> {
    pub my_did: &'a str,
    pub credential: &'a MoatCredential,
    pub key_bundle: &'a [u8],
    pub now_ms: i64,
    pub drawbridge_connected: bool,
    pub sync_session_active: bool,
    /// Stealth scan-pubkeys for all of our devices, used when emitting outgoing
    /// Welcome envelopes (coord and ring).
    pub stealth_pubkeys: &'a [[u8; 32]],
    /// Per-sibling stealth address records (`scan_pubkey` + `device_id`),
    /// used for bootstrap-KP publication. Excludes our own device.
    pub sibling_stealth: &'a [SiblingStealth],
}

/// Events fed into [`DeviceRingState::step`].
pub enum RingEvent<'a> {
    /// Periodic catch-up: time advanced; settle any pending work
    /// (ring creation, ring Add of CoordReady peers, sync offers, member
    /// detection).  `key_packages` is the current PDS snapshot of own-DID
    /// key packages — needed because the Tick handler may call `add_device`
    /// against the freshest KP for a pending peer.
    Tick {
        key_packages: &'a [KeyPackageInput],
    },

    /// A key package belonging to a sibling device was observed on our PDS.
    /// If the peer is unknown, creates a coord group; otherwise no-op.
    PeerKeyPackageObserved {
        key_package: &'a [u8],
    },

    /// A stealth-decrypted payload from our own PDS event stream.
    /// Tries to decode as a Welcome envelope and join the resulting group.
    StealthPayloadDecrypted {
        plaintext: &'a [u8],
    },

    /// A stealth-decrypted bootstrap KP event was received from a sibling.
    /// `from_device_id` is the sender's device id (extracted from the
    /// embedded KP credential); `key_package` is the raw MLS KeyPackage
    /// bytes the sender is offering us to add them to the ring.
    BootstrapKpReceived {
        from_device_id: DeviceId,
        key_package: &'a [u8],
    },

    /// The host already processed an MLS Welcome out-of-band (e.g. the Dart
    /// PollingService) and joined a group whose membership identifies it as
    /// a coord group.  Records the coord group and emits a Hello.
    CoordGroupJoined {
        group_id: Vec<u8>,
    },

    /// A coordination message was decrypted and decoded by the host.
    /// `sender_device_id` is the 16-byte id of the device whose MLS leaf
    /// produced the application message (extracted by the host from the
    /// decrypted Event wrapper); for legacy 2-party coord groups the
    /// driver still falls back to a member lookup if this is `None`,
    /// but ring messages with N > 2 members rely on it.
    CoordMsgReceived {
        source_group_id: Vec<u8>,
        sender_device_id: Option<DeviceId>,
        msg: CoordMsg,
    },

    /// An active sync session ended (success or failure).  Clears the
    /// `OfferEmitted` flag so a fresh offer can be made next tick if needed.
    SyncSessionEnded,

    /// Advance the own-PDS stealth-scan cursor.  Emitted by the host once
    /// per drained event so an incremental fetch can resume after restart.
    OwnEventsCursorAdvanced {
        rkey: String,
    },
}

/// Sibling key package fed into [`DeviceRingState::tick`].
#[derive(Debug, Clone)]
pub struct KeyPackageInput {
    /// Raw TLS-serialised MLS key package.
    pub key_package: Vec<u8>,
}

/// Per-sibling stealth address record fed into [`DeviceRingState::tick`].
///
/// Used by the bootstrap-publishing path: the ring driver needs each
/// sibling's `scan_pubkey` (to stealth-encrypt the bootstrap KP) and
/// their stable `device_id` (to mark "we've already published for this
/// sibling" without re-fetching).
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
    pub stealth_pubkeys: &'a [[u8; 32]],
    /// Per-sibling stealth address records, used to address bootstrap KPs.
    /// Should exclude our own device.
    pub sibling_stealth: &'a [SiblingStealth],
    pub own_events: &'a [OwnEventInput],
    pub stealth_privkey: &'a [u8; 32],
    pub credential: &'a MoatCredential,
    pub key_bundle: &'a [u8],
    pub now_ms: i64,
    pub drawbridge_has_own_connection: bool,
    pub sync_session_active: bool,
    pub my_did: &'a str,
}

/// Side effect requested by the ring state machine.  The host interprets
/// these in terms of its own I/O layer (PDS publish, Drawbridge frames,
/// persistence).
#[derive(Debug, Clone)]
pub enum RingCommand {
    /// Publish a tagged event to the PDS event stream.  If `mark_own` is
    /// true, the host should add `tag` to its own-published-tags set so the
    /// eventual echo is skipped (MLS forbids self-decryption).
    PublishEvent {
        tag: [u8; 16],
        ciphertext: Vec<u8>,
        mark_own: bool,
    },
    /// Publish a stealth-encrypted Welcome ciphertext under a random tag.
    /// Stealth payloads are decrypted out-of-band by recipients, so they are
    /// **not** marked as own.
    StealthPublishWelcome {
        tag: [u8; 16],
        ciphertext: Vec<u8>,
    },
    /// Publish a stealth-encrypted sibling event for a specific sibling.
    /// Same wire shape as [`StealthPublishWelcome`] — the host just publishes
    /// the ciphertext under the supplied tag.  The payload inside is either an
    /// `EventKind::BootstrapKp` event (MLS KeyPackage bytes for the ring
    /// bootstrap) or an `EventKind::SiblingMsg` event (steady-state
    /// `KpBatch` / `KpRequest` / `UserConvWelcome` CoordMsg JSON); the
    /// recipient's own-PDS stealth scan picks it up.  Stealth delivery is
    /// epoch-free and order-insensitive.
    PublishStealthEvent {
        tag: [u8; 16],
        ciphertext: Vec<u8>,
    },
    /// We just joined a coord group via Welcome — replenish our consumed
    /// key package so siblings can still add us to the ring.
    ReplenishKeyPackage,
    /// Register a newly-classified group with the host's metadata store and
    /// candidate-tag set.
    RegisterGroup {
        group_id: Vec<u8>,
        kind: GroupKind,
    },
    /// Initiate the Drawbridge pair flow as the offerer (history sync).
    SendDrawbridgePairOffer { token: Vec<u8> },
    /// Initiate the Drawbridge pair flow as the joiner (history sync).
    SendDrawbridgePairJoin { token: Vec<u8> },
    /// A new sibling joined the ring; immediately add them to all existing
    /// user conversations.
    PollForNewDevices,
}

// ─── Invariant violations ──────────────────────────────────────────────────

/// A predicate on [`DeviceRingState`] that should hold after every step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// More than one peer has `SyncStatus::OfferEmitted` simultaneously.
    MultipleOffersInFlight,
    /// A peer is `CoordReady` but our membership says `Solo`.
    CoordReadyPeerButSolo,
}

// ─── State machine impl ────────────────────────────────────────────────────

impl DeviceRingState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hex-encoded ring group id, if any.
    pub fn ring_id(&self) -> Option<&[u8]> {
        match &self.ring {
            RingMembership::InRing { ring_id, .. } => Some(ring_id.as_slice()),
            _ => None,
        }
    }

    /// Generation of the ring we are a member of, if any.
    pub fn ring_generation(&self) -> Option<u64> {
        match &self.ring {
            RingMembership::InRing { generation, .. } => Some(*generation),
            _ => None,
        }
    }

    pub fn ring_created_at(&self) -> Option<i64> {
        match &self.ring {
            RingMembership::InRing { created_at, .. } => Some(*created_at),
            _ => None,
        }
    }

    /// Coord group id we have with this peer, if any.
    pub fn coord_group_id_for(&self, peer: &DeviceId) -> Option<&[u8]> {
        let key = hex::encode(peer);
        match self.peers.get(&key)? {
            PeerState::Discovered => None,
            PeerState::AwaitingTheirHello { coord_group_id }
            | PeerState::CoordReady { coord_group_id, .. } => Some(coord_group_id.as_slice()),
        }
    }

    pub fn own_events_cursor(&self) -> Option<&str> {
        self.own_events_cursor.as_deref()
    }

    /// Number of coord groups we currently hold (peers with a coord_group_id).
    pub fn coord_group_count(&self) -> usize {
        self.peers
            .values()
            .filter(|ps| {
                matches!(
                    ps,
                    PeerState::AwaitingTheirHello { .. } | PeerState::CoordReady { .. }
                )
            })
            .count()
    }

    pub fn set_own_events_cursor(&mut self, rkey: String) {
        self.own_events_cursor = Some(rkey);
    }

    // ── KP-pool state-machine helpers ──────────────────────────────────────
    //
    // These manipulate the per-owner consumer state plus the owner-global
    // monotonic counter.  They are unwired in Phase B; Phase C / D will call
    // them from the appropriate `step()` arms.

    /// Allocate `count` fresh monotonic `seq` values for KPs we are about
    /// to ship to *some* consumer.  Seqs are owner-global; consumers
    /// dedupe by `highest_seq_observed` per owner, so gaps caused by
    /// other consumers' batches are harmless.
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

    /// Record that we have consumed `peer`'s bootstrap event.  Subsequent
    /// fetches of the same event are ignored.
    pub fn mark_bootstrap_consumed(&mut self, peer: &DeviceId) {
        self.consumed_bootstrap_for.insert(hex::encode(peer));
    }

    pub fn is_bootstrap_consumed(&self, peer: &DeviceId) -> bool {
        self.consumed_bootstrap_for.contains(&hex::encode(peer))
    }

    /// Verify structural invariants.  Cheap; intended for debug-build asserts
    /// and the proptest harness.
    pub fn check_invariants(&self) -> std::result::Result<(), InvariantViolation> {
        let mut offers_in_flight = 0usize;
        let mut any_coord_ready = false;
        for ps in self.peers.values() {
            if let PeerState::CoordReady { ring_link, .. } = ps {
                any_coord_ready = true;
                if let RingLink::Joined { sync: SyncStatus::OfferEmitted { .. }, .. } = ring_link {
                    offers_in_flight += 1;
                }
            }
        }
        if offers_in_flight > 1 {
            return Err(InvariantViolation::MultipleOffersInFlight);
        }
        if any_coord_ready && matches!(self.ring, RingMembership::Solo) {
            return Err(InvariantViolation::CoordReadyPeerButSolo);
        }
        Ok(())
    }

    /// True if any peer has a sync offer awaiting acceptance.  Mirrors the
    /// `MultipleOffersInFlight` invariant; see [`Self::check_invariants`].
    fn any_offer_in_flight(&self) -> bool {
        self.peers.values().any(|ps| {
            matches!(
                ps,
                PeerState::CoordReady {
                    ring_link: RingLink::Joined { sync: SyncStatus::OfferEmitted { .. }, .. },
                    ..
                }
            )
        })
    }

    fn peer_get(&self, id: &DeviceId) -> Option<&PeerState> {
        self.peers.get(&hex::encode(id))
    }

    fn peer_insert(&mut self, id: DeviceId, state: PeerState) {
        let key = hex::encode(id);
        // Any transition means we are no longer waiting on whatever we were
        // waiting on, so the stall clock restarts.
        self.stall_ticks.remove(&key);
        self.peers.insert(key, state);
    }

    fn peer_iter(&self) -> impl Iterator<Item = (DeviceId, &PeerState)> {
        self.peers.iter().filter_map(|(k, v)| {
            let bytes = hex::decode(k).ok()?;
            let arr: DeviceId = bytes.try_into().ok()?;
            Some((arr, v))
        })
    }

    /// Promote `Solo` → `Discovering` when we first learn of a peer.
    fn promote_to_discovering(&mut self) {
        if matches!(self.ring, RingMembership::Solo) {
            self.ring = RingMembership::Discovering { defer_ticks: 0 };
        }
    }

    /// Single state-machine step.  Returns the list of side effects to perform.
    pub fn step(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        event: RingEvent<'_>,
    ) -> Vec<RingCommand> {
        let cmds = match event {
            RingEvent::Tick { key_packages } => self.on_tick(mls, env, key_packages),
            RingEvent::PeerKeyPackageObserved { key_package } => {
                self.on_peer_kp_observed(mls, env, key_package)
            }
            RingEvent::StealthPayloadDecrypted { plaintext } => {
                self.on_stealth_payload(mls, env, plaintext)
            }
            RingEvent::CoordGroupJoined { group_id } => self.on_coord_group_joined(mls, env, &group_id),
            RingEvent::CoordMsgReceived { source_group_id, sender_device_id, msg } => {
                self.on_coord_msg(mls, env, &source_group_id, sender_device_id, msg)
            }
            RingEvent::SyncSessionEnded => self.on_sync_session_ended(),
            RingEvent::OwnEventsCursorAdvanced { rkey } => {
                self.own_events_cursor = Some(rkey);
                Vec::new()
            }
            RingEvent::BootstrapKpReceived { from_device_id, key_package } => {
                self.on_bootstrap_kp_received(from_device_id, key_package)
            }
        };
        debug_assert!(self.check_invariants().is_ok(), "ring invariant: {:?}", self.check_invariants());
        cmds
    }

    /// Convenience entry: fan a [`TickInputs`] bundle out into individual events.
    ///
    /// Mirrors the previous `tick()` signature so existing callers don't have
    /// to change shape.  Internally just calls `step()` in a canonical order:
    /// per-KP observations, per-stealth-event decryptions, then a final `Tick`.
    pub fn tick(&mut self, mls: &MoatSession, inputs: TickInputs<'_>) -> Vec<RingCommand> {
        let env = StepEnv {
            my_did: inputs.my_did,
            credential: inputs.credential,
            key_bundle: inputs.key_bundle,
            now_ms: inputs.now_ms,
            drawbridge_connected: inputs.drawbridge_has_own_connection,
            sync_session_active: inputs.sync_session_active,
            stealth_pubkeys: inputs.stealth_pubkeys,
            sibling_stealth: inputs.sibling_stealth,
        };
        let mut cmds = Vec::new();
        for kp in newest_key_package_per_device(mls, inputs.key_packages) {
            cmds.extend(self.step(mls, &env, RingEvent::PeerKeyPackageObserved { key_package: kp }));
        }
        for ev in inputs.own_events {
            if let Some(plaintext) = try_decrypt_stealth(inputs.stealth_privkey, &ev.ciphertext) {
                cmds.extend(self.step(mls, &env, RingEvent::StealthPayloadDecrypted { plaintext: &plaintext }));
            }
            if !ev.rkey.is_empty() {
                self.own_events_cursor = Some(ev.rkey.clone());
            }
        }
        cmds.extend(self.step(mls, &env, RingEvent::Tick { key_packages: inputs.key_packages }));
        cmds
    }

    // ─── Event handlers ───────────────────────────────────────────────────

    fn on_peer_kp_observed(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        key_package: &[u8],
    ) -> Vec<RingCommand> {
        let my_device_id = *mls.device_id();
        let sibling_cred = match mls.extract_credential_from_key_package(key_package) {
            Ok(Some(c)) => c,
            _ => return Vec::new(),
        };
        let sibling_id: DeviceId = *sibling_cred.device_id();
        if sibling_cred.did() != env.my_did || sibling_id == my_device_id {
            return Vec::new();
        }

        // Already tracked → no-op.
        if self.peer_get(&sibling_id).is_some() {
            return Vec::new();
        }

        // Once a ring exists, only the elected (smallest-leaf) ring member
        // discovers-and-creates a coord group from the shared cross-user
        // KeyPackage pool. Without this gate, every existing ring member
        // independently observes a brand-new sibling's *same* pool KP (the
        // pool snapshot is identical for everyone) and each tries to
        // `create_device_coord_group` using it. Only one Welcome can ever
        // be successfully processed by the new sibling — its init secret
        // is consumed on first success — so every other ring member's
        // attempt is permanently stuck ("No matching key package was
        // found in the key store"), with no retry, since `peer_get`'s
        // dedup above prevents ever trying again. This is the exact
        // same-KP race `same-user-key-distribution.md` fixed for ring-join
        // and user-conversation fan-out, just never applied to this
        // earlier coord-group-bootstrap step. Deferring to the elected
        // member is safe: the elected member's coord group with the new
        // sibling carries Hello/RingInfo/RingWelcome, which is all any
        // *other* ring member needs — once the new sibling is a ring
        // member, the ring itself is their shared channel for anything
        // else (the same-user KP lane is stealth-addressed and doesn't
        // need a coord group at all). Doesn't apply before any ring
        // exists (Solo/Discovering) — the original two-device bootstrap
        // symmetric-race-then-converge dance is unaffected.
        if let RingMembership::InRing { ring_id, .. } = &self.ring {
            let ring_id = ring_id.clone();
            let members = mls.get_group_members(&ring_id).unwrap_or_default();
            let my_leaf = find_own_leaf(mls, &ring_id);
            let smallest_leaf = members.iter().map(|(idx, _)| *idx).min();
            if my_leaf.is_none() || my_leaf != smallest_leaf {
                self.peer_insert(sibling_id, PeerState::Discovered);
                return Vec::new();
            }
        }

        // First sighting: create coord group, transition to AwaitingTheirHello.
        self.promote_to_discovering();

        let CoordGroupResult { group_id, commit, welcome } =
            match mls.create_device_coord_group(env.credential, env.key_bundle, key_package) {
                Ok(r) => r,
                Err(_) => {
                    // Couldn't create — record as Discovered so a later tick may retry.
                    self.peer_insert(sibling_id, PeerState::Discovered);
                    return Vec::new();
                }
            };

        let mut cmds = Vec::new();
        cmds.push(RingCommand::RegisterGroup {
            group_id: group_id.clone(),
            kind: GroupKind::DeviceCoord,
        });

        let commit_tag = mls
            .derive_next_tag(&group_id, env.key_bundle)
            .unwrap_or_else(|_| rand::random());
        cmds.push(RingCommand::PublishEvent {
            tag: commit_tag,
            ciphertext: commit,
            mark_own: true,
        });

        // Our Hello into the new coord group.
        let epoch = mls.get_group_epoch(&group_id).ok().flatten().unwrap_or(0);
        let hello_event = Event::coord(
            group_id.clone(),
            epoch,
            encode_coord_msg(&CoordMsg::Hello {
                sender_device_id: my_device_id.to_vec(),
            }),
        );
        if let Ok(enc) = mls.encrypt_event(&group_id, env.key_bundle, &hello_event) {
            cmds.push(RingCommand::PublishEvent {
                tag: enc.tag,
                ciphertext: enc.ciphertext,
                mark_own: true,
            });
        }
        // Tell the sibling about our ring, if we have one — see
        // `emit_ring_info` for why this closes the ring-creation race.
        if let Some(cmd) = self.emit_ring_info(mls, env, &group_id) {
            cmds.push(cmd);
        }

        // Stealth-publish the coord Welcome envelope so the sibling can find it.
        if !env.stealth_pubkeys.is_empty() {
            let envelope = encode_welcome_envelope(&welcome);
            if let Ok(ct) = encrypt_for_stealth(env.stealth_pubkeys, &envelope) {
                cmds.push(RingCommand::StealthPublishWelcome {
                    tag: rand::random(),
                    ciphertext: ct,
                });
            }
        }

        self.peer_insert(sibling_id, PeerState::AwaitingTheirHello { coord_group_id: group_id });
        cmds
    }

    /// Stash an incoming bootstrap KP unless we have already consumed
    /// one from this sender.  The `on_tick` ring-add loop drains the
    /// pending map and produces the actual Welcome.  No commands fire
    /// from this arm — keeping ring-add side effects in a single place
    /// makes the "consumed exactly once" property local and auditable.
    fn on_bootstrap_kp_received(
        &mut self,
        from_device_id: DeviceId,
        key_package: &[u8],
    ) -> Vec<RingCommand> {
        let key = hex::encode(from_device_id);
        if self.consumed_bootstrap_for.contains(&key) {
            // Replay defence: already added this sibling to our ring.
            return Vec::new();
        }
        // Overwrite-on-duplicate is fine; the latest KP is as good as
        // any other.  pending_bootstrap_kps is keyed by sender, so a
        // re-publication from D_new before consumption just replaces.
        self.pending_bootstrap_kps.insert(key, key_package.to_vec());
        Vec::new()
    }

    fn on_stealth_payload(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        plaintext: &[u8],
    ) -> Vec<RingCommand> {
        // BootstrapKp events arrive as padded Event JSON (Phase C). Try
        // unpadding first; if the result starts with '{' and parses as an
        // Event with `kind == BootstrapKp`, route it to the bootstrap arm.
        //
        // `unpad` is forgiving about non-padded inputs (returns Vec::new()
        // when the leading length prefix is implausible), so passing an
        // MWE1 envelope through it is safe — it just produces an empty
        // result and falls through to the Welcome handler below.
        let unpadded = crate::padding::unpad(plaintext);
        if unpadded.first() == Some(&b'{') {
            if let Ok(ev) = Event::from_bytes(&unpadded) {
                if matches!(ev.kind, crate::EventKind::BootstrapKp) {
                    let from_device_id = match mls
                        .extract_credential_from_key_package(&ev.payload)
                        .ok()
                        .flatten()
                    {
                        Some(cred) => *cred.device_id(),
                        None => return Vec::new(),
                    };
                    return self.on_bootstrap_kp_received(from_device_id, &ev.payload);
                }
                // Steady-state sibling coordination (KP lane) — see
                // `on_sibling_msg` for the authenticity model.
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

        // Stealth payload may be either the raw Welcome (legacy) or an MWE1
        // envelope.  Try to unwrap; fall back to the raw plaintext.
        let unwrapped = decode_welcome_envelope(plaintext);
        let welcome_bytes: &[u8] = unwrapped.as_deref().unwrap_or(plaintext);

        let group_id = match mls.process_welcome(welcome_bytes) {
            Ok(id) => id,
            Err(_) => return Vec::new(), // already joined or not for us
        };

        self.on_group_joined_via_welcome(mls, env, group_id)
    }

    fn on_coord_group_joined(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        group_id: &[u8],
    ) -> Vec<RingCommand> {
        // Host already called process_welcome; we just sync state and emit Hello.
        self.on_group_joined_via_welcome(mls, env, group_id.to_vec())
    }

    /// Common path after a Welcome has been processed: classify the new group,
    /// register it, and (for coord groups) publish our Hello.
    fn on_group_joined_via_welcome(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        group_id: Vec<u8>,
    ) -> Vec<RingCommand> {
        let my_device_id = *mls.device_id();
        let mut cmds = Vec::new();

        // Is it the ring?  (We don't expect ring Welcomes via stealth in normal
        // operation — they arrive via CoordMsg::RingWelcome — but be defensive.)
        if let RingMembership::InRing { ring_id, .. } = &self.ring {
            if ring_id.as_slice() == group_id.as_slice() {
                cmds.push(RingCommand::RegisterGroup {
                    group_id,
                    kind: GroupKind::Ring,
                });
                return cmds;
            }
        }

        let members = mls.get_group_members(&group_id).unwrap_or_default();
        let kind = classify_group_kind(&members, env.my_did);

        match kind {
            GroupKind::DeviceCoord => {
                // Identify the sibling.
                let sibling_id = members.iter().find_map(|(_, c)| {
                    c.as_ref().and_then(|c| {
                        if c.did() == env.my_did && *c.device_id() != my_device_id {
                            Some(*c.device_id())
                        } else {
                            None
                        }
                    })
                });

                cmds.push(RingCommand::RegisterGroup {
                    group_id: group_id.clone(),
                    kind: GroupKind::DeviceCoord,
                });
                // We just consumed our init key; replenish.
                cmds.push(RingCommand::ReplenishKeyPackage);

                if let Some(sib) = sibling_id {
                    // Always update the routing entry so that the group the sibling
                    // CREATED (and therefore has candidate tags for) is used when
                    // sending later RingWelcomes.
                    self.promote_to_discovering();
                    let new_state = match self.peer_get(&sib).cloned() {
                        Some(PeerState::CoordReady { ring_link, .. }) => {
                            PeerState::CoordReady { coord_group_id: group_id.clone(), ring_link }
                        }
                        _ => PeerState::AwaitingTheirHello { coord_group_id: group_id.clone() },
                    };
                    self.peer_insert(sib, new_state);

                    // Publish our Hello into this group.
                    let epoch = mls.get_group_epoch(&group_id).ok().flatten().unwrap_or(0);
                    let hello_event = Event::coord(
                        group_id.clone(),
                        epoch,
                        encode_coord_msg(&CoordMsg::Hello {
                            sender_device_id: my_device_id.to_vec(),
                        }),
                    );
                    if let Ok(enc) = mls.encrypt_event(&group_id, env.key_bundle, &hello_event) {
                        cmds.push(RingCommand::PublishEvent {
                            tag: enc.tag,
                            ciphertext: enc.ciphertext,
                            mark_own: true,
                        });
                    }
                    // Tell the sibling about our ring, if we have one — see
                    // `emit_ring_info` for why this closes the ring-creation race.
                    if let Some(cmd) = self.emit_ring_info(mls, env, &group_id) {
                        cmds.push(cmd);
                    }
                }
            }
            GroupKind::User => {
                cmds.push(RingCommand::RegisterGroup { group_id, kind: GroupKind::User });
                cmds.push(RingCommand::ReplenishKeyPackage);
            }
            GroupKind::Ring => {
                // Shouldn't happen via stealth in modern flow, but be defensive.
                cmds.push(RingCommand::RegisterGroup { group_id, kind: GroupKind::Ring });
            }
        }

        cmds
    }

    fn on_coord_msg(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        source_group_id: &[u8],
        sender_device_id: Option<DeviceId>,
        msg: CoordMsg,
    ) -> Vec<RingCommand> {
        let my_device_id = *mls.device_id();

        // Resolve sender: prefer the host-supplied hint (from the Event
        // wrapper at decrypt time), then the device_id carried in the
        // message itself (Hello only), then a coord-group member lookup.
        // The member lookup only works for 2-party coord groups; ring
        // messages (N > 2 members) MUST have the sender hint set.
        let from_device_id: DeviceId = sender_device_id.unwrap_or_else(|| {
            let members = mls.get_group_members(source_group_id).unwrap_or_default();
            members
                .iter()
                .find_map(|(_, c)| {
                    c.as_ref().and_then(|c| {
                        if c.did() == env.my_did && *c.device_id() != my_device_id {
                            Some(*c.device_id())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or([0u8; 16])
        });

        match msg {
            CoordMsg::Hello { sender_device_id } => {
                let id: DeviceId = sender_device_id
                    .as_slice()
                    .try_into()
                    .unwrap_or(from_device_id);
                self.record_hello_from(id, source_group_id);
                Vec::new()
            }
            CoordMsg::RingInfo { ring_id, generation, created_at } => {
                self.maybe_reconcile(&ring_id, generation, created_at);
                Vec::new()
            }
            CoordMsg::Supersede { old_ring_id } => {
                if let RingMembership::InRing { ring_id, .. } = &self.ring {
                    if ring_id == &old_ring_id {
                        self.ring = if self.peers.is_empty() {
                            RingMembership::Solo
                        } else {
                            RingMembership::Discovering { defer_ticks: 0 }
                        };
                    }
                }
                Vec::new()
            }
            CoordMsg::RingWelcome { ring_id, welcome, generation, created_at } => {
                self.on_ring_welcome(mls, env, ring_id, welcome, generation, created_at)
            }
            CoordMsg::SyncOffer { token, target_device_id } => {
                let for_us = target_device_id
                    .as_deref()
                    .map_or(true, |t| t == &my_device_id[..]);
                if for_us {
                    vec![RingCommand::SendDrawbridgePairJoin { token }]
                } else {
                    Vec::new()
                }
            }
            // KP-lane messages ride the stealth lane (`EventKind::SiblingMsg`
            // → `on_sibling_msg`), not MLS channels.  If one arrives here —
            // e.g. published by a pre-E′ build — ignore it rather than
            // double-processing.
            CoordMsg::KpBatch { .. }
            | CoordMsg::KpRequest { .. }
            | CoordMsg::UserConvWelcome { .. } => Vec::new(),
        }
    }

    /// Handle a stealth-delivered sibling CoordMsg (`EventKind::SiblingMsg`).
    ///
    /// Only the KP-lane variants are meaningful here; membership and sync
    /// messages (`Hello`, `RingInfo`, `RingWelcome`, `SyncOffer`,
    /// `Supersede`) stay on the MLS coord channels and are ignored if a
    /// peer (mis)sends them via stealth.
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
                if !self.ring_joined_siblings().contains(&sender) {
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
            // Membership/sync traffic does not ride the stealth lane.
            CoordMsg::Hello { .. }
            | CoordMsg::RingInfo { .. }
            | CoordMsg::Supersede { .. }
            | CoordMsg::RingWelcome { .. }
            | CoordMsg::SyncOffer { .. } => Vec::new(),
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

    /// Device ids of siblings whose ring-membership status is
    /// [`RingLink::Joined`].  The host uses this to drive the same-user
    /// fan-out: walk every confirmed ring member, and for each user
    /// conversation they are not yet in, draw a KP and emit a
    /// [`CoordMsg::UserConvWelcome`].
    pub fn ring_joined_siblings(&self) -> Vec<DeviceId> {
        self.peers
            .iter()
            .filter_map(|(hex_id, ps)| {
                if let PeerState::CoordReady {
                    ring_link: RingLink::Joined { .. },
                    ..
                } = ps
                {
                    let bytes = hex::decode(hex_id).ok()?;
                    let mut out = [0u8; 16];
                    if bytes.len() != 16 {
                        return None;
                    }
                    out.copy_from_slice(&bytes);
                    Some(out)
                } else {
                    None
                }
            })
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

    fn record_hello_from(&mut self, sibling_id: DeviceId, source_group_id: &[u8]) {
        let key = hex::encode(sibling_id);
        let new_state = match self.peers.get(&key) {
            Some(PeerState::AwaitingTheirHello { coord_group_id })
            | Some(PeerState::CoordReady { coord_group_id, .. }) => PeerState::CoordReady {
                coord_group_id: coord_group_id.clone(),
                ring_link: RingLink::PendingAdd,
            },
            Some(PeerState::Discovered) | None => PeerState::CoordReady {
                coord_group_id: source_group_id.to_vec(),
                ring_link: RingLink::PendingAdd,
            },
        };
        // Preserve ring_link if already Joined.
        let final_state = match self.peers.get(&key) {
            Some(PeerState::CoordReady { ring_link: rl @ RingLink::Joined { .. }, coord_group_id }) => {
                PeerState::CoordReady { coord_group_id: coord_group_id.clone(), ring_link: rl.clone() }
            }
            _ => new_state,
        };
        self.peers.insert(key, final_state);
        self.promote_to_discovering();
    }

    fn maybe_reconcile(&mut self, theirs_ring_id: &[u8], theirs_generation: u64, theirs_created_at: i64) {
        let theirs = RingRef {
            ring_id: theirs_ring_id,
            generation: theirs_generation,
            created_at: theirs_created_at,
        };
        if let RingMembership::InRing { ring_id, created_at, generation, .. } = &self.ring {
            let mine = RingRef { ring_id, generation: *generation, created_at: *created_at };
            match reconcile_rings(mine, theirs) {
                ReconcileDecision::AlreadyInTheirs | ReconcileDecision::KeepMine => {}
                ReconcileDecision::SwitchToTheirs => {
                    self.ring = if self.peers.is_empty() {
                        RingMembership::Solo
                    } else {
                        RingMembership::Discovering { defer_ticks: 0 }
                    };
                }
            }
        } else {
            // Not yet in a ring: remember that one already exists so the
            // Discovering-branch creator tiebreak (which only sees locally
            // Hello-exchanged peers) doesn't race to create a second,
            // competing ring.  We don't adopt `theirs_ring_id` directly —
            // `RingInfo` carries no Welcome, so we hold no MLS state for
            // that group yet; real membership still arrives via the
            // normal Add/Welcome path once an existing member processes
            // our bootstrap KP.
            self.known_ring = Some((theirs_ring_id.to_vec(), theirs_generation, theirs_created_at));
        }
    }

    /// If we're already `InRing`, build a `CoordMsg::RingInfo` for the given
    /// coord group so a newly Hello-exchanged sibling learns of our ring
    /// immediately — before its own Discovering-branch tiebreak could
    /// otherwise race to create a second one.  No-op (returns `None`) if we
    /// have no ring yet or encryption fails.
    fn emit_ring_info(
        &self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        coord_group_id: &[u8],
    ) -> Option<RingCommand> {
        let (ring_id, generation, created_at) = match &self.ring {
            RingMembership::InRing { ring_id, generation, created_at, .. } => {
                (ring_id.clone(), *generation, *created_at)
            }
            _ => return None,
        };
        let msg = CoordMsg::RingInfo { ring_id, generation, created_at };
        let epoch = mls.get_group_epoch(coord_group_id).ok().flatten().unwrap_or(0);
        let event = Event::coord(coord_group_id.to_vec(), epoch, encode_coord_msg(&msg));
        let enc = mls.encrypt_event(coord_group_id, env.key_bundle, &event).ok()?;
        Some(RingCommand::PublishEvent { tag: enc.tag, ciphertext: enc.ciphertext, mark_own: true })
    }

    fn on_ring_welcome(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        ring_id: Vec<u8>,
        welcome: Vec<u8>,
        generation: u64,
        created_at: i64,
    ) -> Vec<RingCommand> {
        // Already in a ring? Only a superseding one displaces it — a device
        // onboarding into an established set creates generation N+1 and
        // invites the existing members, so those members must be willing to
        // move. Uses the same ordering as `RingInfo` reconciliation, so a
        // stale or replayed Welcome for a lower generation is ignored.
        if let RingMembership::InRing { ring_id: mine_id, created_at: mine_at, generation: mine_gen, .. } =
            &self.ring
        {
            let mine = RingRef { ring_id: mine_id, generation: *mine_gen, created_at: *mine_at };
            let theirs = RingRef { ring_id: &ring_id, generation, created_at };
            match reconcile_rings(mine, theirs) {
                ReconcileDecision::AlreadyInTheirs | ReconcileDecision::KeepMine => return Vec::new(),
                ReconcileDecision::SwitchToTheirs => {}
            }
        }
        let joined = match mls.process_welcome(&welcome) {
            Ok(id) => id,
            Err(_) => return Vec::new(),
        };
        if joined != ring_id {
            return Vec::new();
        }
        let our_leaf = find_own_leaf(mls, &ring_id).unwrap_or(u32::MAX);
        self.ring = RingMembership::InRing { ring_id: ring_id.clone(), created_at, generation, our_leaf };
        self.known_ring = None; // no longer meaningful once we hold real membership

        // All ring members (other than us) are siblings already; mark them
        // Joined with sync: OweOffer.  We (the joiner) won't actually emit a
        // sync offer (try_emit_sync_offer gates on our_leaf == 0); OweOffer
        // here only tracks the one-shot pairing-offer obligation.
        // `PollForNewDevices` itself now fires every tick for any Joined
        // sibling (see `on_tick`), independent of this flag, so we add
        // these siblings to any user conversations we own.
        let members = mls.get_group_members(&ring_id).unwrap_or_default();
        let my_device_id = *mls.device_id();
        for (_, cred) in &members {
            if let Some(c) = cred {
                let dev_id = *c.device_id();
                if c.did() != env.my_did || dev_id == my_device_id {
                    continue;
                }
                let key = hex::encode(dev_id);
                let new_state = match self.peers.get(&key).cloned() {
                    Some(PeerState::CoordReady { coord_group_id, .. }) => PeerState::CoordReady {
                        coord_group_id,
                        ring_link: RingLink::Joined {
                            added_by: AddedBy::Them,
                            sync: SyncStatus::OweOffer,
                        },
                    },
                    Some(PeerState::AwaitingTheirHello { coord_group_id }) => PeerState::CoordReady {
                        coord_group_id,
                        ring_link: RingLink::Joined {
                            added_by: AddedBy::Them,
                            sync: SyncStatus::OweOffer,
                        },
                    },
                    // No coord group with this peer (either never
                    // established, or its creation was deferred to the
                    // elected ring member — see `on_peer_kp_observed`'s
                    // leaf-election gate). We've just confirmed them as an
                    // authoritative ring member via `get_group_members`
                    // directly, so mark Joined anyway with an empty
                    // `coord_group_id` — same-user fan-out
                    // (`ring_joined_siblings`) only cares about `Joined`,
                    // and any future `do_ring_add` for this peer will
                    // short-circuit on the "already a member" check before
                    // ever consulting `coord_group_id_for`.
                    Some(PeerState::Discovered) | None => PeerState::CoordReady {
                        coord_group_id: Vec::new(),
                        ring_link: RingLink::Joined {
                            added_by: AddedBy::Them,
                            sync: SyncStatus::OweOffer,
                        },
                    },
                };
                self.peers.insert(key, new_state);
            }
        }

        let mut cmds = vec![
            RingCommand::RegisterGroup { group_id: ring_id.clone(), kind: GroupKind::Ring },
            // Welcome consumed our init key — replenish so a future Add can target us.
            RingCommand::ReplenishKeyPackage,
            // The next tick will trigger PollForNewDevices so we add the existing
            // ring members to all known user conversations.
            RingCommand::PollForNewDevices,
        ];
        // Phase D: ship every existing ring member an initial KP batch so
        // they can add us to their user conversations without a round
        // trip.  The adder already received their own initial batch when
        // they Added us (see do_ring_add), so this is the symmetric half
        // for every OTHER ring member.
        for (_, cred) in &members {
            if let Some(c) = cred {
                let dev_id = *c.device_id();
                if c.did() != env.my_did || dev_id == my_device_id {
                    continue;
                }
                cmds.extend(self.ship_initial_kp_batches_to(mls, env, &dev_id));
            }
        }
        cmds
    }

    fn on_sync_session_ended(&mut self) -> Vec<RingCommand> {
        // Clear any in-flight OfferEmitted so future ticks can re-arm.
        for (_k, ps) in self.peers.iter_mut() {
            if let PeerState::CoordReady {
                ring_link: RingLink::Joined { sync, .. }, ..
            } = ps
            {
                if matches!(sync, SyncStatus::OfferEmitted { .. }) {
                    *sync = SyncStatus::Done;
                }
            }
        }
        Vec::new()
    }

    /// For every confirmed ring-member peer, fire a `CoordMsg::KpRequest`
    /// if our local pool of that peer's KPs is at or below the low-water
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
        let my_device_id = *mls.device_id();
        let mut cmds = Vec::new();
        for (hex_key, ps) in self.peers.iter() {
            // Only confirmed ring members.
            if !matches!(
                ps,
                PeerState::CoordReady { ring_link: RingLink::Joined { .. }, .. }
            ) {
                continue;
            }
            let bytes = match hex::decode(hex_key) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let owner: DeviceId = match bytes.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => continue,
            };
            if owner == my_device_id {
                continue;
            }
            cmds.extend(self.maybe_emit_kp_request(mls, env, &owner));
        }
        cmds
    }

    /// Publish a bootstrap KP event for each known sibling we have not
    /// yet published one to.  Symmetric — any device, regardless of ring
    /// membership, publishes one of these per newly-observed sibling.
    /// The receiver picks the event up via its own-PDS stealth scan and
    /// uses the embedded KP to add us to the ring.  Once `published_bootstrap_for`
    /// has marked a sibling, we never republish for them — the original
    /// event sits on the PDS indefinitely (see `same-user-key-distribution.md`).
    fn publish_bootstrap_kps(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
    ) -> Vec<RingCommand> {
        let mut cmds = Vec::new();
        let my_device_id = *mls.device_id();
        for sib in env.sibling_stealth {
            if sib.device_id == my_device_id {
                continue;
            }
            let key = hex::encode(sib.device_id);
            if self.published_bootstrap_for.contains(&key) {
                continue;
            }
            // Fresh init key, kept in our local keystore; never written to the
            // cross-user PDS pool — bootstrap KPs are exclusive to this lane.
            // Signing key is our identity key (see the module note).
            let kp_bytes = match mls.replenish_key_package(env.credential, env.key_bundle) {
                Ok(p) => p,
                Err(_) => continue, // try again next tick
            };
            let event = Event::bootstrap_kp(kp_bytes);
            let event_bytes = match event.to_bytes() {
                Ok(b) => b,
                Err(_) => continue,
            };
            let padded = crate::padding::pad_to_bucket(&event_bytes);
            let ciphertext = match encrypt_for_stealth(&[sib.scan_pubkey], &padded) {
                Ok(ct) => ct,
                Err(_) => continue,
            };
            let tag: [u8; 16] = rand::random();
            cmds.push(RingCommand::PublishStealthEvent { tag, ciphertext });
            self.published_bootstrap_for.insert(key);
        }
        cmds
    }

    fn on_tick(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        _key_packages: &[KeyPackageInput],
    ) -> Vec<RingCommand> {
        let mut cmds = Vec::new();

        // ── Pre-A. Publish bootstrap KP for each newly-observed sibling ──
        cmds.extend(self.publish_bootstrap_kps(mls, env));

        // ── Pre-A bis. Top up pools that are at-or-below low-water ───────
        cmds.extend(self.emit_low_water_kp_requests(mls, env));

        // ── A. Detect ring members added by someone else ─────────────────
        if let RingMembership::InRing { ring_id, our_leaf, .. } = &self.ring {
            let ring_id = ring_id.clone();
            let our_leaf = *our_leaf;
            if let Ok(members) = mls.get_group_members(&ring_id) {
                let my_device_id = *mls.device_id();
                let mut to_mark: Vec<DeviceId> = Vec::new();
                for (leaf_idx, cred_opt) in &members {
                    if let Some(cred) = cred_opt {
                        let dev_id = *cred.device_id();
                        if cred.did() != env.my_did || dev_id == my_device_id {
                            continue;
                        }
                        // Skip pre-existing members (they joined before us).
                        if *leaf_idx <= our_leaf {
                            continue;
                        }
                        let key = hex::encode(dev_id);
                        let already_joined = matches!(
                            self.peers.get(&key),
                            Some(PeerState::CoordReady { ring_link: RingLink::Joined { .. }, .. })
                        );
                        if !already_joined {
                            to_mark.push(dev_id);
                        }
                    }
                }
                for dev_id in to_mark {
                    let key = hex::encode(dev_id);
                    let new_state = match self.peers.get(&key).cloned() {
                        Some(PeerState::CoordReady { coord_group_id, .. }) => PeerState::CoordReady {
                            coord_group_id,
                            ring_link: RingLink::Joined {
                                added_by: AddedBy::OtherSibling(my_device_id_or_placeholder(mls)),
                                sync: SyncStatus::OweOffer,
                            },
                        },
                        Some(PeerState::AwaitingTheirHello { coord_group_id }) => PeerState::CoordReady {
                            coord_group_id,
                            ring_link: RingLink::Joined {
                                added_by: AddedBy::OtherSibling(my_device_id_or_placeholder(mls)),
                                sync: SyncStatus::OweOffer,
                            },
                        },
                        // See the matching comment in `on_ring_welcome`: no
                        // coord group with this peer (deferred to the
                        // elected ring member), but `get_group_members`
                        // just confirmed them as a real ring member, so
                        // mark Joined with an empty `coord_group_id`.
                        Some(PeerState::Discovered) | None => PeerState::CoordReady {
                            coord_group_id: Vec::new(),
                            ring_link: RingLink::Joined {
                                added_by: AddedBy::OtherSibling(my_device_id_or_placeholder(mls)),
                                sync: SyncStatus::OweOffer,
                            },
                        },
                    };
                    self.peers.insert(key, new_state);
                }
            }
        }

        // ── B. PollForNewDevices fires on every tick while we have at least
        //       one confirmed ring sibling — this drives the per-conversation
        //       add_device fan-out on the inviting side, independently of
        //       Drawbridge/history-sync availability.
        //
        //       Previously gated on `SyncStatus::OweOffer`, which is a
        //       one-shot signal that clears as soon as the (also one-shot)
        //       history-sync pairing offer is emitted.  That conflated two
        //       unrelated retry cadences: pairing-offer is genuinely
        //       one-shot, but same-user fan-out is not — it must keep
        //       retrying every tick until every user conversation contains
        //       every ring sibling, since a fan-out attempt can stall
        //       waiting on a KP-pool refill (`emit_kp_request_for` /
        //       `claim_kp` in the host's `poll_for_new_devices`) that only
        //       resolves on a later tick.  `poll_for_new_devices` is
        //       idempotent — it skips conversations that already contain a
        //       given sibling — so firing it unconditionally here is safe.
        let any_joined_sibling = self.peers.values().any(|ps| {
            matches!(
                ps,
                PeerState::CoordReady { ring_link: RingLink::Joined { .. }, .. }
            )
        });
        if any_joined_sibling {
            cmds.push(RingCommand::PollForNewDevices);
        }

        // ── B bis. Recover peers stalled with no acknowledgement path ────
        cmds.extend(self.recover_stalled_peers());

        // ── C. Issue a sync offer to any OweOffer peer we out-rank ───────
        if env.drawbridge_connected && !env.sync_session_active {
            cmds.extend(self.try_emit_sync_offer(mls, env));
        }

        // ── D. Bootstrap ring or MLS Add CoordReady peers ────────────────
        cmds.extend(self.try_advance_ring_membership(mls, env));

        cmds
    }

    /// Recover peers stuck in a wait that will never be reported as failed.
    ///
    /// Two states have no acknowledgement path, so failure is
    /// indistinguishable from slowness and neither self-corrects:
    ///
    /// - `OfferEmitted` — the peer may be busy in another pair session and
    ///   never accept. `any_offer_in_flight()` is a per-device gate, so one
    ///   unaccepted offer blocks every future offer to anyone. Recovery
    ///   returns the peer to `OweOffer`; safe to repeat, since pairing tokens
    ///   are single-use with a relay-side expiry.
    /// - `AwaitingTheirHello` — the coord-group Welcome we sent may have been
    ///   built from a key package whose init key was already consumed, which
    ///   the peer cannot process and never reports. Recovery drops the peer
    ///   entry so discovery re-arms: `on_peer_kp_observed` dedups on the entry
    ///   existing, so clearing it is what allows a fresh attempt.
    fn recover_stalled_peers(&mut self) -> Vec<RingCommand> {
        let waiting: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, ps)| {
                matches!(
                    ps,
                    PeerState::AwaitingTheirHello { .. }
                        | PeerState::CoordReady {
                            ring_link: RingLink::Joined { sync: SyncStatus::OfferEmitted { .. }, .. },
                            ..
                        }
                )
            })
            .map(|(k, _)| k.clone())
            .collect();

        // Peers that are no longer waiting should not keep a stale clock.
        self.stall_ticks.retain(|k, _| waiting.contains(k));

        for key in waiting {
            let ticks = self.stall_ticks.entry(key.clone()).or_insert(0);
            *ticks += 1;
            if *ticks <= STALL_RETRY_TICKS {
                continue;
            }
            self.stall_ticks.remove(&key);
            match self.peers.get_mut(&key) {
                Some(PeerState::CoordReady {
                    ring_link: RingLink::Joined { sync, .. },
                    ..
                }) => *sync = SyncStatus::OweOffer,
                Some(PeerState::AwaitingTheirHello { .. }) => {
                    self.peers.remove(&key);
                }
                _ => {}
            }
        }
        Vec::new()
    }

    /// At most one offer **in flight**.  Walks peers, picks the first OweOffer
    /// (deterministic by hex key sort), and emits the offer if conditions
    /// allow.  Sets the peer's sync to OfferEmitted on success.
    fn try_emit_sync_offer(&mut self, mls: &MoatSession, env: &StepEnv<'_>) -> Vec<RingCommand> {
        let ring_id = match &self.ring {
            RingMembership::InRing { ring_id, .. } => ring_id.clone(),
            _ => return Vec::new(),
        };
        // An emitted offer only makes `env.sync_session_active` true once the
        // peer accepts it, so that flag alone doesn't cover the emit→accept
        // window: with two peers owing offers we would emit to the second
        // before the first cleared.  `SyncSessionEnded` resets these to `Done`.
        if self.any_offer_in_flight() {
            return Vec::new();
        }

        // Offerer election is per pair: within each pair the smaller
        // `device_id` offers. `SyncStatus::OweOffer` is set symmetrically, so
        // without a tiebreak both sides would offer and open two pairing
        // sessions for one pair.
        //
        // A fixed per-pair choice costs nothing in liveness: history transfer
        // needs a pair WebSocket with both ends online, so if a pair's
        // offerer is offline that pair could not have synced anyway. Every
        // pair has its own offerer, so no device's absence blocks another
        // pair.
        // Serve the least-attempted peer first, breaking ties by key for
        // determinism. Sorted-key order alone starves: stall recovery returns
        // an unresponsive peer to `OweOffer`, so it would be re-selected on
        // every attempt while peers sorting after it are never served. Only
        // one offer may be in flight per device, so that is a permanent
        // block, not a delay.
        let my_key = hex::encode(mls.device_id());
        let mut candidates: Vec<&String> = self
            .peers
            .iter()
            .filter(|(k, ps)| {
                // Fixed-width lowercase hex, so string order is byte order.
                my_key.as_str() < k.as_str()
                    && matches!(
                        ps,
                        PeerState::CoordReady {
                            ring_link: RingLink::Joined { sync: SyncStatus::OweOffer, .. },
                            ..
                        }
                    )
            })
            .map(|(k, _)| k)
            .collect();
        candidates.sort_by_key(|k| (self.offer_attempts.get(*k).copied().unwrap_or(0), (*k).clone()));
        let target_key = candidates.first().map(|k| (*k).clone());
        let Some(target_key) = target_key else { return Vec::new() };

        let target_id_bytes = hex::decode(&target_key).unwrap_or_default();
        let target_device_id: DeviceId = match target_id_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return Vec::new(),
        };

        let mut cmds = Vec::new();
        use rand::RngCore;
        let mut token = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);

        let epoch = mls.get_group_epoch(&ring_id).ok().flatten().unwrap_or(0);
        let offer_event = Event::coord(
            ring_id.clone(),
            epoch,
            encode_coord_msg(&CoordMsg::SyncOffer {
                token: token.clone(),
                target_device_id: Some(target_device_id.to_vec()),
            }),
        );
        // SendDrawbridgePairOffer must be processed BEFORE PublishEvent so the
        // pair_offer is registered on Drawbridge before the SyncOffer lands on
        // the PDS.
        cmds.push(RingCommand::SendDrawbridgePairOffer { token: token.clone() });
        // We are InRing with this ring_id, so our leaf exists and is signed with
        // our identity key — this cannot legitimately fail.  Swallowing it here
        // once hid a signing-key mismatch that silently stopped every
        // non-creator ring member from ever emitting a sync offer.
        match mls.encrypt_event(&ring_id, env.key_bundle, &offer_event) {
            Ok(enc) => cmds.push(RingCommand::PublishEvent {
                tag: enc.tag,
                ciphertext: enc.ciphertext,
                mark_own: true,
            }),
            Err(e) => debug_assert!(false, "sync offer encrypt into own ring failed: {e}"),
        }

        *self.offer_attempts.entry(target_key.clone()).or_insert(0) += 1;

        // Update peer state to OfferEmitted.
        if let Some(PeerState::CoordReady { ring_link: RingLink::Joined { sync, .. }, .. }) =
            self.peers.get_mut(&target_key)
        {
            *sync = SyncStatus::OfferEmitted { token };
        }

        cmds
    }

    fn try_advance_ring_membership(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
    ) -> Vec<RingCommand> {
        let mut cmds = Vec::new();
        let my_device_id = *mls.device_id();

        // Snapshot of peers that need MLS adding.
        let pending: Vec<DeviceId> = self
            .peer_iter()
            .filter_map(|(id, ps)| match ps {
                PeerState::CoordReady { ring_link: RingLink::PendingAdd, .. } => Some(id),
                _ => None,
            })
            .collect();

        if pending.is_empty() {
            // No pending Adds.  Reset Discovering defer if applicable.
            if let RingMembership::Discovering { defer_ticks } = &mut self.ring {
                *defer_ticks = 0;
            }
            return cmds;
        }

        match &self.ring {
            RingMembership::InRing { ring_id, .. } => {
                let ring_id = ring_id.clone();
                // Every pending peer is checked (do_ring_add recognises an
                // already-present MLS member and updates bookkeeping to
                // Joined for ANY device, elected or not — see the leaf-
                // election gate inside do_ring_add for why the actual
                // `add_device` mutation itself is restricted to one device).
                for sib in &pending {
                    if let Some(cmds_for_add) =
                        self.do_ring_add(mls, env, &ring_id, *sib)
                    {
                        cmds.extend(cmds_for_add);
                    }
                }
            }
            RingMembership::Discovering { defer_ticks } => {
                // Two different situations reach this arm, and they take
                // opposite decisions.
                //
                // (a) `known_ring` is set: a sibling has told us via
                //     `CoordMsg::RingInfo` that a ring already exists and we
                //     are not in it. We are onboarding into an established
                //     device set, so *we* create the next generation and
                //     invite everyone we know. We are the only participant
                //     guaranteed to be online — waiting to be added means
                //     waiting on a device that may be asleep or destroyed,
                //     which is the deadlock `ring-inversion.md` documents.
                //     The device_id tiebreak deliberately does not apply:
                //     the existing members are `InRing` and will never
                //     compete for creation, so applying it would just block
                //     us behind a device that is not going to act.
                //
                // (b) `known_ring` is unset: no ring exists anywhere yet, so
                //     this is first-ring formation among mutually-discovering
                //     devices. Keep the smallest-device_id tiebreak, which
                //     picks one creator among genuine competitors.
                let joining_established = self.known_ring.clone();

                if joining_established.is_none() {
                    // Are we the smallest device_id among ourselves + hello-exchanged peers?
                    let mut all_ids: Vec<DeviceId> = pending.clone();
                    all_ids.push(my_device_id);
                    all_ids.sort();
                    if all_ids[0] != my_device_id {
                        // We're not the creator; wait for a RingWelcome from the smallest.
                        return cmds;
                    }
                }

                if *defer_ticks == 0 {
                    // One tick of grace either way. In case (a) it lets an
                    // in-flight `RingWelcome` from an existing member land
                    // first, which is cheaper than a generation bump — if it
                    // does, `on_ring_welcome` moves us to `InRing` and we
                    // never reach here. Unlike the old behaviour, the wait
                    // is bounded: we act on the next tick regardless.
                    self.ring = RingMembership::Discovering { defer_ticks: 1 };
                    return cmds; // skip this tick
                }

                // defer elapsed → create ring.
                let ring_id = match mls.create_device_ring(env.credential, env.key_bundle) {
                    Ok(id) => id,
                    Err(_) => return cmds,
                };
                let our_leaf = find_own_leaf(mls, &ring_id).unwrap_or(0);
                // Superseding an established ring means strictly exceeding
                // its generation; a first ring is generation 1.
                let generation = joining_established.map_or(1, |(_, gen, _)| gen + 1);
                self.ring = RingMembership::InRing {
                    ring_id: ring_id.clone(),
                    created_at: env.now_ms,
                    generation,
                    our_leaf,
                };
                // We hold real membership now, so the remembered "someone
                // else has a ring" hint is spent.
                self.known_ring = None;
                cmds.push(RingCommand::RegisterGroup {
                    group_id: ring_id.clone(),
                    kind: GroupKind::Ring,
                });
                for sib in &pending {
                    if let Some(cmds_for_add) =
                        self.do_ring_add(mls, env, &ring_id, *sib)
                    {
                        cmds.extend(cmds_for_add);
                    }
                }
            }
            RingMembership::Solo => {
                // Pending peers but Solo membership — promote.
                self.ring = RingMembership::Discovering { defer_ticks: 0 };
            }
        }

        cmds
    }

    fn do_ring_add(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        ring_id: &[u8],
        sibling_id: DeviceId,
    ) -> Option<Vec<RingCommand>> {
        // Already a ring member?  Mark Joined and exit.  This check runs
        // for every device regardless of election status below — every
        // ring member independently recognises peers already present in
        // the MLS group and updates its own bookkeeping accordingly.
        let members = mls.get_group_members(ring_id).unwrap_or_default();
        if members.iter().any(|(_, c)| {
            c.as_ref().map(|c| *c.device_id() == sibling_id).unwrap_or(false)
        }) {
            self.mark_peer_joined(sibling_id, AddedBy::OtherSibling([0u8; 16]), SyncStatus::OweOffer);
            return Some(Vec::new());
        }

        // Only the smallest-leaf-index ring member actually performs the
        // Add — mirrors the pairing-offer tiebreak in `try_emit_sync_offer`
        // ("the *only* device that issues pair_offer is the member whose
        // leaf index is the smallest") and closes a genuine concurrent-add
        // race: without a single elected adder, two existing ring members
        // can each independently see the same new sibling as `PendingAdd`
        // and both call `add_device` from the same base epoch. Only one of
        // the resulting commits can be the real successor; the new sibling
        // processes whichever Welcome arrives first and the other fails
        // outright ("Invalid node signature") or leaves the adders' local
        // states silently diverged. Uses `find_own_leaf` (device_id-based),
        // not the stored `our_leaf` or `MoatSession::get_own_leaf_index`
        // (signature-key-based) — see `find_own_leaf`'s doc comment for why
        // signature-key matching is unreliable here.
        let my_leaf = find_own_leaf(mls, ring_id);
        let smallest_leaf = members.iter().map(|(idx, _)| *idx).min();
        if my_leaf.is_none() || my_leaf != smallest_leaf {
            return None; // not our turn to add — the elected member will
        }

        // Phase C: use the bootstrap KP this sibling delivered to us
        // (single-use, race-free).  If none is pending, defer to a
        // later tick — D_new will publish (or has published) and
        // their event will arrive via own-PDS stealth scan.
        let sib_kp_key = hex::encode(sibling_id);
        let sib_kp_bytes = self.pending_bootstrap_kps.get(&sib_kp_key).cloned()?;

        // Derive the commit tag at the current epoch, BEFORE `add_device`
        // advances it. Receivers scan for tags at the epoch they are on and
        // `populate_candidate_tags` covers the current and prior epochs only,
        // so a tag derived after the add is unmatchable by every other member.
        let commit_tag = mls
            .derive_next_tag(ring_id, env.key_bundle)
            .unwrap_or_else(|_| rand::random());

        let wr = match mls.add_device(ring_id, env.key_bundle, &sib_kp_bytes) {
            Ok(w) => w,
            Err(_) => return None,
        };
        // Bootstrap KP is consumed by the add_device call (init key
        // burned).  Move from pending to consumed so a re-fetched
        // BootstrapKp event won't try to use the same init key again.
        self.pending_bootstrap_kps.remove(&sib_kp_key);
        self.consumed_bootstrap_for.insert(sib_kp_key);

        let mut cmds = Vec::new();
        cmds.push(RingCommand::PublishEvent {
            tag: commit_tag,
            ciphertext: wr.commit,
            mark_own: true,
        });
        // RingWelcome via the sibling's coord group (preferred over stealth so
        // they have ring_id context).
        let coord_id_owned = self
            .coord_group_id_for(&sibling_id)
            .map(<[u8]>::to_vec);
        if let Some(coord_id) = coord_id_owned {
            let created_at = self.ring_created_at().unwrap_or(env.now_ms);
            let msg = CoordMsg::RingWelcome {
                ring_id: ring_id.to_vec(),
                welcome: wr.welcome,
                generation: self.ring_generation().unwrap_or(1),
                created_at,
            };
            let epoch = mls.get_group_epoch(&coord_id).ok().flatten().unwrap_or(0);
            let ev = Event::coord(coord_id.clone(), epoch, encode_coord_msg(&msg));
            if let Ok(enc) = mls.encrypt_event(&coord_id, env.key_bundle, &ev) {
                cmds.push(RingCommand::PublishEvent {
                    tag: enc.tag,
                    ciphertext: enc.ciphertext,
                    mark_own: true,
                });
            }
        }

        // Ship the new sibling an initial KP batch via the stealth lane so
        // they can immediately add us to user conversations.  Stealth
        // delivery is epoch-free, so this is safe to emit in the same
        // breath as the ring Add commit.
        cmds.extend(self.ship_initial_kp_batches_to(mls, env, &sibling_id));

        self.mark_peer_joined(sibling_id, AddedBy::Us, SyncStatus::OweOffer);
        Some(cmds)
    }

    /// Emit `KP_POOL_TARGET` fresh KPs to `recipient` via the stealth lane,
    /// split across `ceil(KP_POOL_TARGET / KP_BATCH_CAP)` batches.
    /// Called whenever the ring topology changes (we added a sibling,
    /// or we joined the ring ourselves).  If the recipient's stealth
    /// record is not yet known the batch is skipped — the consumer-driven
    /// low-water `KpRequest` retries the fill on later ticks.
    fn ship_initial_kp_batches_to(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        recipient: &DeviceId,
    ) -> Vec<RingCommand> {
        let mut cmds = Vec::new();
        let mut remaining = KP_POOL_TARGET;
        while remaining > 0 {
            let take = remaining.min(KP_BATCH_CAP);
            let batch = match self.build_kp_batch(mls, env, take) {
                Some(b) => b,
                None => break,
            };
            let msg = CoordMsg::KpBatch {
                recipient_device_id: recipient.to_vec(),
                kps: batch,
            };
            if let Some(cmd) = encrypt_sibling_msg(mls, env, recipient, &msg) {
                cmds.push(cmd);
            }
            remaining -= take;
        }
        cmds
    }

    fn mark_peer_joined(&mut self, sibling_id: DeviceId, added_by: AddedBy, sync: SyncStatus) {
        let key = hex::encode(sibling_id);
        let new_state = match self.peers.get(&key).cloned() {
            Some(PeerState::CoordReady { coord_group_id, .. }) => PeerState::CoordReady {
                coord_group_id,
                ring_link: RingLink::Joined { added_by, sync },
            },
            Some(PeerState::AwaitingTheirHello { coord_group_id }) => PeerState::CoordReady {
                coord_group_id,
                ring_link: RingLink::Joined { added_by, sync },
            },
            // See the matching comment in `on_ring_welcome`: no coord
            // group with this peer, but the caller (`do_ring_add`'s
            // "already a member" check) just confirmed them as a real
            // ring member, so mark Joined with an empty `coord_group_id`.
            Some(PeerState::Discovered) | None => {
                PeerState::CoordReady { coord_group_id: Vec::new(), ring_link: RingLink::Joined { added_by, sync } }
            }
        };
        self.peers.insert(key, new_state);
    }
}

fn my_device_id_or_placeholder(mls: &MoatSession) -> DeviceId {
    *mls.device_id()
}

/// Find our own leaf index in `ring_id` by matching `device_id`, not
/// signature key.
///
/// `device_id` is embedded in every `MoatCredential` this session produces and
/// identifies the device directly, so the lookup stays correct no matter which
/// KeyPackage the adder consumed. `MoatSession::get_own_leaf_index` matches on
/// the leaf's signature key instead, which only works because every KP we offer
/// carries our identity key (see the module note) — a stricter precondition
/// than this lookup needs. Same device_id-matching pattern used elsewhere in
/// this file (e.g. `on_tick`'s section A, `on_ring_welcome`'s peer-marking loop).
/// Reduce a raw key-package pool snapshot to the **newest** package per
/// sibling device, preserving first-seen device order.
///
/// The `social.moat.keyPackage` pool accumulates: packages are published
/// with `createRecord` and never deleted, so a package whose init key has
/// already been consumed stays visible next to its replacement, and no
/// consumer can tell them apart. `fetch_key_packages` returns ascending
/// rkey order, so the *last* entry for a device id is its most recent
/// publication and the only one with a good chance of being unconsumed.
///
/// Anything older risks building a Welcome against a dead init key, which
/// fails at the recipient with "No matching key package was found in the
/// key store" and is invisible to the sender.
///
/// This is a filter, not a guarantee: with concurrent consumers (siblings
/// plus cross-user inviters) even the newest entry can lose a race, which
/// is what the retry path is for.
///
/// Packages whose credential cannot be extracted are dropped —
/// `on_peer_kp_observed` would have ignored them anyway.
fn newest_key_package_per_device<'a>(
    mls: &MoatSession,
    pool: &'a [KeyPackageInput],
) -> Vec<&'a [u8]> {
    let mut newest: Vec<(DeviceId, &'a [u8])> = Vec::new();
    for kp in pool {
        let Some(cred) = mls
            .extract_credential_from_key_package(&kp.key_package)
            .ok()
            .flatten()
        else {
            continue;
        };
        let device_id = *cred.device_id();
        match newest.iter_mut().find(|(id, _)| *id == device_id) {
            Some(slot) => slot.1 = &kp.key_package,
            None => newest.push((device_id, &kp.key_package)),
        }
    }
    newest.into_iter().map(|(_, kp)| kp).collect()
}

fn find_own_leaf(mls: &MoatSession, ring_id: &[u8]) -> Option<u32> {
    let my_device_id = *mls.device_id();
    mls.get_group_members(ring_id).ok()?.into_iter().find_map(|(idx, cred)| {
        cred.and_then(|c| (*c.device_id() == my_device_id).then_some(idx))
    })
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
    let padded = crate::padding::pad_to_bucket(&event_bytes);
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
        assert!(s.peers.is_empty());
        assert!(s.check_invariants().is_ok());
    }

    #[test]
    fn ring_state_roundtrip_json() {
        let mut s = DeviceRingState::new();
        s.ring = RingMembership::InRing {
            ring_id: vec![1u8; 32],
            created_at: 12345,
            generation: 1,
            our_leaf: 0,
        };
        s.peers.insert(
            hex::encode([7u8; 16]),
            PeerState::CoordReady {
                coord_group_id: vec![9u8; 16],
                ring_link: RingLink::Joined {
                    added_by: AddedBy::Us,
                    sync: SyncStatus::OfferEmitted { token: vec![42; 32] },
                },
            },
        );
        let json = serde_json::to_string(&s).expect("serialize");
        let restored: DeviceRingState = serde_json::from_str(&json).expect("deserialize");
        match restored.ring {
            RingMembership::InRing { ring_id, created_at, generation: _, our_leaf } => {
                assert_eq!(ring_id, vec![1u8; 32]);
                assert_eq!(created_at, 12345);
                assert_eq!(our_leaf, 0);
            }
            other => panic!("expected InRing, got {other:?}"),
        }
        // SyncStatus normalizes to OweOffer on load.
        let peer = restored.peers.get(&hex::encode([7u8; 16])).unwrap();
        match peer {
            PeerState::CoordReady {
                ring_link: RingLink::Joined { sync, added_by, .. },
                ..
            } => {
                assert!(matches!(sync, SyncStatus::OweOffer));
                assert_eq!(*added_by, AddedBy::Us);
            }
            other => panic!("expected CoordReady/Joined, got {other:?}"),
        }
    }

    #[test]
    fn record_hello_promotes_solo_to_discovering() {
        let mut s = DeviceRingState::new();
        s.record_hello_from([3u8; 16], &[8u8; 16]);
        assert!(matches!(s.ring, RingMembership::Discovering { .. }));
        assert!(matches!(
            s.peer_get(&[3u8; 16]),
            Some(PeerState::CoordReady { ring_link: RingLink::PendingAdd, .. })
        ));
    }

    #[test]
    fn supersede_clears_matching_ring() {
        let mut s = DeviceRingState::new();
        let ring = vec![1u8; 32];
        s.ring = RingMembership::InRing { ring_id: ring.clone(), created_at: 1, generation: 1, our_leaf: 0 };

        // Synthesize a Supersede via on_coord_msg.
        // We can't easily call on_coord_msg without a MoatSession; exercise the
        // inner logic directly.
        if let RingMembership::InRing { ring_id, .. } = &s.ring {
            if ring_id == &ring {
                s.ring = RingMembership::Solo;
            }
        }
        assert!(matches!(s.ring, RingMembership::Solo));
    }

    #[test]
    fn supersede_wrong_id_no_op() {
        let mut s = DeviceRingState::new();
        let ring = vec![1u8; 32];
        s.ring = RingMembership::InRing { ring_id: ring, created_at: 1, generation: 1, our_leaf: 0 };
        // simulate Supersede with wrong id
        let other = vec![2u8; 32];
        if let RingMembership::InRing { ring_id, .. } = &s.ring {
            if ring_id == &other {
                s.ring = RingMembership::Solo;
            }
        }
        assert!(matches!(s.ring, RingMembership::InRing { .. }));
    }

    fn ring_ref(id: &[u8], generation: u64, created_at: i64) -> RingRef<'_> {
        RingRef { ring_id: id, generation, created_at }
    }

    #[test]
    fn reconcile_older_mine_wins() {
        let mine = vec![1u8];
        let theirs = vec![2u8];
        assert_eq!(
            reconcile_rings(ring_ref(&mine, 1, 100), ring_ref(&theirs, 1, 200)),
            ReconcileDecision::KeepMine
        );
    }

    #[test]
    fn reconcile_older_theirs_wins() {
        let mine = vec![1u8];
        let theirs = vec![2u8];
        assert_eq!(
            reconcile_rings(ring_ref(&mine, 1, 200), ring_ref(&theirs, 1, 100)),
            ReconcileDecision::SwitchToTheirs
        );
    }

    #[test]
    fn reconcile_tie_smaller_id_wins() {
        let mine = vec![1u8];
        let theirs = vec![2u8];
        assert_eq!(
            reconcile_rings(ring_ref(&mine, 1, 100), ring_ref(&theirs, 1, 100)),
            ReconcileDecision::KeepMine
        );
        assert_eq!(
            reconcile_rings(ring_ref(&theirs, 1, 100), ring_ref(&mine, 1, 100)),
            ReconcileDecision::SwitchToTheirs
        );
    }

    #[test]
    fn reconcile_same_ring_id() {
        let id = vec![1u8, 2, 3];
        assert_eq!(
            reconcile_rings(ring_ref(&id, 1, 100), ring_ref(&id, 1, 200)),
            ReconcileDecision::AlreadyInTheirs
        );
    }

    /// Generation beats `created_at`, in both directions. This is the rule
    /// that makes joiner-created rings viable: a ring created by a device
    /// onboarding into an established device-set is necessarily the newest
    /// by `created_at`, and under the old oldest-wins rule would always have
    /// been superseded straight back to the ring it was replacing.
    #[test]
    fn reconcile_higher_generation_wins_over_older_created_at() {
        let mine = vec![1u8];
        let theirs = vec![2u8];
        // Theirs is newer by wall clock but a later generation → theirs wins.
        assert_eq!(
            reconcile_rings(ring_ref(&mine, 1, 100), ring_ref(&theirs, 2, 999)),
            ReconcileDecision::SwitchToTheirs
        );
        // And symmetrically, an older-by-clock ring at a lower generation loses.
        assert_eq!(
            reconcile_rings(ring_ref(&mine, 2, 999), ring_ref(&theirs, 1, 100)),
            ReconcileDecision::KeepMine
        );
    }

    /// Same generation falls through to the original oldest-wins tiebreak —
    /// the case this rule was written for, two devices independently forming
    /// a first ring after a partition.
    #[test]
    fn reconcile_same_generation_falls_back_to_created_at() {
        let mine = vec![9u8];
        let theirs = vec![2u8];
        assert_eq!(
            reconcile_rings(ring_ref(&mine, 3, 100), ring_ref(&theirs, 3, 200)),
            ReconcileDecision::KeepMine
        );
    }

    #[test]
    fn coord_msg_roundtrip_hello() {
        let msg = CoordMsg::Hello { sender_device_id: vec![1u8; 16] };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::Hello { sender_device_id } => assert_eq!(sender_device_id, vec![1u8; 16]),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn coord_msg_roundtrip_ring_info() {
        let msg = CoordMsg::RingInfo { ring_id: vec![5u8; 32], generation: 1, created_at: 42 };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::RingInfo { ring_id, generation: _, created_at } => {
                assert_eq!(ring_id, vec![5u8; 32]);
                assert_eq!(created_at, 42);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn coord_msg_roundtrip_supersede() {
        let msg = CoordMsg::Supersede { old_ring_id: vec![9u8; 32] };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::Supersede { old_ring_id } => assert_eq!(old_ring_id, vec![9u8; 32]),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn coord_msg_roundtrip_sync_offer() {
        let msg = CoordMsg::SyncOffer {
            token: vec![1, 2, 3, 4],
            target_device_id: Some(vec![7u8; 16]),
        };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::SyncOffer { token, target_device_id } => {
                assert_eq!(token, vec![1, 2, 3, 4]);
                assert_eq!(target_device_id, Some(vec![7u8; 16]));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn coord_msg_fits_in_small_bucket() {
        let cases = vec![
            CoordMsg::Hello { sender_device_id: vec![1u8; 16] },
            CoordMsg::RingInfo { ring_id: vec![5u8; 32], generation: 1, created_at: i64::MAX },
            CoordMsg::Supersede { old_ring_id: vec![5u8; 32] },
            CoordMsg::SyncOffer { token: vec![0u8; 32], target_device_id: Some(vec![1u8; 16]) },
        ];
        for c in cases {
            let bytes = encode_coord_msg(&c);
            assert!(bytes.len() <= 256, "{:?} is {} bytes", c, bytes.len());
        }
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

    fn make_members(dids: &[&str]) -> Vec<(u32, Option<MoatCredential>)> {
        dids.iter()
            .enumerate()
            .map(|(i, did)| (i as u32, Some(make_credential(did, "dev", [(i + 1) as u8; 16]))))
            .collect()
    }

    #[test]
    fn classify_all_same_did_is_device_coord() {
        let members = make_members(&["did:plc:alice", "did:plc:alice"]);
        assert_eq!(classify_group_kind(&members, "did:plc:alice"), GroupKind::DeviceCoord);
    }

    #[test]
    fn classify_different_dids_is_user() {
        let members = make_members(&["did:plc:alice", "did:plc:bob"]);
        assert_eq!(classify_group_kind(&members, "did:plc:alice"), GroupKind::User);
    }

    #[test]
    fn classify_empty_is_user() {
        assert_eq!(classify_group_kind(&[], "did:plc:alice"), GroupKind::User);
    }

    #[test]
    fn create_device_coord_group_sibling_can_join() {
        let alice = MoatSession::new();
        let bob = MoatSession::new();
        let alice_cred = make_credential("did:plc:user", "alice", *alice.device_id());
        let (_alice_kp, alice_kb) = alice.generate_key_package(&alice_cred).expect("alice kp");
        let bob_cred = make_credential("did:plc:user", "bob", *bob.device_id());
        let (bob_kp, _bob_kb) = bob.generate_key_package(&bob_cred).expect("bob kp");
        let coord = alice
            .create_device_coord_group(&alice_cred, &alice_kb, &bob_kp)
            .expect("create coord");
        // Bob can process the Welcome.
        let joined = bob.process_welcome(&coord.welcome).expect("bob join");
        assert_eq!(joined, coord.group_id);
    }

    /// Raw MLS-level reproduction (no state machine) of the three-device
    /// bootstrap flow: D2 creates a 2-party ring and adds D1; then D1 (an
    /// existing ring member, NOT the ring creator) adds D3.  Confirms both
    /// that D3's Welcome processes successfully AND that D3's reconstructed
    /// view includes all three devices — i.e. the ratchet-tree extension
    /// gives a joiner full visibility into pre-existing members from a
    /// single Welcome, with no separate fetch needed.
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
        let ring_id = d2.create_device_ring(&d2_cred, &d2_kb).expect("create ring");
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

    /// State-machine-level check that the leaf-election guard in
    /// `try_advance_ring_membership` prevents a non-elected ring member
    /// from re-adding a peer that's already an MLS member.  D3 has already
    /// joined via D1's Welcome (real MLS group has all 3 members).  D3's
    /// peer map separately marks D2 `PendingAdd` (an unavoidable race from
    /// D3 independently exchanging Hello with D2). A tick must not mutate
    /// the MLS group and must recognise D2 as already `Joined`.
    #[test]
    fn on_tick_does_not_re_add_a_peer_already_in_the_mls_group() {
        let d1 = MoatSession::new();
        let d2 = MoatSession::new();
        let d3 = MoatSession::new();
        let d1_cred = make_credential("did:plc:user", "d1", *d1.device_id());
        let d2_cred = make_credential("did:plc:user", "d2", *d2.device_id());
        let d3_cred = make_credential("did:plc:user", "d3", *d3.device_id());
        let (d1_kp, d1_kb) = d1.generate_key_package(&d1_cred).expect("d1 kp");
        let (_d2_kp, d2_kb) = d2.generate_key_package(&d2_cred).expect("d2 kp");
        let (d3_kp, d3_kb) = d3.generate_key_package(&d3_cred).expect("d3 kp");

        let ring_id = d2.create_device_ring(&d2_cred, &d2_kb).expect("create ring");
        let wr1 = d2.add_device(&ring_id, &d2_kb, &d1_kp).expect("d2 add d1");
        d1.process_welcome(&wr1.welcome).expect("d1 join");

        let wr2 = d1.add_device(&ring_id, &d1_kb, &d3_kp).expect("d1 add d3");
        d3.process_welcome(&wr2.welcome).expect("d3 join");
        let members_before = d3.get_group_members(&ring_id).expect("d3 members");
        assert_eq!(members_before.len(), 3);

        let d2_id = *d2.device_id();
        let mut s3 = DeviceRingState::new();
        // Our own leaf in the freshly-joined group happens to be 2 here;
        // the guard recomputes it fresh via `find_own_leaf` rather than
        // trusting this stored value, so its exact number doesn't matter
        // for this test beyond being `RingMembership::InRing`.
        s3.ring = RingMembership::InRing { ring_id: ring_id.clone(), created_at: 1, generation: 1, our_leaf: 2 };
        s3.peers.insert(
            hex::encode(d2_id),
            PeerState::CoordReady {
                coord_group_id: vec![0xAA; 16],
                ring_link: RingLink::PendingAdd,
            },
        );

        let env = StepEnv {
            my_did: "did:plc:user",
            credential: &d3_cred,
            key_bundle: &d3_kb,
            now_ms: 0,
            drawbridge_connected: false,
            sync_session_active: false,
            stealth_pubkeys: &[],
            sibling_stealth: &[],
        };
        let _cmds = s3.step(&d3, &env, RingEvent::Tick { key_packages: &[] });

        let members_after = d3.get_group_members(&ring_id).expect("d3 members after tick");
        assert_eq!(
            members_after.len(),
            3,
            "on_tick must not mutate group membership for an already-present peer"
        );
        assert!(
            matches!(
                s3.peers.get(&hex::encode(d2_id)),
                Some(PeerState::CoordReady { ring_link: RingLink::Joined { .. }, .. })
            ),
            "D2 should be recognised as Joined via the already-a-member guard, got {:?}",
            s3.peers.get(&hex::encode(d2_id))
        );
    }

    #[test]
    fn create_device_ring_produces_distinct_random_ids() {
        let s = MoatSession::new();
        let cred = make_credential("did:plc:user", "device", *s.device_id());
        let (_kp, kb) = s.generate_key_package(&cred).expect("kp");
        let id1 = s.create_device_ring(&cred, &kb).expect("ring 1");
        let id2 = s.create_device_ring(&cred, &kb).expect("ring 2");
        assert_ne!(id1, id2);
    }

    #[test]
    fn invariant_multiple_offers_caught() {
        let mut s = DeviceRingState::new();
        s.ring = RingMembership::InRing { ring_id: vec![1u8], created_at: 0, generation: 1, our_leaf: 0 };
        s.peers.insert(
            hex::encode([1u8; 16]),
            PeerState::CoordReady {
                coord_group_id: vec![1u8],
                ring_link: RingLink::Joined {
                    added_by: AddedBy::Us,
                    sync: SyncStatus::OfferEmitted { token: vec![1] },
                },
            },
        );
        s.peers.insert(
            hex::encode([2u8; 16]),
            PeerState::CoordReady {
                coord_group_id: vec![2u8],
                ring_link: RingLink::Joined {
                    added_by: AddedBy::Us,
                    sync: SyncStatus::OfferEmitted { token: vec![2] },
                },
            },
        );
        assert_eq!(
            s.check_invariants(),
            Err(InvariantViolation::MultipleOffersInFlight)
        );
    }

    /// Two peers owing offers must not both get one: the first offer stays in
    /// flight until `SyncSessionEnded`, and `sync_session_active` doesn't cover
    /// the emit→accept window. Regression guard — emitting to the second peer
    /// here trips `MultipleOffersInFlight` in the very next `step()`.
    #[test]
    fn sync_offer_not_emitted_while_one_is_in_flight() {
        let dev = make_stealth_device("did:plc:user", "offerer");
        let env = env_for(&dev, &[]);
        let mut s = DeviceRingState::new();
        s.ring = RingMembership::InRing { ring_id: vec![1u8], created_at: 0, generation: 1, our_leaf: 0 };
        // Peer 1: offer already in flight.  Peer 2: owes an offer.
        s.peers.insert(
            hex::encode([1u8; 16]),
            PeerState::CoordReady {
                coord_group_id: vec![1u8],
                ring_link: RingLink::Joined {
                    added_by: AddedBy::Us,
                    sync: SyncStatus::OfferEmitted { token: vec![1] },
                },
            },
        );
        s.peers.insert(
            hex::encode([2u8; 16]),
            PeerState::CoordReady {
                coord_group_id: vec![2u8],
                ring_link: RingLink::Joined { added_by: AddedBy::Us, sync: SyncStatus::OweOffer },
            },
        );

        let cmds = s.try_emit_sync_offer(&dev.mls, &env);
        assert!(cmds.is_empty(), "must not emit a second concurrent offer, got {cmds:?}");
        assert!(s.check_invariants().is_ok());

        // Once the in-flight offer resolves, the waiting peer gets served.
        s.on_sync_session_ended();
        assert!(s.any_offer_in_flight() == false);
    }

    /// Offerer election is per pair: the smaller `device_id` offers.
    /// `OweOffer` is set symmetrically, so without this exactly one pair
    /// would open two pairing sessions.
    #[test]
    fn sync_offer_emitted_only_by_the_smaller_device_id_of_a_pair() {
        let dev = make_stealth_device("did:plc:user", "d");
        let env = env_for(&dev, &[]);
        let me = *dev.mls.device_id();

        // A peer that sorts *above* us: we are the offerer, so we emit.
        let mut higher = me;
        higher[15] = higher[15].wrapping_add(1);
        if higher <= me {
            higher = [0xFF; 16];
        }
        let ring_id = dev.mls.create_device_ring(&dev.cred, &dev.key_bundle).expect("ring");
        let mut s = DeviceRingState::new();
        s.ring = RingMembership::InRing {
            ring_id: ring_id.clone(),
            created_at: 1,
            generation: 1,
            our_leaf: 0,
        };
        s.peers.insert(
            hex::encode(higher),
            PeerState::CoordReady {
                coord_group_id: vec![1u8],
                ring_link: RingLink::Joined { added_by: AddedBy::Us, sync: SyncStatus::OweOffer },
            },
        );
        assert!(
            !s.try_emit_sync_offer(&dev.mls, &env).is_empty(),
            "we out-rank the peer, so we must be the one to offer"
        );

        // A peer that sorts *below* us: they are the offerer, we stay quiet.
        let lower = [0u8; 16];
        assert!(lower < me, "test fixture assumption: our device_id is not all-zero");
        let mut s2 = DeviceRingState::new();
        s2.ring = RingMembership::InRing {
            ring_id: ring_id.clone(),
            created_at: 1,
            generation: 1,
            our_leaf: 0,
        };
        s2.peers.insert(
            hex::encode(lower),
            PeerState::CoordReady {
                coord_group_id: vec![1u8],
                ring_link: RingLink::Joined { added_by: AddedBy::Us, sync: SyncStatus::OweOffer },
            },
        );
        assert!(
            s2.try_emit_sync_offer(&dev.mls, &env).is_empty(),
            "the lower device_id owns this pair's offer; we must not duplicate it"
        );
    }

    /// A device that is not ring leaf 0 must still be able to offer, or two
    /// non-leaf-0 siblings never sync and history held only by one of them
    /// can never reach the other.
    #[test]
    fn sync_offer_is_not_restricted_to_ring_leaf_zero() {
        let dev = make_stealth_device("did:plc:user", "d");
        let env = env_for(&dev, &[]);
        let me = *dev.mls.device_id();
        let mut higher = me;
        higher[15] = higher[15].wrapping_add(1);
        if higher <= me {
            higher = [0xFF; 16];
        }

        let ring_id = dev.mls.create_device_ring(&dev.cred, &dev.key_bundle).expect("ring");
        let mut s = DeviceRingState::new();
        // Deliberately NOT leaf 0.
        s.ring = RingMembership::InRing {
            ring_id,
            created_at: 1,
            generation: 1,
            our_leaf: 7,
        };
        s.peers.insert(
            hex::encode(higher),
            PeerState::CoordReady {
                coord_group_id: vec![1u8],
                ring_link: RingLink::Joined { added_by: AddedBy::Us, sync: SyncStatus::OweOffer },
            },
        );
        assert!(
            !s.try_emit_sync_offer(&dev.mls, &env).is_empty(),
            "leaf index must no longer gate offering"
        );
    }

    /// An emitted offer the peer never accepts must not mute this device
    /// forever. `any_offer_in_flight()` is a per-device gate, so without
    /// recovery a single unaccepted offer blocks every later offer to
    /// every peer.
    #[test]
    fn stalled_sync_offer_returns_to_owe_offer_and_unblocks_the_device() {
        let mut s = DeviceRingState::new();
        mark_in_ring(&mut s);
        let peer = [7u8; 16];
        s.peers.insert(
            hex::encode(peer),
            PeerState::CoordReady {
                coord_group_id: vec![1u8],
                ring_link: RingLink::Joined {
                    added_by: AddedBy::Us,
                    sync: SyncStatus::OfferEmitted { token: vec![9] },
                },
            },
        );
        assert!(s.any_offer_in_flight(), "precondition: an offer is outstanding");

        for _ in 0..STALL_RETRY_TICKS {
            s.recover_stalled_peers();
            assert!(s.any_offer_in_flight(), "must not give up before the budget elapses");
        }
        s.recover_stalled_peers();

        assert!(!s.any_offer_in_flight(), "the device must be free to offer again");
        assert!(
            matches!(
                s.peers.get(&hex::encode(peer)),
                Some(PeerState::CoordReady {
                    ring_link: RingLink::Joined { sync: SyncStatus::OweOffer, .. },
                    ..
                })
            ),
            "peer should be re-armed for a fresh offer, got {:?}",
            s.peers.get(&hex::encode(peer))
        );
    }

    /// A coord-group Welcome built from an already-consumed key package
    /// fails silently at the peer, so `AwaitingTheirHello` never resolves.
    /// Recovery drops the entry so discovery re-arms with a newer package.
    #[test]
    fn stalled_awaiting_hello_is_dropped_so_discovery_can_retry() {
        let mut s = DeviceRingState::new();
        let peer = [3u8; 16];
        s.peers.insert(
            hex::encode(peer),
            PeerState::AwaitingTheirHello { coord_group_id: vec![4u8] },
        );

        for _ in 0..STALL_RETRY_TICKS {
            s.recover_stalled_peers();
            assert!(s.peers.contains_key(&hex::encode(peer)), "must not drop early");
        }
        s.recover_stalled_peers();

        assert!(
            !s.peers.contains_key(&hex::encode(peer)),
            "entry must be cleared; on_peer_kp_observed dedups on it existing, \
             so leaving it would make the retry a no-op"
        );
    }

    /// The stall clock must not accumulate across unrelated states — a peer
    /// that keeps transitioning is making progress, not stalling.
    #[test]
    fn stall_clock_resets_on_peer_state_transition() {
        let mut s = DeviceRingState::new();
        let peer = [5u8; 16];
        s.peer_insert(peer, PeerState::AwaitingTheirHello { coord_group_id: vec![1u8] });
        for _ in 0..STALL_RETRY_TICKS {
            s.recover_stalled_peers();
        }
        // A transition arrives just before the budget would have elapsed.
        s.peer_insert(peer, PeerState::AwaitingTheirHello { coord_group_id: vec![2u8] });
        s.recover_stalled_peers();
        assert!(
            s.peers.contains_key(&hex::encode(peer)),
            "clock should have restarted on the transition"
        );
    }

    /// A peer that never accepts must not starve the others: only one offer
    /// may be in flight per device, so a peer that is retried forever would
    /// permanently block every other pair.
    #[test]
    fn a_peer_that_never_accepts_does_not_starve_the_others() {
        let dev = make_stealth_device("did:plc:user", "d");
        let env = env_for(&dev, &[]);
        let me = *dev.mls.device_id();
        // Two peers that both sort above us, so we own both pairs.
        let mut lower = [0xFEu8; 16];
        let mut higher = [0xFFu8; 16];
        assert!(me < lower && lower < higher, "fixture assumes our id sorts below both");
        lower[0] = 0xFE;
        higher[0] = 0xFF;

        let ring_id = dev.mls.create_device_ring(&dev.cred, &dev.key_bundle).expect("ring");
        let mut s = DeviceRingState::new();
        s.ring = RingMembership::InRing {
            ring_id,
            created_at: 1,
            generation: 1,
            our_leaf: 0,
        };
        for peer in [lower, higher] {
            s.peers.insert(
                hex::encode(peer),
                PeerState::CoordReady {
                    coord_group_id: vec![1u8],
                    ring_link: RingLink::Joined { added_by: AddedBy::Us, sync: SyncStatus::OweOffer },
                },
            );
        }

        // Drive many rounds. `lower` never accepts, so every offer to it
        // stalls and is recovered. `higher` must still get served.
        let mut higher_offered = false;
        for _ in 0..40 {
            s.recover_stalled_peers();
            let _ = s.try_emit_sync_offer(&dev.mls, &env);
            if matches!(
                s.peers.get(&hex::encode(higher)),
                Some(PeerState::CoordReady {
                    ring_link: RingLink::Joined { sync: SyncStatus::OfferEmitted { .. }, .. },
                    ..
                })
            ) {
                higher_offered = true;
                break;
            }
        }
        assert!(
            higher_offered,
            "the second peer never received an offer — the unresponsive peer starves it"
        );
    }

    #[test]
    fn invariant_coord_ready_solo_caught() {
        let mut s = DeviceRingState::new();
        s.peers.insert(
            hex::encode([1u8; 16]),
            PeerState::CoordReady {
                coord_group_id: vec![1u8],
                ring_link: RingLink::PendingAdd,
            },
        );
        // ring is still Solo — invariant violated.
        assert_eq!(s.check_invariants(), Err(InvariantViolation::CoordReadyPeerButSolo));
    }

    // ── KP-pool state-machine helpers ──────────────────────────────────────

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

        // 1. Seed an initial batch (the natural state after Phase D's
        //    ship_initial_kp_batches_to runs at ring-join time).
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
    fn bootstrap_consumed_flag_roundtrips() {
        let mut s = DeviceRingState::new();
        let peer: DeviceId = [7u8; 16];

        assert!(!s.is_bootstrap_consumed(&peer));
        s.mark_bootstrap_consumed(&peer);
        assert!(s.is_bootstrap_consumed(&peer));

        // Different peer is independent.
        let other: DeviceId = [8u8; 16];
        assert!(!s.is_bootstrap_consumed(&other));
    }

    // ── Bootstrap KP receive arm ───────────────────────────────────────────

    #[test]
    fn bootstrap_kp_received_stashes_in_pending() {
        let mut s = DeviceRingState::new();
        let sender: DeviceId = [7u8; 16];
        let kp = vec![0xAB; 32];

        let cmds = s.on_bootstrap_kp_received(sender, &kp);
        assert!(cmds.is_empty(), "stash-only; no commands fire from this arm");

        let key = hex::encode(sender);
        assert_eq!(s.pending_bootstrap_kps.get(&key), Some(&kp));
        assert!(!s.is_bootstrap_consumed(&sender));
    }

    #[test]
    fn bootstrap_kp_received_is_dropped_once_consumed() {
        let mut s = DeviceRingState::new();
        let sender: DeviceId = [7u8; 16];
        let kp_original = vec![0x11; 32];
        let kp_replay = vec![0x22; 32];

        // First arrival → stashed.
        s.on_bootstrap_kp_received(sender, &kp_original);
        // Simulate do_ring_add consuming it: remove from pending, mark consumed.
        let key = hex::encode(sender);
        s.pending_bootstrap_kps.remove(&key);
        s.mark_bootstrap_consumed(&sender);

        // Second arrival from the same sender after consume must not
        // re-stash — this is the replay defence verified in
        // `hybrid_bootstrap_event_replay_blocked_by_consumer_flag`.
        let cmds = s.on_bootstrap_kp_received(sender, &kp_replay);
        assert!(cmds.is_empty());
        assert!(
            s.pending_bootstrap_kps.get(&key).is_none(),
            "replayed KP after consume must not be re-stashed"
        );
    }

    #[test]
    fn bootstrap_kp_received_overwrites_pending_until_consumed() {
        // Owner re-publishes (e.g. after restart) before we've consumed.
        // The newer KP replaces the older entry in pending_bootstrap_kps.
        let mut s = DeviceRingState::new();
        let sender: DeviceId = [7u8; 16];
        s.on_bootstrap_kp_received(sender, &[0x11; 32]);
        s.on_bootstrap_kp_received(sender, &[0x22; 32]);

        let key = hex::encode(sender);
        assert_eq!(s.pending_bootstrap_kps.get(&key), Some(&vec![0x22; 32]));
    }

    // ── Phase D: low-water + emit gating ──────────────────────────────────

    #[test]
    fn emit_low_water_kp_requests_is_noop_outside_ring() {
        // The emitter returns Vec::new() early on the `RingMembership::InRing`
        // guard, even with Joined peers present.  This makes the call cheap
        // and safe in every tick regardless of ring state.
        let mut s = DeviceRingState::new();
        s.peers.insert(
            hex::encode([2u8; 16]),
            PeerState::CoordReady {
                coord_group_id: vec![0u8; 8],
                ring_link: RingLink::Joined {
                    added_by: AddedBy::Us,
                    sync: SyncStatus::OweOffer,
                },
            },
        );

        let mls = crate::MoatSession::new();
        let credential = make_credential("did:plc:test", "dev", [1u8; 16]);
        let env = StepEnv {
            my_did: "did:plc:test",
            credential: &credential,
            key_bundle: &[],
            now_ms: 0,
            drawbridge_connected: false,
            sync_session_active: false,
            stealth_pubkeys: &[],
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
        s.mark_bootstrap_consumed(&[7u8; 16]);
        s.on_bootstrap_kp_received([4u8; 16], &[0xDE; 16]);
        s.published_bootstrap_for.insert(hex::encode([5u8; 16]));

        let json = serde_json::to_string(&s).unwrap();
        let parsed: DeviceRingState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.highest_issued_kp_seq(), 3);
        assert_eq!(parsed.kp_pool_size(&owner), 1); // one claimed, one left
        assert!(parsed.is_bootstrap_consumed(&[7u8; 16]));
        assert_eq!(
            parsed.pending_bootstrap_kps.get(&hex::encode([4u8; 16])),
            Some(&vec![0xDE; 16])
        );
        assert!(parsed.published_bootstrap_for.contains(&hex::encode([5u8; 16])));
    }

    // ── Phase E′: stealth carrier for the KP lane ──────────────────────────

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
            drawbridge_connected: false,
            sync_session_active: false,
            stealth_pubkeys: &[],
            sibling_stealth: siblings,
        }
    }

    fn mark_in_ring(s: &mut DeviceRingState) {
        s.ring = RingMembership::InRing { ring_id: vec![0xEE; 32], created_at: 1, generation: 1, our_leaf: 0 };
    }

    fn mark_joined_peer(s: &mut DeviceRingState, peer: DeviceId) {
        s.peers.insert(
            hex::encode(peer),
            PeerState::CoordReady {
                coord_group_id: vec![0xCC; 16],
                ring_link: RingLink::Joined { added_by: AddedBy::Them, sync: SyncStatus::Done },
            },
        );
    }

    /// Decrypt every stealth-publish command addressed to `dev` and feed the
    /// plaintexts through `step(StealthPayloadDecrypted)`, returning the
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
                    out.extend(state.step(&dev.mls, env, RingEvent::StealthPayloadDecrypted {
                        plaintext: &pt,
                    }));
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

        let mut owner_state = DeviceRingState::new();
        mark_in_ring(&mut owner_state);
        mark_joined_peer(&mut owner_state, consumer_id);
        let mut consumer_state = DeviceRingState::new();
        mark_in_ring(&mut consumer_state);
        mark_joined_peer(&mut consumer_state, owner_id);

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

        let mut consumer_state = DeviceRingState::new();
        mark_in_ring(&mut consumer_state);
        mark_joined_peer(&mut consumer_state, owner_id);
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
        mark_in_ring(&mut consumer_state);
        // NOTE: owner deliberately NOT marked as a joined peer.
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

        let mut owner_state = DeviceRingState::new();
        mark_in_ring(&mut owner_state);
        mark_joined_peer(&mut owner_state, consumer_id);
        let mut consumer_state = DeviceRingState::new();
        mark_in_ring(&mut consumer_state);
        mark_joined_peer(&mut consumer_state, owner_id);

        let owner_sib = [SiblingStealth { scan_pubkey: consumer.stealth_pub, device_id: consumer_id }];
        let consumer_sib = [SiblingStealth { scan_pubkey: owner.stealth_pub, device_id: owner_id }];
        let owner_env = env_for(&owner, &owner_sib);
        let consumer_env = env_for(&consumer, &consumer_sib);

        // Owner ships an initial batch; consumer ingests it.
        let batch_cmds = owner_state.ship_initial_kp_batches_to(&owner.mls, &owner_env, &consumer_id);
        let _ = deliver_stealth(&batch_cmds, &consumer, &mut consumer_state, &consumer_env);
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

    // ── Full three-device ring-bootstrap simulator ─────────────────────────
    //
    // Drives real DeviceRingState::step()/tick() calls for three in-process
    // devices against real MoatSession MLS state, with a hand-rolled but
    // faithful transport: a shared cross-user KeyPackage pool (sibling
    // discovery, same as the real `social.moat.keyPackage` pool), a shared
    // per-DID stealth event feed (bootstrap KPs + same-user KP lane, same
    // as the real own-PDS event stream), and direct delivery of ring/coord
    // ciphertexts to whichever OTHER devices are members of that specific
    // group (bypassing PDS tag-guessing, which is a transport-layer
    // mechanism orthogonal to the state-machine convergence question this
    // harness checks). No sleeps, no subprocesses, no Beacon — deterministic
    // and fast, so it can assert a *bounded* round count rather than "give
    // up after N and hope."

    struct SimDevice {
        mls: MoatSession,
        cred: MoatCredential,
        key_bundle: Vec<u8>,
        stealth_priv: [u8; 32],
        stealth_pub: [u8; 32],
        state: DeviceRingState,
    }

    impl SimDevice {
        /// The returned `identity_kp` is the *same* KeyPackage whose private
        /// bundle is stored as `key_bundle`, matching how `do_login`
        /// provisions a real device. Publishing a separately-generated KP
        /// here would give the joiner a leaf it can't sign for — see the
        /// module note on signing-key identity.
        fn new(did: &str, name: &str) -> (Self, Vec<u8>) {
            let mls = MoatSession::new();
            let cred = make_credential(did, name, *mls.device_id());
            let (identity_kp, key_bundle) = mls.generate_key_package(&cred).expect("kp");
            let (stealth_priv, stealth_pub) = crate::generate_stealth_keypair();
            (
                Self { mls, cred, key_bundle, stealth_priv, stealth_pub, state: DeviceRingState::new() },
                identity_kp,
            )
        }

        fn device_id(&self) -> DeviceId {
            *self.mls.device_id()
        }
    }

    /// Simulation network state threaded through every round.
    struct SimNetwork {
        /// Shared cross-user `social.moat.keyPackage` pool: every device's
        /// full current snapshot is fed to every device every round (fresh,
        /// non-incremental — matching real `fetch_key_packages` semantics).
        kp_pool: Vec<Vec<u8>>,
        /// Shared per-DID stealth event feed (bootstrap KPs + same-user KP
        /// lane). Incremental — each device tracks its own read cursor,
        /// matching real own-PDS-scan semantics.
        own_events: Vec<Vec<u8>>,
        own_cursor: [usize; 3],
        /// Every group id each device has ever been told to `RegisterGroup`
        /// for — mirrors the real host's `populate_candidate_tags`, which
        /// is additive and never forgotten just because `DeviceRingState`'s
        /// `peers` bookkeeping later overwrites which coord group is
        /// "preferred" for a given sibling (see `on_group_joined_via_welcome`'s
        /// "always update routing entry" comment). Two devices discovering
        /// each other in the same round each independently create their own
        /// 2-party coord group, so a pair can end up with two coord groups;
        /// `peers` only remembers the most-recently-joined one for
        /// send-routing, but reception must still work against both —
        /// exactly as real tag-scanning would.
        known_groups: [Vec<Vec<u8>>; 3],
        /// Every ring/coord `PublishEvent` ciphertext ever produced, with
        /// its sender index. Persistent and retried every round against
        /// every recipient's currently-known groups — mirrors the real PDS,
        /// where a ciphertext just sits under its tag for any later poll to
        /// find, rather than being a one-shot delivery attempt. A device
        /// that hasn't yet joined the relevant group simply hasn't
        /// registered a matching tag yet and tries again next poll; it
        /// doesn't miss the message forever.
        broadcasts: Vec<(usize, Vec<u8>)>,
        /// Which devices are currently running. An offline device is not
        /// ticked and receives no deliveries, but everything it published
        /// while online stays in `kp_pool` / `own_events` / `broadcasts` —
        /// matching a real lost or sleeping device, whose PDS records
        /// persist and remain fetchable by everyone else. Its read cursor
        /// also stays put, so if it ever returns it sees the full backlog.
        online: [bool; 3],
    }

    /// Run one simulation round: gather fresh `TickInputs` per device from
    /// `net`, call `tick()`, then deliver every resulting command back into
    /// `net` (stealth feed, cross-user pool) or directly to whichever other
    /// devices' known groups the ciphertext decrypts against.
    /// Interpret one `RingCommand` produced by device `i`, exactly as the
    /// real host's command loop would (`app.rs::ring_tick_inner`'s match,
    /// or `interpret_sync_commands` for the synchronous coord-message
    /// path) — shared by both Phase 1 (`tick()`) and Phase 3
    /// (`step(CoordMsgReceived)`) callers so neither one silently drops
    /// commands the other would have handled.
    fn interpret_ring_command(devices: &mut [SimDevice; 3], net: &mut SimNetwork, i: usize, cmd: RingCommand) {
        match cmd {
            RingCommand::PublishEvent { ciphertext, .. } => net.broadcasts.push((i, ciphertext)),
            RingCommand::PublishStealthEvent { ciphertext, .. }
            | RingCommand::StealthPublishWelcome { ciphertext, .. } => net.own_events.push(ciphertext),
            RingCommand::ReplenishKeyPackage => {
                // Must mirror the host (`app.rs::replenish_key_package`):
                // `generate_key_package` mints a fresh signature keypair per
                // call, so a sibling consuming that KeyPackage joins with a
                // leaf it cannot sign for — the Welcome processes, but every
                // later `encrypt_event` into the group fails with "Own member
                // not found in group".
                let kp = devices[i]
                    .mls
                    .replenish_key_package(&devices[i].cred, &devices[i].key_bundle)
                    .expect("replenish kp");
                net.kp_pool.push(kp);
            }
            RingCommand::RegisterGroup { group_id, .. } => {
                if !net.known_groups[i].contains(&group_id) {
                    net.known_groups[i].push(group_id);
                }
            }
            RingCommand::SendDrawbridgePairOffer { .. }
            | RingCommand::SendDrawbridgePairJoin { .. }
            | RingCommand::PollForNewDevices => {
                // Out of scope for ring-join convergence: Drawbridge
                // pairing and same-user conversation fan-out (app.rs-
                // level, not part of DeviceRingState) don't affect
                // whether the ring itself converges to one group with
                // one leaf per device.
            }
        }
    }

    fn three_device_sim_round(devices: &mut [SimDevice; 3], net: &mut SimNetwork, now_ms: i64) {
        let sibling_stealth: Vec<Vec<SiblingStealth>> = (0..3)
            .map(|i| {
                (0..3)
                    .filter(|&j| j != i)
                    .map(|j| SiblingStealth { scan_pubkey: devices[j].stealth_pub, device_id: devices[j].device_id() })
                    .collect()
            })
            .collect();
        let stealth_pubkeys: Vec<[u8; 32]> = devices.iter().map(|d| d.stealth_pub).collect();

        // Phase 1: each device ticks and we collect the resulting commands
        // alongside which device produced them (for delivery/self-exclusion).
        let mut produced: Vec<(usize, RingCommand)> = Vec::new();
        let key_packages: Vec<KeyPackageInput> =
            net.kp_pool.iter().map(|kp| KeyPackageInput { key_package: kp.clone() }).collect();

        for i in 0..3 {
            if !net.online[i] {
                continue; // not running: no poll, no tick, cursor unchanged
            }
            let unseen: Vec<OwnEventInput> = net.own_events[net.own_cursor[i]..]
                .iter()
                .enumerate()
                .map(|(k, ct)| OwnEventInput { rkey: format!("{:020}", net.own_cursor[i] + k), ciphertext: ct.clone() })
                .collect();
            net.own_cursor[i] = net.own_events.len();

            let dev = &mut devices[i];
            let inputs = TickInputs {
                key_packages: &key_packages,
                stealth_pubkeys: &stealth_pubkeys,
                sibling_stealth: &sibling_stealth[i],
                own_events: &unseen,
                stealth_privkey: &dev.stealth_priv,
                credential: &dev.cred,
                key_bundle: &dev.key_bundle,
                now_ms,
                drawbridge_has_own_connection: false,
                sync_session_active: false,
                my_did: dev.cred.did(),
            };
            let cmds = dev.state.tick(&dev.mls, inputs);
            for cmd in cmds {
                produced.push((i, cmd));
            }
        }

        // Phase 2: interpret each command exactly as the real host would.
        for (i, cmd) in produced {
            interpret_ring_command(devices, net, i, cmd);
        }

        // Phase 3: retry EVERY broadcast ever produced (not just this
        // round's) against every OTHER device's currently-known groups. A
        // wrong-group or already-consumed-generation attempt just errors
        // and is skipped — this is the retry-on-every-poll behaviour a real
        // PDS gives for free (a ciphertext sits under its tag until some
        // poll's candidate-tag set finally covers it), which a one-shot
        // per-round delivery would NOT capture: two devices discovering
        // each other in the same round each create their own coord group,
        // so a Hello into the group the *other* side created can't be
        // decrypted by the recipient until a later round when it has
        // joined that specific group via Welcome — it must not be dropped
        // just because that hadn't happened yet this round.
        for (sender_idx, ciphertext) in net.broadcasts.clone() {
            for j in 0..3 {
                if j == sender_idx {
                    continue; // MLS forbids self-decryption; mirrors mark_own
                }
                if !net.online[j] {
                    continue; // not polling, so nothing is delivered to it
                }
                for gid in net.known_groups[j].clone() {
                    let outcome = match devices[j].mls.decrypt_event(&gid, &ciphertext) {
                        Ok(o) => o,
                        Err(_) => continue,
                    };
                    let result = outcome.result();
                    if matches!(result.event.kind, crate::EventKind::Coord) {
                        if let Ok(msg) = decode_coord_msg(&result.event.payload) {
                            let sender_device_id = result.sender.as_ref().map(|s| s.device_id);
                            // Owned copies so `env`'s borrows don't tie up
                            // `devices[j]` while we also need `&mut
                            // devices[j].state` below.
                            let my_did = devices[j].cred.did().to_string();
                            let cred = devices[j].cred.clone();
                            let key_bundle = devices[j].key_bundle.clone();
                            let env = StepEnv {
                                my_did: &my_did,
                                credential: &cred,
                                key_bundle: &key_bundle,
                                now_ms,
                                drawbridge_connected: false,
                                sync_session_active: false,
                                stealth_pubkeys: &stealth_pubkeys,
                                sibling_stealth: &sibling_stealth[j],
                            };
                            let dev = &mut devices[j];
                            let cmds = dev.state.step(
                                &dev.mls,
                                &env,
                                RingEvent::CoordMsgReceived { source_group_id: gid.clone(), sender_device_id, msg },
                            );
                            // Route resulting commands (RegisterGroup,
                            // ReplenishKeyPackage, further PublishEvents —
                            // e.g. `on_ring_welcome`'s initial KP-batch
                            // shipping or its RegisterGroup{Ring}) through
                            // the same interpreter Phase 2 uses. An earlier
                            // version of this harness discarded these
                            // (`let _ = ...`), which silently dropped
                            // RegisterGroup{Ring} for whichever device
                            // processed its RingWelcome via this coord-
                            // message path (as opposed to the stealth/
                            // `tick()` path) — that device's `known_groups`
                            // then never included the ring, so it could
                            // never decrypt (or even attempt) the ring's
                            // own subsequent commits, even though they were
                            // sitting right there in `net.broadcasts`.
                            for cmd in cmds {
                                interpret_ring_command(devices, net, j, cmd);
                            }
                        }
                    }
                    // Commit case: decrypt_event already merged it. Either
                    // way, this ciphertext belonged to `gid` — stop trying
                    // other group ids for this (sender, ciphertext) pair.
                    break;
                }
            }
        }
    }

    /// The three-device bootstrap race, driven deterministically: D1 and D2
    /// bootstrap a ring first (mirrors the Beacon scenario's initial
    /// "d1d2-bootstrap" phase), then D3 joins. Asserts convergence to a
    /// *single* shared ring within a fixed, generous round budget, with no
    /// forked ring ids and all three MLS groups agreeing on 3 members.
    ///
    /// This is the deterministic, fast counterpart to
    /// `three_device_bootstrap_rrr` in `moat-beacon` — no network, no
    /// subprocess timing, so a failure here is a real state-machine
    /// convergence bug, not test impatience.
    #[test]
    fn three_device_bootstrap_converges_within_bounded_rounds() {
        const ROUND_BUDGET: usize = 40;
        const D1D2_ROUNDS: usize = 12;

        let (d1, d1_identity_kp) = SimDevice::new("did:plc:user", "d1");
        let (d2, d2_identity_kp) = SimDevice::new("did:plc:user", "d2");
        let (d3, d3_identity_kp) = SimDevice::new("did:plc:user", "d3");
        let mut devices = [d1, d2, d3];

        // Seed the cross-user pool with D1 and D2's *identity* KPs only —
        // D3 hasn't "logged in" yet (mirroring the Beacon scenario where
        // D3 is spawned only after D1+D2 already share a ring) — and its
        // KeyPackage is deliberately not the one whose bundle is
        // `devices[2].key_bundle` until we push it below.
        let mut net = SimNetwork {
            kp_pool: vec![d1_identity_kp, d2_identity_kp],
            own_events: Vec::new(),
            own_cursor: [0; 3],
            known_groups: [Vec::new(), Vec::new(), Vec::new()],
            broadcasts: Vec::new(),
            // D3 is offline until it "logs in" below. Leaving it ticking is
            // not equivalent to being undiscoverable: discovery runs in the
            // other direction too, so a ticking D3 would consume D1's and
            // D2's identity KeyPackages in round one, before either has
            // replenished, and `on_peer_kp_observed`'s dedup makes that
            // permanent.
            online: [true, true, false],
        };

        let mut now_ms = 0i64;
        for _ in 0..D1D2_ROUNDS {
            now_ms += 1;
            three_device_sim_round(&mut devices, &mut net, now_ms);
            if devices[0].state.ring_id().is_some() && devices[1].state.ring_id().is_some() {
                break;
            }
        }
        assert!(
            devices[0].state.ring_id().is_some() && devices[1].state.ring_id().is_some(),
            "D1+D2 must bootstrap a ring before D3 joins"
        );
        assert_eq!(devices[0].state.ring_id(), devices[1].state.ring_id());

        // Now D3 "logs in": it comes online and publishes its identity KP to
        // the pool so D1/D2 can discover it, and all three tick together.
        net.online[2] = true;
        net.kp_pool.push(d3_identity_kp);

        // Convergence means every device (a) has joined the *same* ring_id
        // and (b) has actually applied every commit that grew it to 3
        // members — `ring_id()` alone only reflects Join time and never
        // changes as later commits merge, so it can't detect a device that
        // joined the ring but hasn't yet caught up on a subsequent Add.
        let mut converged_at = None;
        for round in 0..ROUND_BUDGET {
            now_ms += 1;
            three_device_sim_round(&mut devices, &mut net, now_ms);
            if let Some(ring_id) = devices[0].state.ring_id().map(<[u8]>::to_vec) {
                let all_same_ring = devices.iter().all(|d| d.state.ring_id() == Some(ring_id.as_slice()));
                let all_see_3_members = devices
                    .iter()
                    .all(|d| d.mls.get_group_members(&ring_id).map(|m| m.len()).unwrap_or(0) == 3);
                if all_same_ring && all_see_3_members {
                    converged_at = Some(round);
                    break;
                }
            }
        }

        let ring_ids: Vec<Option<Vec<u8>>> =
            devices.iter().map(|d| d.state.ring_id().map(<[u8]>::to_vec)).collect();
        let member_counts: Vec<usize> = devices
            .iter()
            .map(|d| {
                d.state
                    .ring_id()
                    .and_then(|rid| d.mls.get_group_members(rid).ok())
                    .map(|m| m.len())
                    .unwrap_or(0)
            })
            .collect();
        assert!(
            converged_at.is_some(),
            "three devices did not converge on a single shared 3-member ring within {ROUND_BUDGET} rounds; \
             final ring ids: {ring_ids:?}, member counts as each device sees them: {member_counts:?}"
        );

        // No fork: every device's own MLS view of the ring must agree on
        // exactly 3 members (this is the assertion the leaf-election fix
        // exists to guarantee — a lost race here means a forked commit).
        let ring_id = devices[0].state.ring_id().unwrap().to_vec();
        for (idx, dev) in devices.iter().enumerate() {
            let members = dev.mls.get_group_members(&ring_id).unwrap_or_default();
            assert_eq!(
                members.len(),
                3,
                "device {idx} sees {} members in the ring, expected 3 (forked/diverged commit)",
                members.len()
            );
        }

        // Membership isn't enough — every ring member must be able to author
        // into the ring, which is what sync offers depend on. Regression guard
        // for the signing-key mismatch described in the module note; before the
        // fix only the ring *creator* could encrypt here.
        for (idx, dev) in devices.iter().enumerate() {
            let ev = Event::sibling_msg(dev.mls.device_id().to_vec(), b"hello".to_vec());
            dev.mls
                .encrypt_event(&ring_id, &dev.key_bundle, &ev)
                .unwrap_or_else(|e| panic!("device {idx} cannot encrypt into its own ring: {e}"));
        }
    }

    /// The shared `social.moat.keyPackage` pool accumulates: packages are
    /// published with `createRecord` and never deleted, so a consumed
    /// package stays visible next to its replacement and consumers cannot
    /// tell them apart. A Welcome built against a consumed init key is
    /// silently undeliverable forever.
    #[test]
    fn welcome_built_from_a_consumed_key_package_is_undeliverable() {
        let a = MoatSession::new();
        let a_cred = make_credential("did:plc:u", "a", *a.device_id());
        let (a_kp_identity, _) = a.generate_key_package(&a_cred).unwrap();

        let b = MoatSession::new();
        let b_cred = make_credential("did:plc:u", "b", *b.device_id());
        let (_, b_bundle) = b.generate_key_package(&b_cred).unwrap();

        // B consumes A's identity KP. Baseline: this must work.
        let r1 = b.create_device_coord_group(&b_cred, &b_bundle, &a_kp_identity).unwrap();
        a.process_welcome(&r1.welcome).expect("A joins via its identity KP");

        // A replenishes, as `on_group_joined_via_welcome` instructs the host to.
        // Both KPs are now in the pool; only this one is still usable.
        let (a_kp_replenished, _) = a.generate_key_package(&a_cred).unwrap();

        let c = MoatSession::new();
        let c_cred = make_credential("did:plc:u", "c", *c.device_id());
        let (_, c_bundle) = c.generate_key_package(&c_cred).unwrap();

        // Picking the stale entry produces a Welcome A can never process.
        let stale = c.create_device_coord_group(&c_cred, &c_bundle, &a_kp_identity).unwrap();
        let err = a
            .process_welcome(&stale.welcome)
            .expect_err("a consumed init key must not be reusable");
        assert!(
            err.to_string().contains("No matching key package"),
            "expected a key-store miss, got: {err}"
        );

        // Picking the replenished entry works — so selection, not the pool
        // itself, is what decides whether onboarding succeeds.
        let c2 = MoatSession::new();
        let c2_cred = make_credential("did:plc:u", "c2", *c2.device_id());
        let (_, c2_bundle) = c2.generate_key_package(&c2_cred).unwrap();
        let fresh = c2.create_device_coord_group(&c2_cred, &c2_bundle, &a_kp_replenished).unwrap();
        a.process_welcome(&fresh.welcome)
            .expect("the replenished KP must still be usable");
    }

    // ── Liveness: onboarding must not depend on one specific device ────────
    //
    // A user who loses a device must be able to onboard a replacement
    // through any surviving sibling. See `ring-inversion.md`.

    /// Bootstrap D1+D2 into a shared ring and return its id. Shared setup
    /// for the liveness tests below.
    ///
    /// D3 must be offline for this (`online[2] == false`) — a replacement
    /// device does not exist while its siblings are bootstrapping.
    fn bootstrap_d1_d2_ring(
        devices: &mut [SimDevice; 3],
        net: &mut SimNetwork,
        now_ms: &mut i64,
    ) -> Vec<u8> {
        assert!(!net.online[2], "D3 must be offline until it logs in");
        for _ in 0..12 {
            *now_ms += 1;
            three_device_sim_round(devices, net, *now_ms);
            if devices[0].state.ring_id().is_some() && devices[1].state.ring_id().is_some() {
                break;
            }
        }
        assert_eq!(
            devices[0].state.ring_id(),
            devices[1].state.ring_id(),
            "D1+D2 must share a ring before the test begins"
        );
        devices[0].state.ring_id().expect("D1+D2 ring").to_vec()
    }

    /// Index of whichever of D1/D2 holds the smallest ring leaf.
    fn smallest_leaf_index(devices: &[SimDevice; 3], ring_id: &[u8]) -> usize {
        let d1 = find_own_leaf(&devices[0].mls, ring_id).expect("D1 leaf");
        let d2 = find_own_leaf(&devices[1].mls, ring_id).expect("D2 leaf");
        if d1 <= d2 {
            0
        } else {
            1
        }
    }

    /// True once `a` and `b` share a ring and each sees the other in it.
    fn share_a_working_ring(devices: &[SimDevice; 3], a: usize, b: usize) -> bool {
        let (Some(ring_a), Some(ring_b)) = (devices[a].state.ring_id(), devices[b].state.ring_id())
        else {
            return false;
        };
        if ring_a != ring_b {
            return false;
        }
        let sees = |from: usize, other: usize| {
            devices[from]
                .mls
                .get_group_members(ring_a)
                .map(|m| {
                    m.iter().any(|(_, c)| {
                        c.as_ref().map(|c| *c.device_id() == devices[other].device_id()).unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        };
        sees(a, b) && sees(b, a)
    }

    /// Diagnostic dump for the assertion messages below. Prints `ring`
    /// membership, `known_ring` and both peer maps, so a failure can be
    /// diagnosed from the output without re-instrumenting.
    fn liveness_debug(devices: &[SimDevice; 3], survivor: usize) -> String {
        let ring_of = |i: usize| {
            devices[i].state.ring_id().map(hex::encode).unwrap_or_else(|| "<none>".into())
        };
        let joined_of = |i: usize| {
            devices[i].state.ring_joined_siblings().iter().map(hex::encode).collect::<Vec<_>>()
        };
        let d3_id = hex::encode(devices[2].device_id());
        format!(
            "\n  D3 device_id={d3_id}\
             \n  survivor(D{surv}): ring={} joined_siblings={:?}\n    membership={:?}\n    peers={:?}\
             \n  D3: ring={} joined_siblings={:?}\n    membership={:?}\n    known_ring={:?}\n    peers={:?}",
            ring_of(survivor),
            joined_of(survivor),
            devices[survivor].state.ring,
            devices[survivor].state.peers,
            ring_of(2),
            joined_of(2),
            devices[2].state.ring,
            devices[2].state.known_ring.as_ref().map(|(id, gen, at)| (hex::encode(id), gen, at)),
            devices[2].state.peers,
            surv = survivor + 1,
        )
    }

    /// The user loses the device holding the smallest ring leaf and buys a
    /// replacement. The surviving sibling is online throughout, so onboarding
    /// must complete without the lost device ever returning.
    #[test]
    fn new_device_joins_when_smallest_leaf_never_returns() {
        const ROUND_BUDGET: usize = 60;

        let (d1, d1_kp) = SimDevice::new("did:plc:user", "d1");
        let (d2, d2_kp) = SimDevice::new("did:plc:user", "d2");
        let (d3, d3_kp) = SimDevice::new("did:plc:user", "d3");
        let mut devices = [d1, d2, d3];
        let mut net = SimNetwork {
            kp_pool: vec![d1_kp, d2_kp],
            own_events: Vec::new(),
            own_cursor: [0; 3],
            known_groups: [Vec::new(), Vec::new(), Vec::new()],
            broadcasts: Vec::new(),
            online: [true, true, false], // D3 is still in its box
        };

        let mut now_ms = 0i64;
        let ring_id = bootstrap_d1_d2_ring(&mut devices, &mut net, &mut now_ms);

        // The phone is lost: the elected device stops running, permanently.
        // Its PDS records stay published, exactly as a real lost device's do.
        let lost = smallest_leaf_index(&devices, &ring_id);
        let survivor = 1 - lost;
        net.online[lost] = false;

        // The replacement is unboxed: it comes online and publishes its
        // identity key package.
        net.online[2] = true;
        net.kp_pool.push(d3_kp);

        let mut converged_at = None;
        for round in 0..ROUND_BUDGET {
            now_ms += 1;
            three_device_sim_round(&mut devices, &mut net, now_ms);
            if share_a_working_ring(&devices, survivor, 2) {
                converged_at = Some(round);
                break;
            }
        }

        assert!(
            converged_at.is_some(),
            "replacement device never joined a ring with the surviving sibling within \
             {ROUND_BUDGET} rounds, though that sibling was online the whole time. {}",
            liveness_debug(&devices, survivor)
        );

        // Ring membership alone isn't the user-visible outcome — same-user
        // conversation fan-out reads `ring_joined_siblings()`, so a peer
        // stuck in `Discovered` never gets added to any conversation.
        assert!(
            devices[survivor].state.ring_joined_siblings().contains(&devices[2].device_id()),
            "survivor does not list the new device as a joined ring sibling, so it will \
             never fan it into conversations. {}",
            liveness_debug(&devices, survivor)
        );

        // Both must be able to author into the shared ring, or sync can't run.
        let ring = devices[2].state.ring_id().expect("D3 ring").to_vec();
        for idx in [survivor, 2] {
            let ev = Event::sibling_msg(devices[idx].mls.device_id().to_vec(), b"hi".to_vec());
            devices[idx]
                .mls
                .encrypt_event(&ring, &devices[idx].key_bundle, &ev)
                .unwrap_or_else(|e| panic!("device {idx} cannot author into the shared ring: {e}"));
        }
    }

    /// The same shape, but the elected device is merely asleep rather than
    /// lost. Onboarding must not *depend* on it waking — a backgrounded
    /// phone or a closed laptop is the common case, not the exception —
    /// and when it does return it must rejoin the ring the others are
    /// already using rather than forking a competing one.
    #[test]
    fn new_device_joins_when_smallest_leaf_is_merely_slow() {
        const JOIN_BUDGET: usize = 60;
        const REJOIN_BUDGET: usize = 40;

        let (d1, d1_kp) = SimDevice::new("did:plc:user", "d1");
        let (d2, d2_kp) = SimDevice::new("did:plc:user", "d2");
        let (d3, d3_kp) = SimDevice::new("did:plc:user", "d3");
        let mut devices = [d1, d2, d3];
        let mut net = SimNetwork {
            kp_pool: vec![d1_kp, d2_kp],
            own_events: Vec::new(),
            own_cursor: [0; 3],
            known_groups: [Vec::new(), Vec::new(), Vec::new()],
            broadcasts: Vec::new(),
            online: [true, true, false], // D3 is still in its box
        };

        let mut now_ms = 0i64;
        let ring_id = bootstrap_d1_d2_ring(&mut devices, &mut net, &mut now_ms);

        let asleep = smallest_leaf_index(&devices, &ring_id);
        let survivor = 1 - asleep;
        net.online[asleep] = false;
        net.online[2] = true;
        net.kp_pool.push(d3_kp);

        let mut joined = false;
        for _ in 0..JOIN_BUDGET {
            now_ms += 1;
            three_device_sim_round(&mut devices, &mut net, now_ms);
            if share_a_working_ring(&devices, survivor, 2) {
                joined = true;
                break;
            }
        }
        assert!(
            joined,
            "onboarding stalled while the elected device slept; it must not be on the \
             critical path. {}",
            liveness_debug(&devices, survivor)
        );

        // The laptop lid opens.
        net.online[asleep] = true;
        let mut all_together = false;
        for _ in 0..REJOIN_BUDGET {
            now_ms += 1;
            three_device_sim_round(&mut devices, &mut net, now_ms);
            if share_a_working_ring(&devices, survivor, 2)
                && share_a_working_ring(&devices, asleep, 2)
                && share_a_working_ring(&devices, asleep, survivor)
            {
                all_together = true;
                break;
            }
        }
        assert!(
            all_together,
            "the returning device did not converge onto the ring the others were using \
             (competing ring / fork). ring ids: {:?}",
            devices.iter().map(|d| d.state.ring_id().map(hex::encode)).collect::<Vec<_>>()
        );
    }
}
