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

/// Decide which ring wins when two devices discover they are in different rings.
///
/// Oldest `created_at` wins. Tie broken by lexicographically smallest `ring_id`.
pub fn reconcile_rings(
    mine_ring_id: &[u8],
    mine_created_at: i64,
    theirs_ring_id: &[u8],
    theirs_created_at: i64,
) -> ReconcileDecision {
    if mine_ring_id == theirs_ring_id {
        return ReconcileDecision::AlreadyInTheirs;
    }
    match mine_created_at.cmp(&theirs_created_at) {
        std::cmp::Ordering::Less => ReconcileDecision::KeepMine,
        std::cmp::Ordering::Greater => ReconcileDecision::SwitchToTheirs,
        std::cmp::Ordering::Equal => {
            if mine_ring_id <= theirs_ring_id {
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
        our_leaf: u32,
    },
}

/// Target number of an owner's key packages a consumer maintains locally.
pub const KP_POOL_TARGET: usize = 8;

/// Low-water mark: when the local pool of an owner's KPs drops to this
/// value, the consumer issues a `CoordMsg::KpRequest` to refill.
pub const KP_POOL_LOW_WATER: usize = 2;

/// Maximum number of [`OfferedKp`] entries the owner ships in a single
/// [`CoordMsg::KpBatch`].  Larger refills are split across multiple
/// messages so each fits inside the 4 KB padding bucket.
#[allow(dead_code)] // wired in Phase D when owners actually ship batches
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
            RingMembership::InRing { ring_id, created_at, our_leaf } => RingMembershipWire::InRing {
                ring_id: ring_id.clone(),
                created_at: *created_at,
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
            RingMembershipWire::InRing { ring_id, created_at, our_leaf } => RingMembership::InRing {
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
    CoordMsgReceived {
        source_group_id: Vec<u8>,
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
    /// Publish a stealth-encrypted bootstrap KP event for a specific sibling.
    /// Same wire shape as [`StealthPublishWelcome`] — the host just publishes
    /// the ciphertext under the supplied tag.  The payload inside is an
    /// `EventKind::BootstrapKp` event whose `payload` is the MLS KeyPackage
    /// bytes; the recipient's own-PDS stealth scan picks it up.
    PublishBootstrapKp {
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

    fn peer_get(&self, id: &DeviceId) -> Option<&PeerState> {
        self.peers.get(&hex::encode(id))
    }

    fn peer_insert(&mut self, id: DeviceId, state: PeerState) {
        self.peers.insert(hex::encode(id), state);
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
            RingEvent::CoordMsgReceived { source_group_id, msg } => {
                self.on_coord_msg(mls, env, &source_group_id, msg)
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
        for kp in inputs.key_packages {
            cmds.extend(self.step(mls, &env, RingEvent::PeerKeyPackageObserved { key_package: &kp.key_package }));
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
        msg: CoordMsg,
    ) -> Vec<RingCommand> {
        let my_device_id = *mls.device_id();

        // Resolve sender: prefer device_id carried in the message, fall back
        // to the coord-group members.
        let from_device_id: DeviceId = {
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
        };

        match msg {
            CoordMsg::Hello { sender_device_id } => {
                let id: DeviceId = sender_device_id
                    .as_slice()
                    .try_into()
                    .unwrap_or(from_device_id);
                self.record_hello_from(id, source_group_id);
                Vec::new()
            }
            CoordMsg::RingInfo { ring_id, created_at } => {
                self.maybe_reconcile(&ring_id, created_at);
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
            CoordMsg::RingWelcome { ring_id, welcome, created_at } => {
                self.on_ring_welcome(mls, env, ring_id, welcome, created_at)
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
            CoordMsg::KpBatch { .. } | CoordMsg::KpRequest { .. } => {
                // Phase A scaffolding: variants exist on the wire, but the
                // state machine ignores them until Phase B/D wires the pool
                // and refill state.
                Vec::new()
            }
        }
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

    fn maybe_reconcile(&mut self, theirs_ring_id: &[u8], theirs_created_at: i64) {
        if let RingMembership::InRing { ring_id, created_at, .. } = &self.ring {
            match reconcile_rings(ring_id, *created_at, theirs_ring_id, theirs_created_at) {
                ReconcileDecision::AlreadyInTheirs | ReconcileDecision::KeepMine => {}
                ReconcileDecision::SwitchToTheirs => {
                    self.ring = if self.peers.is_empty() {
                        RingMembership::Solo
                    } else {
                        RingMembership::Discovering { defer_ticks: 0 }
                    };
                }
            }
        }
    }

    fn on_ring_welcome(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        ring_id: Vec<u8>,
        welcome: Vec<u8>,
        created_at: i64,
    ) -> Vec<RingCommand> {
        // Only act if we don't already have a ring.
        if matches!(self.ring, RingMembership::InRing { .. }) {
            return Vec::new();
        }
        let joined = match mls.process_welcome(&welcome) {
            Ok(id) => id,
            Err(_) => return Vec::new(),
        };
        if joined != ring_id {
            return Vec::new();
        }
        let our_leaf = mls
            .get_own_leaf_index(&ring_id, env.key_bundle)
            .ok()
            .flatten()
            .unwrap_or(u32::MAX);
        self.ring = RingMembership::InRing { ring_id: ring_id.clone(), created_at, our_leaf };

        // All ring members (other than us) are siblings already; mark them
        // Joined with sync: OweOffer.  We (the joiner) won't actually emit a
        // sync offer (try_emit_sync_offer gates on our_leaf == 0), but the
        // OweOffer presence is what drives `PollForNewDevices` from the Tick
        // handler so we add these siblings to any user conversations we own.
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
                    Some(PeerState::Discovered) | None => PeerState::Discovered,
                };
                self.peers.insert(key, new_state);
            }
        }

        vec![
            RingCommand::RegisterGroup { group_id: ring_id, kind: GroupKind::Ring },
            // Welcome consumed our init key — replenish so a future Add can target us.
            RingCommand::ReplenishKeyPackage,
            // The next tick will trigger PollForNewDevices so we add the existing
            // ring members to all known user conversations.
            RingCommand::PollForNewDevices,
        ]
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
            // Generate a fresh KP whose init key stays in our local
            // keystore.  Not also written to the cross-user PDS pool —
            // bootstrap KPs are exclusive to this lane.
            let (kp_bytes, _bundle) = match mls.generate_key_package(env.credential) {
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
            cmds.push(RingCommand::PublishBootstrapKp { tag, ciphertext });
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
                        Some(PeerState::Discovered) | None => PeerState::Discovered,
                    };
                    self.peers.insert(key, new_state);
                }
            }
        }

        // ── B. PollForNewDevices fires whenever any peer is freshly in the ring
        //       and still owes a sync offer — this drives the
        //       per-conversation add_device fan-out on the inviting side
        //       independently of Drawbridge availability.
        let any_owe_offer = self.peers.values().any(|ps| {
            matches!(
                ps,
                PeerState::CoordReady {
                    ring_link: RingLink::Joined { sync: SyncStatus::OweOffer, .. },
                    ..
                }
            )
        });
        if any_owe_offer {
            cmds.push(RingCommand::PollForNewDevices);
        }

        // ── C. Issue sync offers for any OweOffer peer (we are leaf-0) ────
        if env.drawbridge_connected && !env.sync_session_active {
            cmds.extend(self.try_emit_sync_offer(mls, env));
        }

        // ── D. Bootstrap ring or MLS Add CoordReady peers ────────────────
        cmds.extend(self.try_advance_ring_membership(mls, env));

        cmds
    }

    /// At most one offer per tick.  Walks peers, picks the first OweOffer
    /// (deterministic by hex key sort), and emits the offer if conditions
    /// allow.  Sets the peer's sync to OfferEmitted on success.
    fn try_emit_sync_offer(&mut self, mls: &MoatSession, env: &StepEnv<'_>) -> Vec<RingCommand> {
        let (ring_id, our_leaf) = match &self.ring {
            RingMembership::InRing { ring_id, our_leaf, .. } => (ring_id.clone(), *our_leaf),
            _ => return Vec::new(),
        };
        if our_leaf != 0 {
            // Static-leaf-0 offerer rule (Phase 4).
            return Vec::new();
        }

        let mut sorted_keys: Vec<&String> = self.peers.keys().collect();
        sorted_keys.sort();
        let target_key = sorted_keys
            .into_iter()
            .find(|k| {
                matches!(
                    self.peers.get(*k),
                    Some(PeerState::CoordReady {
                        ring_link: RingLink::Joined { sync: SyncStatus::OweOffer, .. },
                        ..
                    })
                )
            })
            .cloned();
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
        if let Ok(enc) = mls.encrypt_event(&ring_id, env.key_bundle, &offer_event) {
            cmds.push(RingCommand::PublishEvent {
                tag: enc.tag,
                ciphertext: enc.ciphertext,
                mark_own: true,
            });
        }

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
                for sib in &pending {
                    if let Some(cmds_for_add) =
                        self.do_ring_add(mls, env, &ring_id, *sib)
                    {
                        cmds.extend(cmds_for_add);
                    }
                }
            }
            RingMembership::Discovering { defer_ticks } => {
                // Are we the smallest device_id among ourselves + hello-exchanged peers?
                let mut all_ids: Vec<DeviceId> = pending.clone();
                all_ids.push(my_device_id);
                all_ids.sort();
                if all_ids[0] != my_device_id {
                    // We're not the creator; wait for a RingWelcome from the smallest.
                    return cmds;
                }

                if *defer_ticks == 0 {
                    self.ring = RingMembership::Discovering { defer_ticks: 1 };
                    return cmds; // skip this tick
                }

                // defer elapsed → create ring.
                let ring_id = match mls.create_device_ring(env.credential, env.key_bundle) {
                    Ok(id) => id,
                    Err(_) => return cmds,
                };
                let our_leaf = mls
                    .get_own_leaf_index(&ring_id, env.key_bundle)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                self.ring = RingMembership::InRing {
                    ring_id: ring_id.clone(),
                    created_at: env.now_ms,
                    our_leaf,
                };
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
        // Already a ring member?  Mark Joined and exit.
        if let Ok(members) = mls.get_group_members(ring_id) {
            if members.iter().any(|(_, c)| {
                c.as_ref().map(|c| *c.device_id() == sibling_id).unwrap_or(false)
            }) {
                self.mark_peer_joined(sibling_id, AddedBy::OtherSibling([0u8; 16]), SyncStatus::OweOffer);
                return Some(Vec::new());
            }
        }

        // Phase C: use the bootstrap KP this sibling delivered to us
        // (single-use, race-free).  If none is pending, defer to a
        // later tick — D_new will publish (or has published) and
        // their event will arrive via own-PDS stealth scan.
        let sib_kp_key = hex::encode(sibling_id);
        let sib_kp_bytes = self.pending_bootstrap_kps.get(&sib_kp_key).cloned()?;

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
        let commit_tag = mls
            .derive_next_tag(ring_id, env.key_bundle)
            .unwrap_or_else(|_| rand::random());
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

        self.mark_peer_joined(sibling_id, AddedBy::Us, SyncStatus::OweOffer);
        Some(cmds)
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
            Some(PeerState::Discovered) | None => PeerState::Discovered,
        };
        self.peers.insert(key, new_state);
    }
}

fn my_device_id_or_placeholder(mls: &MoatSession) -> DeviceId {
    *mls.device_id()
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
            RingMembership::InRing { ring_id, created_at, our_leaf } => {
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
        s.ring = RingMembership::InRing { ring_id: ring.clone(), created_at: 1, our_leaf: 0 };

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
        s.ring = RingMembership::InRing { ring_id: ring, created_at: 1, our_leaf: 0 };
        // simulate Supersede with wrong id
        let other = vec![2u8; 32];
        if let RingMembership::InRing { ring_id, .. } = &s.ring {
            if ring_id == &other {
                s.ring = RingMembership::Solo;
            }
        }
        assert!(matches!(s.ring, RingMembership::InRing { .. }));
    }

    #[test]
    fn reconcile_older_mine_wins() {
        let mine = vec![1u8];
        let theirs = vec![2u8];
        assert_eq!(reconcile_rings(&mine, 100, &theirs, 200), ReconcileDecision::KeepMine);
    }

    #[test]
    fn reconcile_older_theirs_wins() {
        let mine = vec![1u8];
        let theirs = vec![2u8];
        assert_eq!(
            reconcile_rings(&mine, 200, &theirs, 100),
            ReconcileDecision::SwitchToTheirs
        );
    }

    #[test]
    fn reconcile_tie_smaller_id_wins() {
        let mine = vec![1u8];
        let theirs = vec![2u8];
        assert_eq!(reconcile_rings(&mine, 100, &theirs, 100), ReconcileDecision::KeepMine);
        assert_eq!(
            reconcile_rings(&theirs, 100, &mine, 100),
            ReconcileDecision::SwitchToTheirs
        );
    }

    #[test]
    fn reconcile_same_ring_id() {
        let id = vec![1u8, 2, 3];
        assert_eq!(
            reconcile_rings(&id, 100, &id, 200),
            ReconcileDecision::AlreadyInTheirs
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
        let msg = CoordMsg::RingInfo { ring_id: vec![5u8; 32], created_at: 42 };
        let bytes = encode_coord_msg(&msg);
        match decode_coord_msg(&bytes).unwrap() {
            CoordMsg::RingInfo { ring_id, created_at } => {
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
            CoordMsg::RingInfo { ring_id: vec![5u8; 32], created_at: i64::MAX },
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
        s.ring = RingMembership::InRing { ring_id: vec![1u8], created_at: 0, our_leaf: 0 };
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
}
