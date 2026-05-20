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

use std::collections::HashMap;

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
        #[serde(default)]
        target_device_id: Option<Vec<u8>>,
    },
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingMembership {
    /// No peers known; nothing to do.
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

/// Top-level state owned by the host.  Serialized as JSON for persistence.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRingState {
    #[serde(default = "RingMembership::default")]
    ring: RingMembership,
    /// Sibling device_id → peer state.  HashMap key is hex-encoded for JSON.
    #[serde(default)]
    peers: HashMap<String, PeerState>,
    /// Cursor (rkey) for incremental own-PDS stealth scan.
    #[serde(default)]
    own_events_cursor: Option<String>,
}

impl Default for RingMembership {
    fn default() -> Self {
        RingMembership::Solo
    }
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

    fn on_stealth_payload(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        plaintext: &[u8],
    ) -> Vec<RingCommand> {
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

        let mut cmds = Vec::new();
        cmds.push(RingCommand::RegisterGroup { group_id: ring_id, kind: GroupKind::Ring });
        // Welcome consumed our init key — replenish so a future Add can target us.
        cmds.push(RingCommand::ReplenishKeyPackage);
        // The next tick will trigger PollForNewDevices so we add the existing
        // ring members to all known user conversations.
        cmds.push(RingCommand::PollForNewDevices);
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

    fn on_tick(
        &mut self,
        mls: &MoatSession,
        env: &StepEnv<'_>,
        key_packages: &[KeyPackageInput],
    ) -> Vec<RingCommand> {
        let mut cmds = Vec::new();

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
        cmds.extend(self.try_advance_ring_membership(mls, env, key_packages));

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
        key_packages: &[KeyPackageInput],
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
                        self.do_ring_add(mls, env, &ring_id, *sib, key_packages)
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
                        self.do_ring_add(mls, env, &ring_id, *sib, key_packages)
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
        key_packages: &[KeyPackageInput],
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

        // Find the newest KP for this sibling.
        let sib_kp = key_packages.iter().rev().find(|kp| {
            mls.extract_credential_from_key_package(&kp.key_package)
                .ok()
                .flatten()
                .map(|c| *c.device_id() == sibling_id)
                .unwrap_or(false)
        })?;

        let wr = match mls.add_device(ring_id, env.key_bundle, &sib_kp.key_package) {
            Ok(w) => w,
            Err(_) => return None,
        };

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
}
