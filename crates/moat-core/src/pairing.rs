//! Live pairing (QR / text code) device onboarding.
//!
//! Three pieces:
//!
//! 1. **Codec** — [`PairingPayload`] encode/decode, Crockford base32, the
//!    `moat-pair:` URI wrapper. Pure functions.
//! 2. **Channel crypto** — [`derive_pairing_keys`], [`seal_frame`],
//!    [`open_frame`]. HKDF-SHA256 key derivation + AES-128-GCM frames with a
//!    counter nonce.
//! 3. **[`PairingSession`]** — the Enroll/Admit exchange as a
//!    command-returning driver, mirroring the `DeviceRingState` /
//!    `SyncSession` pattern already used in this crate: MLS operations
//!    happen *inside* the driver (it takes `&MoatSession`), and the emitted
//!    [`PairingCommand`]s cover host IO only (send frame, seed the KP pool,
//!    surface the approval prompt, start sync).
//!
//! The wire types and signatures below are settled; most function bodies
//! are still `todo!()` pending implementation.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::Sha256;

use crate::device_ring::{DeviceId, OfferedKp};
use crate::{Error, MoatCredential, MoatSession, Result};

// ─── Wire payload (the code itself) ─────────────────────────────────────────

/// Payload format version. Bumping this is a breaking wire change — old and
/// new devices would need to agree out of band, so in practice this should
/// never move without a very good reason.
pub const PAIRING_PAYLOAD_VERSION: u8 = 0x01;

/// Length of a pairing token in bytes (Drawbridge rendezvous identifier).
pub const PAIRING_TOKEN_LEN: usize = 16;

/// Length of a pairing secret in bytes (channel key material). May drop to
/// 16 bytes (128-bit) after usability testing of the text code's length;
/// 32 is cryptographically comfortable but not required.
pub const PAIRING_SECRET_LEN: usize = 32;

/// Total encoded payload length: `1 (version) + 16 (token) + 32 (secret)`.
pub const PAIRING_PAYLOAD_LEN: usize = 1 + PAIRING_TOKEN_LEN + PAIRING_SECRET_LEN;

/// URI scheme prefix used for the QR form (`moat-pair:<text-form>`).
pub const PAIRING_URI_SCHEME: &str = "moat-pair:";

/// Crockford base32 alphabet (32 symbols; excludes `I`, `L`, `O`, `U` to
/// avoid visual confusion with `1`, `1`, `0`, `V` on manual entry).
pub const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The decoded contents of a pairing code: enough for the new device to
/// register a Drawbridge rendezvous token and for both sides to derive the
/// channel AEAD keys. Deliberately excludes the DID and relay URL: both
/// devices already know their own DID (equality is verified inside the
/// encrypted channel), and the relay URL is discoverable from the shared
/// DID's PDS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingPayload {
    pub token: [u8; PAIRING_TOKEN_LEN],
    pub secret: [u8; PAIRING_SECRET_LEN],
}

impl PairingPayload {
    /// Encode to the raw 49-byte wire form: `[version][token][secret]`.
    pub fn encode(&self) -> Vec<u8> {
        let _ = (&self.token, &self.secret);
        todo!("moat-core pairing.rs: PairingPayload::encode")
    }

    /// Decode from the raw wire form. Rejects a bad version byte or a
    /// length other than [`PAIRING_PAYLOAD_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let _ = bytes;
        todo!("moat-core pairing.rs: PairingPayload::decode")
    }

    /// Encode to the hyphen-grouped Crockford base32 text form
    /// (`MZXW6-YTBOI-…`), for manual entry / display beneath a QR code.
    pub fn to_text(&self) -> String {
        todo!("moat-core pairing.rs: PairingPayload::to_text")
    }

    /// Decode from the text form. Hyphens and whitespace are ignored;
    /// letters are case-insensitive. Rejects characters outside the
    /// Crockford alphabet and malformed lengths.
    pub fn from_text(s: &str) -> Result<Self> {
        let _ = s;
        todo!("moat-core pairing.rs: PairingPayload::from_text")
    }

    /// Encode to the `moat-pair:<text-form>` URI used for the QR payload, so
    /// the app can register a URI handler and reject foreign QRs cheaply.
    pub fn to_uri(&self) -> String {
        todo!("moat-core pairing.rs: PairingPayload::to_uri")
    }

    /// Decode from the `moat-pair:` URI form. Rejects a missing/foreign
    /// scheme.
    pub fn from_uri(s: &str) -> Result<Self> {
        let _ = s;
        todo!("moat-core pairing.rs: PairingPayload::from_uri")
    }
}

/// Crockford base32 encode of arbitrary bytes (no hyphen grouping, no
/// padding characters). [`PairingPayload::to_text`] groups the result.
pub fn crockford_encode(data: &[u8]) -> String {
    let _ = data;
    todo!("moat-core pairing.rs: crockford_encode")
}

/// Crockford base32 decode. Case-insensitive; ignores `-` and whitespace.
/// Rejects any character outside [`CROCKFORD_ALPHABET`].
pub fn crockford_decode(s: &str) -> Result<Vec<u8>> {
    let _ = s;
    todo!("moat-core pairing.rs: crockford_decode")
}

// ─── Channel crypto ──────────────────────────────────────────────────────────

/// HKDF info string for the new-device → existing-device direction.
pub const PAIRING_HKDF_INFO_N2O: &[u8] = b"moat-pair-v1 n2o";

/// HKDF info string for the existing-device → new-device direction.
pub const PAIRING_HKDF_INFO_O2N: &[u8] = b"moat-pair-v1 o2n";

/// AES-128-GCM key length / nonce length, for clarity at call sites.
pub const PAIRING_FRAME_KEY_LEN: usize = 16;
pub const PAIRING_FRAME_NONCE_LEN: usize = 12;

/// The two directional AEAD keys derived from a pairing secret + token.
///
/// `k_new_to_old` seals frames sent by the new device; `k_old_to_new` seals
/// frames sent by the existing device. Never reused across a nonce space —
/// each direction gets its own counter (see [`PairingSession`]).
#[derive(Clone)]
pub struct PairingChannelKeys {
    pub k_new_to_old: [u8; PAIRING_FRAME_KEY_LEN],
    pub k_old_to_new: [u8; PAIRING_FRAME_KEY_LEN],
}

impl std::fmt::Debug for PairingChannelKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingChannelKeys").finish_non_exhaustive()
    }
}

/// Derive both directional channel keys from the pairing secret and token:
/// `HKDF-SHA256(ikm = secret, salt = token, info = "moat-pair-v1 …")`.
pub fn derive_pairing_keys(
    secret: &[u8; PAIRING_SECRET_LEN],
    token: &[u8; PAIRING_TOKEN_LEN],
) -> PairingChannelKeys {
    let hk = Hkdf::<Sha256>::new(Some(token), secret);

    let mut k_new_to_old = [0u8; PAIRING_FRAME_KEY_LEN];
    hk.expand(PAIRING_HKDF_INFO_N2O, &mut k_new_to_old)
        .expect("16 bytes is a valid output length for HKDF-SHA256");

    let mut k_old_to_new = [0u8; PAIRING_FRAME_KEY_LEN];
    hk.expand(PAIRING_HKDF_INFO_O2N, &mut k_old_to_new)
        .expect("16 bytes is a valid output length for HKDF-SHA256");

    PairingChannelKeys {
        k_new_to_old,
        k_old_to_new,
    }
}

/// Seal a frame with AES-128-GCM under `key`, using `counter` as a monotonic
/// nonce source. Callers must never reuse a counter value under the same key
/// — see [`PairingSession`] for the per-direction counter it maintains.
pub fn seal_frame(key: &[u8; PAIRING_FRAME_KEY_LEN], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let _ = (key, counter, plaintext);
    todo!("moat-core pairing.rs: seal_frame")
}

/// Open a frame sealed by [`seal_frame`]. Returns
/// [`Error::PairingCrypto`] on any decryption failure (wrong key, replayed
/// or reflected counter, corrupted ciphertext) — deliberately
/// undifferentiated, since the only correct recovery either way is to
/// abort the pairing with an explicit error on both screens.
pub fn open_frame(
    key: &[u8; PAIRING_FRAME_KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let _ = (key, counter, ciphertext);
    todo!("moat-core pairing.rs: open_frame")
}

// ─── Session messages ────────────────────────────────────────────────────────

/// Sent by the new device once the pair channel is up.
///
/// `conv_kps` seeds the existing device's `kp_pools` entry for the newcomer
/// directly, so the newcomer doesn't need a separate draw from the shared
/// key-package pool for this one sibling.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enroll {
    pub credential: MoatCredential,
    /// 32-byte X25519 stealth scan public key.
    #[serde_as(as = "Base64")]
    pub stealth_scan_pubkey: [u8; 32],
    /// Fresh MLS KeyPackage for the ring Add. The init private key is held
    /// locally by the new device (never transmitted).
    #[serde_as(as = "Base64")]
    pub ring_kp: Vec<u8>,
    /// Seeded steady-state conversation-KP pool; sequence numbers already
    /// allocated by the new device.
    pub conv_kps: Vec<OfferedKp>,
}

/// One existing sibling's identity + stealth address, handed to the
/// newcomer in [`Admit::roster`] so it can address `SiblingMsg` traffic to
/// every sibling from its first tick.
///
/// Deliberately carries no `did`: a same-user ring's DID is not roster
/// data, it's an MLS-authenticated fact available directly from the ring's
/// member credentials once the `Welcome` is processed (see
/// [`PairingSession::on_frame_received`]'s DID-check note). Adding a
/// redundant, unauthenticated `did` field here would just be a second,
/// weaker copy of that same fact.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiblingInfo {
    #[serde_as(as = "Base64")]
    pub device_id: DeviceId,
    pub device_name: String,
    #[serde_as(as = "Base64")]
    pub stealth_pubkey: [u8; 32],
}

/// Sent by the existing device after the user taps Approve.
///
/// The Welcome rides the channel raw, not a stealth-published PDS event.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admit {
    #[serde_as(as = "Base64")]
    pub ring_id: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub welcome: Vec<u8>,
    pub roster: Vec<SiblingInfo>,
}

/// The three message types exchanged over the pairing AEAD channel.
/// JSON-encoded, then sealed whole by [`seal_frame`] — matching the
/// `SyncMsg` convention already used for the sync wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairingMsg {
    Enroll(Enroll),
    Admit(Admit),
    /// Sent by each side once *its own* Enroll/Admit handling is complete
    /// (new device: after processing `Admit`; existing device: after
    /// sending it) — a channel-teardown courtesy so the peer knows it can
    /// close its end of the pair socket. Deliberately scoped to the pairing
    /// exchange only: `PairingSession::is_done()` reflects local Enroll/Admit
    /// completion and does not wait to receive this frame, and history sync
    /// (`SyncSession`, handed the channel via `PairingCommand::StartSync`)
    /// is a separate, independently-completing concern that this message
    /// does not gate or report on.
    Done,
}

/// Encode a [`PairingMsg`] to raw JSON bytes (pre-AEAD).
pub fn encode_pairing_msg(msg: &PairingMsg) -> Vec<u8> {
    serde_json::to_vec(msg).expect("PairingMsg serialization should never fail")
}

/// Decode a [`PairingMsg`] from raw JSON bytes (post-AEAD).
pub fn decode_pairing_msg(bytes: &[u8]) -> Result<PairingMsg> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::PairingProtocol(format!("PairingMsg decode: {e}")))
}

// ─── Commands (host IO) ──────────────────────────────────────────────────────

/// Side effect requested by [`PairingSession`]. Mirrors `RingCommand`: the
/// host interprets these in terms of its own I/O layer (pair-channel
/// socket, local persistence, UI).
#[derive(Debug, Clone)]
pub enum PairingCommand {
    /// Write an already-AEAD-sealed frame to the pair channel.
    SendFrame { ciphertext: Vec<u8> },
    /// Existing device, on Approve: seed the newcomer's `kp_pools` entry
    /// with the `conv_kps` carried in `Enroll` (via `ingest_kp_batch`).
    SeedKpPool {
        device_id: DeviceId,
        kps: Vec<OfferedKp>,
    },
    /// Existing device, on receiving `Enroll`: show the confirmation
    /// screen naming the new device, gated on a user tap before
    /// [`PairingSession::approve`] is called.
    SurfaceApprovalPrompt { device_name: String, did: String },
    /// New device, on receiving `Admit`: the ring has been joined and
    /// should be persisted by the host under the given id.
    PersistRing { ring_id: Vec<u8> },
    /// Both sides, once Enroll/Admit has completed: hand the open channel
    /// to `SyncSession` for history sync. The pairing AEAD keeps running
    /// underneath for the whole session rather than re-keying to ring MLS.
    StartSync,
    /// Pairing failed (decryption failure, protocol violation, DID
    /// mismatch). Both screens should show "code mismatch — try again" and
    /// the new device should regenerate its code.
    Abort { reason: String },
}

impl PairingCommand {
    /// Short stable name for this command, for host debug logs — mirrors
    /// `RingCommand::kind`.
    pub fn kind(&self) -> &'static str {
        match self {
            PairingCommand::SendFrame { .. } => "send_frame",
            PairingCommand::SeedKpPool { .. } => "seed_kp_pool",
            PairingCommand::SurfaceApprovalPrompt { .. } => "surface_approval_prompt",
            PairingCommand::PersistRing { .. } => "persist_ring",
            PairingCommand::StartSync => "start_sync",
            PairingCommand::Abort { .. } => "abort",
        }
    }
}

/// Render a command list as `name xN, name xM` for a one-line log — mirrors
/// `summarize_ring_commands`.
pub fn summarize_pairing_commands(cmds: &[PairingCommand]) -> String {
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

// ─── PairingSession state machine ────────────────────────────────────────────

/// New-device-side phase.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NewDevicePhase {
    /// Constructed, but `start_enroll` has not been called yet. Any frame
    /// received in this phase is an ordering violation — there is nothing
    /// we could be replying to — and `on_frame_received` must reject it
    /// rather than treat it as an Admit.
    Idle,
    /// Enroll sent; waiting for Admit. Not yet constructed: `start_enroll`'s
    /// body is still `todo!()`, so nothing drives the transition out of
    /// `Idle` yet.
    #[allow(dead_code)]
    AwaitingAdmit,
    /// Reached once Admit has been processed. Not yet constructed: none of
    /// `PairingSession::on_frame_received`'s Admit arm has a real body yet,
    /// so nothing drives the transition into it.
    #[allow(dead_code)]
    Done,
}

/// Existing-device-side phase.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExistingDevicePhase {
    /// Channel is up; waiting for the peer's Enroll.
    AwaitingEnroll,
    /// Enroll received and parsed; waiting for the user to tap Approve
    /// (see [`PairingSession::pending_enroll`] / [`PairingSession::approve`]).
    /// Not yet constructed — see the note on `NewDevicePhase::Done`.
    #[allow(dead_code)]
    AwaitingApproval,
    /// Not yet constructed — see the note on `NewDevicePhase::Done`.
    #[allow(dead_code)]
    Done,
}

/// Which role this session is playing. Both roles live in one type,
/// selected at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    NewDevice(NewDevicePhase),
    ExistingDevice(ExistingDevicePhase),
}

/// The Enroll/Admit exchange as a command-returning driver.
///
/// Mirrors `DeviceRingState`/`SyncSession`: MLS operations (building the
/// ring KeyPackage, creating/joining the ring, seeding the KP pool) happen
/// *inside* the driver, taking `&MoatSession` as a parameter; the emitted
/// [`PairingCommand`]s cover host IO only.
#[derive(Debug)]
pub struct PairingSession {
    phase: Phase,
    /// Not yet read: only `derive_pairing_keys` constructs a value for this,
    /// and it's unimplemented — nothing calls `seal_frame`/`open_frame` yet.
    #[allow(dead_code)]
    keys: PairingChannelKeys,
    /// Monotonic counter for frames *we* send. Never reused — see
    /// [`seal_frame`]. Not yet read — see the note on `keys`.
    #[allow(dead_code)]
    send_counter: u64,
    /// Highest counter successfully opened from the peer. Used to detect
    /// replay/reflection: an incoming frame must strictly increase this.
    /// Not yet read — see the note on `keys`.
    #[allow(dead_code)]
    recv_counter: u64,
    /// Existing-device only: the parsed `Enroll`, once received, held until
    /// the host calls [`PairingSession::approve`].
    pending_enroll: Option<Enroll>,
    /// The ring this session ended up in, once known: for the existing
    /// device, set inside [`approve`](Self::approve) (either the
    /// newly-created ring, or the `existing_ring_id` it was given); for the
    /// new device, set from `Admit.ring_id` inside
    /// [`on_frame_received`](Self::on_frame_received). Exposed via
    /// [`ring_id`](Self::ring_id) so a caller pairing a third device can
    /// thread the second device's ring id into the next `approve()` call
    /// without a side channel.
    ring_id: Option<Vec<u8>>,
}

impl PairingSession {
    /// Construct a session for the new (joining) device.
    pub fn new_device(
        secret: &[u8; PAIRING_SECRET_LEN],
        token: &[u8; PAIRING_TOKEN_LEN],
    ) -> Self {
        Self {
            phase: Phase::NewDevice(NewDevicePhase::Idle),
            keys: derive_pairing_keys(secret, token),
            send_counter: 0,
            recv_counter: 0,
            pending_enroll: None,
            ring_id: None,
        }
    }

    /// Construct a session for the existing (approving) device.
    pub fn existing_device(
        secret: &[u8; PAIRING_SECRET_LEN],
        token: &[u8; PAIRING_TOKEN_LEN],
    ) -> Self {
        Self {
            phase: Phase::ExistingDevice(ExistingDevicePhase::AwaitingEnroll),
            keys: derive_pairing_keys(secret, token),
            send_counter: 0,
            recv_counter: 0,
            pending_enroll: None,
            ring_id: None,
        }
    }

    /// New device: build and seal the `Enroll` frame once the pair channel
    /// reaches `paired`. `mls` mints the fresh ring KeyPackage (via
    /// `replenish_key_package`-style key reuse — see the signing-key
    /// identity note at the top of `device_ring.rs`, which applies here
    /// too). Moves the session from `Idle` to `AwaitingAdmit`; must be
    /// called exactly once, before any frame is fed to
    /// [`on_frame_received`](Self::on_frame_received).
    pub fn start_enroll(
        &mut self,
        mls: &MoatSession,
        credential: &MoatCredential,
        key_bundle: &[u8],
        stealth_scan_pubkey: [u8; 32],
        conv_kps: Vec<OfferedKp>,
    ) -> Vec<PairingCommand> {
        let _ = (mls, credential, key_bundle, stealth_scan_pubkey, conv_kps);
        todo!("moat-core pairing.rs: PairingSession::start_enroll")
    }

    /// Feed a sealed frame received over the pair channel. Opens it under
    /// the peer's directional key with the next expected counter, decodes
    /// the [`PairingMsg`], and dispatches on role + phase. A decryption or
    /// ordering-violation error aborts the session (host still gets a
    /// `PairingCommand::Abort` back via the `Err`, so both screens can show
    /// an explicit error). A frame received while the new-device session is
    /// still `Idle` (i.e. before [`start_enroll`](Self::start_enroll) was
    /// ever called) is one such ordering violation — nothing was sent for
    /// it to be a reply to.
    ///
    /// `own_credential` is this device's own credential — used to check DID
    /// equality against the peer, which is a hard abort on mismatch. The
    /// existing device checks it against an incoming `Enroll`'s
    /// `credential` field directly. The new device has no DID field to
    /// check an `Admit` against up front ([`SiblingInfo`] deliberately
    /// carries no `did` — see its docs) — instead it processes the
    /// `Welcome`, then checks DID equality against the resulting ring's own
    /// MLS member credentials (`MoatSession::get_group_members`, the same
    /// source of truth `DeviceRingState::ring_joined_siblings` uses): every
    /// member of a same-user ring must share one DID by construction, so a
    /// mismatch there means the `Admit` led us into somebody else's ring.
    /// On success, records `Admit.ring_id` so it's available via
    /// [`ring_id`](Self::ring_id).
    pub fn on_frame_received(
        &mut self,
        mls: &MoatSession,
        own_credential: &MoatCredential,
        ciphertext: &[u8],
    ) -> Result<Vec<PairingCommand>> {
        let _ = (mls, own_credential, ciphertext);
        todo!("moat-core pairing.rs: PairingSession::on_frame_received")
    }

    /// Existing device only: the peer's `Enroll`, once received, pending
    /// the user's approval decision. `None` before receipt and after
    /// [`approve`](Self::approve) has consumed it.
    pub fn pending_enroll(&self) -> Option<&Enroll> {
        self.pending_enroll.as_ref()
    }

    /// The ring this session ended up in, once known. `None` until
    /// `approve()` (existing device) or a processed `Admit` (new device) —
    /// see the field doc on `ring_id`.
    pub fn ring_id(&self) -> Option<&[u8]> {
        self.ring_id.as_deref()
    }

    /// Existing device only: called once the user taps Approve on the named
    /// peer. Creates the ring (first pairing) or adds the joiner via
    /// `MoatSession::add_member` (subsequent pairings), seeds the
    /// newcomer's KP pool, and emits the sealed `Admit` frame. Records the
    /// resulting ring id (whether freshly created or passed in) so it's
    /// available via [`ring_id`](Self::ring_id) — a caller pairing a third
    /// device reads it back from the second pairing's session to fill in
    /// this parameter.
    ///
    /// `existing_ring_id` is `None` for a first pairing (no ring exists
    /// yet) and `Some(ring_id)` when adding a joiner to an already-existing
    /// ring.
    pub fn approve(
        &mut self,
        mls: &MoatSession,
        credential: &MoatCredential,
        key_bundle: &[u8],
        existing_ring_id: Option<&[u8]>,
    ) -> Result<Vec<PairingCommand>> {
        let _ = (mls, credential, key_bundle, existing_ring_id);
        todo!("moat-core pairing.rs: PairingSession::approve")
    }

    /// `true` once this session has reached its terminal `Done` phase: the
    /// new device has processed `Admit`, or the existing device has sent
    /// it. This is a local, immediate fact — it does not wait to send or
    /// receive [`PairingMsg::Done`], and it says nothing about whether
    /// history sync has finished. Matches `PairStatus::done` in
    /// moat-beacon's client ("joined the ring" / "admitted the peer").
    pub fn is_done(&self) -> bool {
        matches!(
            self.phase,
            Phase::NewDevice(NewDevicePhase::Done) | Phase::ExistingDevice(ExistingDevicePhase::Done)
        )
    }
}
