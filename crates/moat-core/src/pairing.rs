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

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Key, Nonce,
};
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
        let mut out = Vec::with_capacity(PAIRING_PAYLOAD_LEN);
        out.push(PAIRING_PAYLOAD_VERSION);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&self.secret);
        out
    }

    /// Decode from the raw wire form. Rejects a bad version byte or a
    /// length other than [`PAIRING_PAYLOAD_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PAIRING_PAYLOAD_LEN {
            return Err(Error::PairingProtocol(format!(
                "pairing payload must be {PAIRING_PAYLOAD_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if bytes[0] != PAIRING_PAYLOAD_VERSION {
            return Err(Error::PairingProtocol(format!(
                "unsupported pairing payload version {:#04x}, expected {:#04x}",
                bytes[0], PAIRING_PAYLOAD_VERSION
            )));
        }

        let mut token = [0u8; PAIRING_TOKEN_LEN];
        token.copy_from_slice(&bytes[1..1 + PAIRING_TOKEN_LEN]);
        let mut secret = [0u8; PAIRING_SECRET_LEN];
        secret.copy_from_slice(&bytes[1 + PAIRING_TOKEN_LEN..]);

        Ok(Self { token, secret })
    }

    /// Encode to the hyphen-grouped Crockford base32 text form
    /// (`MZXW6-YTBOI-…`), for manual entry / display beneath a QR code.
    pub fn to_text(&self) -> String {
        crockford_encode(&self.encode())
            .as_bytes()
            .chunks(5)
            .map(|group| std::str::from_utf8(group).expect("crockford output is ASCII"))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Decode from the text form. Hyphens and whitespace are ignored;
    /// letters are case-insensitive. Rejects characters outside the
    /// Crockford alphabet and malformed lengths.
    pub fn from_text(s: &str) -> Result<Self> {
        Self::decode(&crockford_decode(s)?)
    }

    /// Encode to the `moat-pair:<text-form>` URI used for the QR payload, so
    /// the app can register a URI handler and reject foreign QRs cheaply.
    pub fn to_uri(&self) -> String {
        format!("{PAIRING_URI_SCHEME}{}", self.to_text())
    }

    /// Decode from the `moat-pair:` URI form. Rejects a missing/foreign
    /// scheme.
    pub fn from_uri(s: &str) -> Result<Self> {
        let rest = s.strip_prefix(PAIRING_URI_SCHEME).ok_or_else(|| {
            Error::PairingProtocol(format!(
                "pairing uri must start with {PAIRING_URI_SCHEME}, got: {s}"
            ))
        })?;
        Self::from_text(rest)
    }
}

/// Crockford base32 encode of arbitrary bytes (no hyphen grouping, no
/// padding characters). [`PairingPayload::to_text`] groups the result.
pub fn crockford_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = (buffer >> bits_in_buffer) & 0x1F;
            out.push(CROCKFORD_ALPHABET[idx as usize] as char);
        }
    }
    if bits_in_buffer > 0 {
        let idx = (buffer << (5 - bits_in_buffer)) & 0x1F;
        out.push(CROCKFORD_ALPHABET[idx as usize] as char);
    }
    out
}

/// Crockford base32 decode. Case-insensitive; ignores `-` and whitespace.
/// Rejects any character outside [`CROCKFORD_ALPHABET`].
pub fn crockford_decode(s: &str) -> Result<Vec<u8>> {
    fn value(c: char) -> Option<u8> {
        let upper = c.to_ascii_uppercase();
        CROCKFORD_ALPHABET
            .iter()
            .position(|&b| b as char == upper)
            .map(|i| i as u8)
    }

    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;

    for c in s.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let v = value(c)
            .ok_or_else(|| Error::PairingProtocol(format!("invalid pairing code character: {c}")))?;
        buffer = ((buffer << 5) | v as u32) & 0xFFFF;
        bits_in_buffer += 5;
        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            out.push(((buffer >> bits_in_buffer) & 0xFF) as u8);
        }
    }
    Ok(out)
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

/// Build the 12-byte AES-GCM nonce for a frame: 4 zero bytes followed by the
/// 64-bit counter, big-endian. Deterministic in the counter alone (no random
/// component) — reuse across a nonce space is prevented entirely by callers
/// never reusing a counter value under the same key (see [`PairingSession`]).
fn frame_nonce(counter: u64) -> [u8; PAIRING_FRAME_NONCE_LEN] {
    let mut nonce = [0u8; PAIRING_FRAME_NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Seal a frame with AES-128-GCM under `key`, using `counter` as a monotonic
/// nonce source. Callers must never reuse a counter value under the same key
/// — see [`PairingSession`] for the per-direction counter it maintains.
pub fn seal_frame(key: &[u8; PAIRING_FRAME_KEY_LEN], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
    let nonce = frame_nonce(counter);
    cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("AES-128-GCM encryption over a valid key/nonce cannot fail")
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
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
    let nonce = frame_nonce(counter);
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| Error::PairingCrypto("failed to open pairing frame".to_string()))
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Existing device, on Approve (second+ pairing onward): publish the
    /// ring Add commit to the PDS under `tag`, so any *other* sibling not
    /// party to this pairing (asleep, or simply not the approver) can pick
    /// it up on its own next poll and advance its own MLS view — the
    /// mechanism qr-pairing.md §6 describes ("a sibling asleep during a
    /// pairing just processes the ring Add commit from the PDS on its next
    /// poll"). The `Welcome` still rides the pair channel raw (`Admit`);
    /// only the commit needs this second, PDS-borne path, since a bystander
    /// isn't on the pair channel at all. `tag` is derived *before*
    /// `add_member` — the invite-lane-duplication.md §3 rule: deriving it
    /// after would tag the commit at the wrong (post-add) epoch.
    PublishRingCommit { tag: [u8; 16], ciphertext: Vec<u8> },
    /// Existing device, on receiving `Enroll`: show the confirmation
    /// screen naming the new device, gated on a user tap before
    /// [`PairingSession::approve`] is called.
    SurfaceApprovalPrompt { device_name: String, did: String },
    /// New device, on receiving `Admit`: the ring has been joined and
    /// should be persisted by the host under the given id.
    PersistRing { ring_id: Vec<u8> },
    /// New device, on receiving `Admit`: the roster of already-established
    /// siblings, so the host can seed its `sibling_stealth` table and start
    /// addressing `SiblingMsg` traffic to every sibling from its first
    /// tick, without waiting on `stealthAddress`-record discovery.
    RosterReceived { roster: Vec<SiblingInfo> },
    /// Both sides, once Enroll/Admit has completed: hand the open channel
    /// to `SyncSession` for history sync. The pairing AEAD keeps running
    /// underneath for the whole session rather than re-keying to ring MLS.
    StartSync,
}

impl PairingCommand {
    /// Short stable name for this command, for host debug logs — mirrors
    /// `RingCommand::kind`.
    pub fn kind(&self) -> &'static str {
        match self {
            PairingCommand::SendFrame { .. } => "send_frame",
            PairingCommand::SeedKpPool { .. } => "seed_kp_pool",
            PairingCommand::PublishRingCommit { .. } => "publish_ring_commit",
            PairingCommand::SurfaceApprovalPrompt { .. } => "surface_approval_prompt",
            PairingCommand::PersistRing { .. } => "persist_ring",
            PairingCommand::RosterReceived { .. } => "roster_received",
            PairingCommand::StartSync => "start_sync",
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
    /// Enroll sent; waiting for Admit.
    AwaitingAdmit,
    /// Reached once Admit has been processed.
    Done,
}

/// Existing-device-side phase.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExistingDevicePhase {
    /// Channel is up; waiting for the peer's Enroll.
    AwaitingEnroll,
    /// Enroll received and parsed; waiting for the user to tap Approve
    /// (see [`PairingSession::pending_enroll`] / [`PairingSession::approve`]).
    AwaitingApproval,
    /// Admit sent.
    Done,
}

/// Which role this session is playing, or that it has failed. Both roles
/// live in one type, selected at construction; `Failed` is reachable from
/// either role's non-terminal states (see [`PairingSession::fail`]) and,
/// once reached, is never overwritten by a later error (see
/// [`PairingSession::is_terminal`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    NewDevice(NewDevicePhase),
    ExistingDevice(ExistingDevicePhase),
    /// Terminal failure. Retains the reason so a failed pairing is
    /// distinguishable from a slow one.
    Failed { reason: String },
}

/// The two rendered forms of a new device's pairing code.
#[derive(Debug, Clone)]
struct DisplayedCode {
    /// Bare text, for manual entry on the peer.
    text: String,
    /// `moat-pair:` URI, for the QR.
    uri: String,
}

/// Presentation projection of [`PairingSession`]'s state. Every host
/// renders this; none derives its own — see [`PairingSession::ui_state`].
/// Computed fresh on every call, never cached, so it cannot drift from the
/// underlying protocol state.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum PairingUiState {
    /// No pairing in flight. `PairingSession` itself never reports this —
    /// it only ever exists once a pairing has started — so this variant is
    /// for a host wrapping `Option<PairingSession>` to report when that
    /// option is `None`.
    Idle,
    /// New device: code generated, waiting for the peer to enter it. Holds
    /// steady across the whole wait, including after `Enroll` has been
    /// sent (still waiting on `Admit`) — the code stays valid and
    /// displayed for the whole exchange.
    ShowingCode { code: String, uri: String },
    /// Existing device: code accepted, waiting for the peer's `Enroll`.
    AwaitingPeer,
    /// Existing device: `Enroll` received, waiting on the approve/reject
    /// decision.
    AwaitingApproval { device_name: String, did: String },
    /// Enroll/Admit exchange complete. Says nothing about history sync —
    /// that stays observable via the existing `/sync/status`, matching
    /// `PairingMsg::Done`'s settled meaning.
    Done {
        #[serde_as(as = "Base64")]
        ring_id: Vec<u8>,
    },
    /// Terminal failure. Retained on the session rather than thrown away —
    /// so `/pair/status` can report a reason instead of `done: false`
    /// forever with no explanation.
    Failed { reason: String },
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
    /// The two directional channel keys derived at construction.
    keys: PairingChannelKeys,
    /// Monotonic counter for frames *we* send. Never reused — see
    /// [`seal_frame`].
    send_counter: u64,
    /// Highest counter successfully opened from the peer. Used to detect
    /// replay/reflection: an incoming frame must strictly increase this.
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
    /// `None` for an existing-device session, which shows no code.
    displayed_code: Option<DisplayedCode>,
    /// Retained (not just consumed by key derivation) so a host can tell a
    /// `pair_closed` for this session from one for a superseded round.
    rendezvous_token: [u8; PAIRING_TOKEN_LEN],
}

impl PairingSession {
    /// Construct a session for the new (joining) device. `payload` is the
    /// freshly generated token+secret this device will display as a code
    /// (QR and text form) for the peer to scan or type; `ui_state()` reads
    /// [`PairingPayload::to_text`]/[`to_uri`](PairingPayload::to_uri) off it
    /// once here, so hosts don't need a second copy of the code alongside
    /// the session.
    pub fn new_device(payload: &PairingPayload) -> Self {
        Self {
            phase: Phase::NewDevice(NewDevicePhase::Idle),
            keys: derive_pairing_keys(&payload.secret, &payload.token),
            send_counter: 0,
            recv_counter: 0,
            pending_enroll: None,
            ring_id: None,
            displayed_code: Some(DisplayedCode {
                text: payload.to_text(),
                uri: payload.to_uri(),
            }),
            rendezvous_token: payload.token,
        }
    }

    /// Construct a session for the existing (approving) device, from a
    /// code the user scanned or typed.
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
            displayed_code: None,
            rendezvous_token: *token,
        }
    }

    /// `true` once this session has reached a terminal phase (`Done`,
    /// either role, or `Failed`). Guards [`fail`](Self::fail),
    /// [`reject`](Self::reject) and [`cancel`](Self::cancel) so a completed
    /// outcome is never overwritten by a later, spurious call.
    fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            Phase::NewDevice(NewDevicePhase::Done)
                | Phase::ExistingDevice(ExistingDevicePhase::Done)
                | Phase::Failed { .. }
        )
    }

    /// Move to `Failed { reason }` unless already terminal — a stray
    /// failure must not erase a real `Done`, and an existing `Failed` keeps
    /// its original reason.
    fn fail(&mut self, reason: String) {
        if !self.is_terminal() {
            self.phase = Phase::Failed { reason };
        }
    }

    /// Render this session's current state for UI presentation — see
    /// [`PairingUiState`]. Every host renders this; none derives its own.
    pub fn ui_state(&self) -> PairingUiState {
        match &self.phase {
            Phase::NewDevice(NewDevicePhase::Idle) | Phase::NewDevice(NewDevicePhase::AwaitingAdmit) => {
                let code = self
                    .displayed_code
                    .clone()
                    .expect("a new-device session always has a code, set at construction");
                PairingUiState::ShowingCode { code: code.text, uri: code.uri }
            }
            Phase::NewDevice(NewDevicePhase::Done) => PairingUiState::Done {
                ring_id: self
                    .ring_id
                    .clone()
                    .expect("NewDevice(Done) is only reached after Admit.ring_id is recorded"),
            },
            Phase::ExistingDevice(ExistingDevicePhase::AwaitingEnroll) => PairingUiState::AwaitingPeer,
            Phase::ExistingDevice(ExistingDevicePhase::AwaitingApproval) => {
                let enroll = self
                    .pending_enroll
                    .as_ref()
                    .expect("AwaitingApproval implies a pending Enroll");
                PairingUiState::AwaitingApproval {
                    device_name: enroll.credential.device_name().to_string(),
                    did: enroll.credential.did().to_string(),
                }
            }
            Phase::ExistingDevice(ExistingDevicePhase::Done) => PairingUiState::Done {
                ring_id: self
                    .ring_id
                    .clone()
                    .expect("ExistingDevice(Done) is only reached after approve() records ring_id"),
            },
            Phase::Failed { reason } => PairingUiState::Failed {
                reason: reason.clone(),
            },
        }
    }

    /// Existing device only: decline the pending `Enroll`, moving the
    /// session to `Failed` — a hard stop. Errors without changing phase if
    /// there is nothing pending to reject (a terminal session included).
    pub fn reject(&mut self) -> Result<()> {
        if !matches!(
            self.phase,
            Phase::ExistingDevice(ExistingDevicePhase::AwaitingApproval)
        ) {
            return Err(Error::PairingProtocol(
                "reject() called with no pending Enroll to reject".to_string(),
            ));
        }
        self.pending_enroll = None;
        self.phase = Phase::Failed {
            reason: "rejected by user".to_string(),
        };
        Ok(())
    }

    /// Either role: abort an in-flight pairing — e.g. the user backs out of
    /// the show-code screen. Moves the session to `Failed`. Errors without
    /// changing phase if already terminal: there is nothing left to cancel,
    /// and a completed session must keep reporting its real outcome.
    pub fn cancel(&mut self) -> Result<()> {
        if self.is_terminal() {
            return Err(Error::PairingProtocol(
                "cannot cancel a session that has already reached a terminal state".to_string(),
            ));
        }
        self.pending_enroll = None;
        self.phase = Phase::Failed {
            reason: "cancelled".to_string(),
        };
        Ok(())
    }

    /// Seal `plaintext` under this session's own send-direction key at the
    /// next unused counter, advancing `send_counter`. New device sends
    /// under `k_new_to_old`; existing device sends under `k_old_to_new`.
    /// Callers must guard against `Phase::Failed` themselves (every public
    /// entry point that reaches this does) — a `Failed` session has no
    /// send direction left to pick.
    fn seal_and_advance(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let key = match self.phase {
            Phase::NewDevice(_) => &self.keys.k_new_to_old,
            Phase::ExistingDevice(_) => &self.keys.k_old_to_new,
            Phase::Failed { .. } => {
                unreachable!("seal_and_advance callers must guard against a Failed session")
            }
        };
        let ciphertext = seal_frame(key, self.send_counter, plaintext);
        self.send_counter += 1;
        ciphertext
    }

    /// Open `ciphertext` under the peer's send-direction key at the next
    /// expected counter, advancing `recv_counter` only on success — a
    /// failed open (wrong key, replay, tamper) must not desynchronize the
    /// counter from what a legitimate retried frame would need. See
    /// [`seal_and_advance`](Self::seal_and_advance) on the `Failed` guard.
    fn open_and_advance(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = match self.phase {
            Phase::NewDevice(_) => &self.keys.k_old_to_new,
            Phase::ExistingDevice(_) => &self.keys.k_new_to_old,
            Phase::Failed { .. } => {
                unreachable!("open_and_advance callers must guard against a Failed session")
            }
        };
        let plaintext = open_frame(key, self.recv_counter, ciphertext)?;
        self.recv_counter += 1;
        Ok(plaintext)
    }

    /// New device: build and seal the `Enroll` frame once the pair channel
    /// reaches `paired`. `mls` mints the fresh ring KeyPackage (via
    /// `replenish_key_package`-style key reuse — see the signing-key
    /// identity note at the top of `device_ring.rs`, which applies here
    /// too). Moves the session from `Idle` to `AwaitingAdmit`; must be
    /// called exactly once, before any frame is fed to
    /// [`on_frame_received`](Self::on_frame_received). Moves the session to
    /// `Failed` and returns `Err` if minting the KeyPackage fails, or if
    /// called on a session that has already reached a terminal state — a
    /// host-level error, not a panic, since it can legitimately happen
    /// (e.g. corrupt local key state) and callers should be able to
    /// surface it rather than crash.
    pub fn start_enroll(
        &mut self,
        mls: &MoatSession,
        credential: &MoatCredential,
        key_bundle: &[u8],
        stealth_scan_pubkey: [u8; 32],
        conv_kps: Vec<OfferedKp>,
    ) -> Result<Vec<PairingCommand>> {
        if self.is_terminal() {
            let reason = "start_enroll() called on a session that has already reached a terminal state".to_string();
            return Err(Error::PairingProtocol(reason));
        }

        // Reuses the identity signing key, not a throwaway one — see the
        // "Signing-key identity" note at the top of `device_ring.rs`, which
        // this KP is subject to just like the steady-state KP-lane ones.
        let ring_kp = match mls.replenish_key_package(credential, key_bundle) {
            Ok(kp) => kp,
            Err(e) => {
                self.fail(e.to_string());
                return Err(e);
            }
        };

        let enroll = PairingMsg::Enroll(Enroll {
            credential: credential.clone(),
            stealth_scan_pubkey,
            ring_kp,
            conv_kps,
        });
        let ciphertext = self.seal_and_advance(&encode_pairing_msg(&enroll));

        self.phase = Phase::NewDevice(NewDevicePhase::AwaitingAdmit);

        Ok(vec![PairingCommand::SendFrame { ciphertext }])
    }

    /// Feed a sealed frame received over the pair channel. Opens it under
    /// the peer's directional key with the next expected counter, decodes
    /// the [`PairingMsg`], and dispatches on role + phase. A decryption or
    /// ordering-violation error aborts the session — the host gets it via
    /// the plain `Err` return (there is no `Ok`-wrapped abort command; the
    /// error variant itself carries enough for both screens to show an
    /// explicit error). A frame received while the new-device session is
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
    ///
    /// Any `Err` returned by this method — decryption failure, decode
    /// failure, DID mismatch, or an ordering violation — moves the session
    /// to `Failed { reason }` first, so the reason survives for
    /// [`ui_state`](Self::ui_state) / status reporting rather than being
    /// thrown away (unless the session was already terminal, in which case
    /// its existing outcome is preserved — see [`fail`](Self::fail)).
    pub fn on_frame_received(
        &mut self,
        mls: &MoatSession,
        own_credential: &MoatCredential,
        ciphertext: &[u8],
    ) -> Result<Vec<PairingCommand>> {
        let result = self.on_frame_received_impl(mls, own_credential, ciphertext);
        if let Err(ref e) = result {
            self.fail(e.to_string());
        }
        result
    }

    fn on_frame_received_impl(
        &mut self,
        mls: &MoatSession,
        own_credential: &MoatCredential,
        ciphertext: &[u8],
    ) -> Result<Vec<PairingCommand>> {
        if self.is_terminal() {
            return Err(Error::PairingProtocol(
                "on_frame_received() called on a session that has already reached a terminal state"
                    .to_string(),
            ));
        }
        let plaintext = self.open_and_advance(ciphertext)?;
        let msg = decode_pairing_msg(&plaintext)?;
        let phase = self.phase.clone();

        match (phase, msg) {
            (
                Phase::ExistingDevice(ExistingDevicePhase::AwaitingEnroll),
                PairingMsg::Enroll(enroll),
            ) => {
                if enroll.credential.did() != own_credential.did() {
                    return Err(Error::PairingProtocol(format!(
                        "Enroll DID {} does not match this device's own DID {}",
                        enroll.credential.did(),
                        own_credential.did()
                    )));
                }
                let device_name = enroll.credential.device_name().to_string();
                let did = enroll.credential.did().to_string();
                self.pending_enroll = Some(enroll);
                self.phase = Phase::ExistingDevice(ExistingDevicePhase::AwaitingApproval);
                Ok(vec![PairingCommand::SurfaceApprovalPrompt { device_name, did }])
            }
            (Phase::ExistingDevice(ExistingDevicePhase::AwaitingApproval), PairingMsg::Enroll(_)) => {
                Err(Error::PairingProtocol(
                    "a second Enroll arrived while one is already pending approval".to_string(),
                ))
            }
            (Phase::NewDevice(NewDevicePhase::AwaitingAdmit), PairingMsg::Admit(admit)) => {
                let group_id = mls.process_welcome(&admit.welcome)?;

                // No `did` field on `Admit`/`SiblingInfo` to check up front
                // (see `SiblingInfo`'s docs) — the ring's own MLS member
                // credentials, available only now, are the only anchor.
                //
                // Known gap: `process_welcome` above has already joined
                // this foreign group and consumed the init key by the time
                // this check runs and rejects it — there is no cleanup of
                // that local MLS state on this error path (no
                // `MoatSession` primitive to un-join a group exists today).
                // Low severity in practice (it requires the attacker to
                // hold the QR secret in the first place), but worth fixing
                // — and worth a red test for a malicious `Admit`, mirroring
                // the existing Mallory coverage for the Enroll direction —
                // before this path is relied on for anything beyond
                // rejecting the pairing.
                let dids = mls.get_group_dids(&group_id)?;
                if dids.is_empty() || !dids.iter().all(|d| d == own_credential.did()) {
                    return Err(Error::PairingProtocol(
                        "Admit's Welcome landed this device in a ring under a foreign DID"
                            .to_string(),
                    ));
                }

                self.ring_id = Some(group_id.clone());
                self.phase = Phase::NewDevice(NewDevicePhase::Done);
                let done = self.seal_and_advance(&encode_pairing_msg(&PairingMsg::Done));

                Ok(vec![
                    PairingCommand::PersistRing { ring_id: group_id },
                    PairingCommand::RosterReceived { roster: admit.roster },
                    PairingCommand::StartSync,
                    PairingCommand::SendFrame { ciphertext: done },
                ])
            }
            // Teardown courtesy only — `is_done()` never waits on this, and
            // it carries no state of its own to apply.
            (_, PairingMsg::Done) => Ok(vec![]),
            (phase, msg) => Err(Error::PairingProtocol(format!(
                "unexpected {msg:?} received in phase {phase:?}"
            ))),
        }
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

    /// See the field doc on `rendezvous_token`.
    pub fn rendezvous_token(&self) -> &[u8; PAIRING_TOKEN_LEN] {
        &self.rendezvous_token
    }

    /// The two directional AEAD keys this session derived at construction.
    /// Exposed so the host can keep sealing/opening frames under the
    /// pairing AEAD after `is_done()` — qr-pairing.md §3.2's "keep the
    /// pairing AEAD for the whole session" decision means the history sync
    /// handed off via `PairingCommand::StartSync` does not re-key to ring
    /// MLS, unlike the established-devices reconnect-sync path (§3.6),
    /// which is a real ring member on both ends and has no such channel to
    /// continue.
    pub fn channel_keys(&self) -> &PairingChannelKeys {
        &self.keys
    }

    /// The next unused counter for frames *we* send, continuing this
    /// session's own sequence. A host driving traffic after `is_done()`
    /// must start here — reusing a counter already used during
    /// Enroll/Admit/Done would violate the AEAD's nonce-uniqueness
    /// requirement (see [`seal_frame`]).
    pub fn next_send_counter(&self) -> u64 {
        self.send_counter
    }

    /// The next unused counter for frames *we* expect to receive,
    /// continuing this session's own sequence. See
    /// [`next_send_counter`](Self::next_send_counter).
    pub fn next_recv_counter(&self) -> u64 {
        self.recv_counter
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
    ///
    /// `own_stealth_pubkey` and `known_siblings` supply what [`Admit::roster`]
    /// needs but `PairingSession` cannot derive on its own: stealth scan
    /// keys live host-side (fed into `DeviceRingState::tick` from
    /// `social.moat.stealthAddress` PDS records — see that module's
    /// `SiblingStealth` doc), never in MLS group state. `known_siblings` is
    /// the host's already-known roster of other ring members (empty for a
    /// first pairing); the emitted `Admit.roster` is `[own SiblingInfo] ++
    /// known_siblings`.
    ///
    /// Errors without changing the session's phase if there is no pending
    /// `Enroll` to approve (including a terminal session — a completed or
    /// already-failed pairing's outcome is never overwritten by a stray
    /// approve). Once past that guard, any further `Err` — a failure
    /// creating or adding to the ring — moves the session to
    /// `Failed { reason }` first, so the reason survives for
    /// [`ui_state`](Self::ui_state) / status reporting.
    pub fn approve(
        &mut self,
        mls: &MoatSession,
        credential: &MoatCredential,
        key_bundle: &[u8],
        own_stealth_pubkey: [u8; 32],
        known_siblings: &[SiblingInfo],
        existing_ring_id: Option<&[u8]>,
    ) -> Result<Vec<PairingCommand>> {
        if !matches!(
            self.phase,
            Phase::ExistingDevice(ExistingDevicePhase::AwaitingApproval)
        ) {
            return Err(Error::PairingProtocol(
                "approve() called with no pending Enroll to approve".to_string(),
            ));
        }
        let result = self.approve_impl(
            mls,
            credential,
            key_bundle,
            own_stealth_pubkey,
            known_siblings,
            existing_ring_id,
        );
        if let Err(ref e) = result {
            self.fail(e.to_string());
        }
        result
    }

    fn approve_impl(
        &mut self,
        mls: &MoatSession,
        credential: &MoatCredential,
        key_bundle: &[u8],
        own_stealth_pubkey: [u8; 32],
        known_siblings: &[SiblingInfo],
        existing_ring_id: Option<&[u8]>,
    ) -> Result<Vec<PairingCommand>> {
        let enroll = self
            .pending_enroll
            .take()
            .expect("AwaitingApproval implies a pending Enroll");

        let ring_id: Vec<u8> = match existing_ring_id {
            None => mls.create_device_ring(credential, key_bundle)?,
            Some(ring_id) => ring_id.to_vec(),
        };
        let welcome_result = mls.add_member(&ring_id, key_bundle, &enroll.ring_kp)?;
        let commit_tag = welcome_result.commit_tag;

        let mut roster = vec![SiblingInfo {
            device_id: *mls.device_id(),
            device_name: credential.device_name().to_string(),
            stealth_pubkey: own_stealth_pubkey,
        }];
        roster.extend_from_slice(known_siblings);

        let admit = PairingMsg::Admit(Admit {
            ring_id: ring_id.clone(),
            welcome: welcome_result.welcome,
            roster,
        });
        let ciphertext = self.seal_and_advance(&encode_pairing_msg(&admit));

        self.ring_id = Some(ring_id);
        self.phase = Phase::ExistingDevice(ExistingDevicePhase::Done);

        Ok(vec![
            PairingCommand::SeedKpPool {
                device_id: *enroll.credential.device_id(),
                kps: enroll.conv_kps,
            },
            PairingCommand::PublishRingCommit {
                tag: commit_tag,
                ciphertext: welcome_result.commit,
            },
            PairingCommand::SendFrame { ciphertext },
            PairingCommand::StartSync,
        ])
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
