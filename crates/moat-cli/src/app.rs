//! Application state and logic

use crate::{
    blob_cache::BlobCache,
    drawbridge,
    drawbridge::DrawbridgeManager,
    image_processing,
    keystore::{hex, GroupMetadata, KeyStore, StoredSession},
    message_helpers::{build_text_payload, needs_blob_upload, render_message_preview, truncate_to_preview},
};
use crossterm::event::{KeyCode, KeyEvent};
use moat_atproto::{BlobRef, MoatAtprotoClient};
use moat_core::{
    blob_decrypt, blob_encrypt, encrypt_for_stealth, generate_stealth_keypair,
    stealth_pubkey_from_privkey, try_decrypt_stealth, ControlKind, CoordMsg, DeviceRingState,
    Event, EventKind, ExternalBlob, GroupKind, LongTextMessage, MediaMessage, MessagePayload,
    MoatCredential, MoatSession, ModifierKind, PairingCommand, PairingPayload, PairingSession,
    PairingUiState, ParsedMessagePayload, RingCommand, RingMsg, SiblingInfo, SiblingStealth,
    StepEnv, SyncRequestSession, SyncRequestUiState, CIPHERSUITE,
};
use ratatui_image::{picker::Picker, protocol::StatefulProtocol};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::mpsc;

/// Quick-reaction emojis (same as Flutter app)
pub const QUICK_EMOJIS: &[&str] = &["👍", "❤️", "😂", "😮", "😢", "🙏"];

// ── Welcome envelope (Welcome + Drawbridge hint bundle) ─────────────────────

/// A Drawbridge hint bundled alongside a Welcome for the new member.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HintBundleEntry {
    did: String,
    url: String,
    device_id: Vec<u8>,
    ticket: Vec<u8>,
}

/// Magic bytes identifying the envelope format (vs. raw MLS Welcome).
const WELCOME_ENVELOPE_MAGIC: [u8; 4] = *b"MWE1";

/// Encode a Welcome + hint bundle into an envelope.
///
/// Format: `[4-byte magic][4-byte welcome_len BE][welcome][hints_json]`
fn encode_welcome_envelope(welcome: &[u8], hints: &[HintBundleEntry]) -> Vec<u8> {
    let hints_json = serde_json::to_vec(&hints).unwrap_or_else(|_| b"[]".to_vec());
    let mut buf = Vec::with_capacity(8 + welcome.len() + hints_json.len());
    buf.extend_from_slice(&WELCOME_ENVELOPE_MAGIC);
    buf.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
    buf.extend_from_slice(welcome);
    buf.extend_from_slice(&hints_json);
    buf
}

/// Decode a Welcome envelope, returning `(welcome_bytes, hints)`.
///
/// All Welcomes must use the envelope format (`[MWE1][len][welcome][hints]`).
fn decode_welcome_envelope(data: &[u8]) -> Result<(Vec<u8>, Vec<HintBundleEntry>)> {
    if data.len() < 8 || data[..4] != WELCOME_ENVELOPE_MAGIC {
        return Err(AppError::Other(
            "invalid welcome envelope: missing MWE1 magic".to_string(),
        ));
    }
    let welcome_len =
        u32::from_be_bytes(data[4..8].try_into().unwrap_or_default()) as usize;
    if data.len() < 8 + welcome_len {
        return Err(AppError::Other(
            "invalid welcome envelope: truncated".to_string(),
        ));
    }
    let welcome = data[8..8 + welcome_len].to_vec();
    let hints: Vec<HintBundleEntry> = if data.len() > 8 + welcome_len {
        serde_json::from_slice(&data[8 + welcome_len..]).unwrap_or_default()
    } else {
        vec![]
    };
    Ok((welcome, hints))
}

/// Thin wrapper around `Box<dyn StatefulProtocol>` that implements `Debug`
/// (needed because `DisplayMessage` derives `Debug`).
pub struct ImageProto(pub StatefulProtocol);
impl std::fmt::Debug for ImageProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImageProto(..)")
    }
}

/// Debug logger that writes to a file in the storage directory
struct DebugLog {
    path: PathBuf,
}

impl DebugLog {
    fn new(storage_dir: &std::path::Path) -> Self {
        let log = Self {
            path: storage_dir.join("debug.log"),
        };
        // A storage root can be reused across process restarts (the beacon
        // restart scenarios do exactly that), so without a marker the log of
        // one run runs straight into the next with only wall-clock times to
        // separate them. Line timestamps carry no date, which makes that
        // ambiguous across midnight and useless for correlating with a test
        // run.
        log.log(&format!(
            "=== run start {} pid={} ===",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            std::process::id(),
        ));
        log
    }

    fn log(&self, msg: &str) {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let timestamp = chrono::Local::now().format("%H:%M:%S%.3f");
            let _ = writeln!(file, "[{}] {}", timestamp, msg);
        }
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("keystore error: {0}")]
    KeyStore(#[from] crate::keystore::KeyStoreError),

    #[error("MLS error: {0}")]
    Mls(#[from] moat_core::Error),

    #[error("ATProto error: {0}")]
    AtProto(#[from] moat_atproto::Error),

    #[error("not logged in")]
    NotLoggedIn,

    #[error("no conversation selected")]
    NoConversation,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AppError>;

/// UI focus state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Conversations,
    Messages,
    Input,
    Login,
    NewConversation,
    WatchHandle,
    /// New device: showing the pairing code, waiting for the existing
    /// device to enter it and approve.
    PairShowCode,
    /// Existing device: text-entry for a pairing code scanned/typed
    /// elsewhere.
    PairEnterCode,
    /// Existing device: confirmation screen naming the peer awaiting an
    /// approval decision.
    PairApprove,
    /// A sibling asked for history: confirmation screen naming it, awaiting
    /// the decision to send.
    SyncApprove,
    /// The linked-device list: who else can read this account's messages,
    /// and the state of any sync in flight.
    Devices,
}

/// Login form state
#[derive(Debug, Clone, Default)]
pub struct LoginForm {
    pub handle: String,
    pub password: String,
    pub field: LoginField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoginField {
    #[default]
    Handle,
    Password,
}

/// A conversation with one or more other users
#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: String,
    /// Explicit group name set by a user (like WhatsApp/Telegram group names).
    /// `None` means the display name is computed from participant handles.
    pub name: Option<String>,
    pub participant_dids: Vec<String>,
    /// Resolved handles for each participant (may contain DIDs for unresolved members).
    pub participant_handles: Vec<String>,
    pub current_epoch: u64,
    pub unread: usize,
    /// Whether this device is an MLS member of the group.
    ///
    /// `false` for a conversation whose history arrived by sync before
    /// the fan-out that adds us to it — see [`App::register_synced_conversation`].
    /// Not a separate source of truth: it caches the check that already
    /// decides the epoch below, namely whether a local MLS group exists
    /// for this id.
    pub is_member: bool,
}

impl Conversation {
    /// Returns the display name: explicit name if set, otherwise comma-joined
    /// participant handles (falling back to DIDs if handles are empty).
    pub fn display_name(&self) -> String {
        if let Some(name) = &self.name {
            return name.clone();
        }
        if !self.participant_handles.is_empty() {
            return self.participant_handles.join(", ");
        }
        self.participant_dids.join(", ")
    }
}

/// A single reaction on a message
#[derive(Debug, Clone)]
pub struct DisplayReaction {
    pub emoji: String,
    pub sender_did: String,
}

/// A display message
#[derive(Debug)]
pub struct DisplayMessage {
    pub from: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_own: bool,
    /// The sender's DID (for collapsed identity display)
    pub sender_did: Option<String>,
    /// The sender's device name (for message info feature)
    pub sender_device: Option<String>,
    /// Unique message identifier (for reactions)
    pub message_id: Option<Vec<u8>>,
    /// Reactions on this message (aggregated)
    pub reactions: Vec<DisplayReaction>,
    /// ratatui-image render state; `Some` once image bytes are available.
    pub image_proto: Option<ImageProto>,
    /// `true` while the image blob is being fetched from the PDS.
    pub image_loading: bool,
    /// ATProto record key (TID), used for canonical ordering.
    pub rkey: String,
}

/// A notification about a new device joining a conversation
#[derive(Debug, Clone)]
pub struct DeviceAlert {
    pub conversation_name: String,
    pub user_name: String,
    pub device_name: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Metadata for an off-chain blob that has been encrypted and uploaded to the PDS.
/// Carried by [`BgEvent::BlobUploaded`] and [`BgEvent::ImageUploaded`] so the
/// foreground task can build an `ExternalBlob` and publish the MLS event.
pub(crate) struct UploadedBlob {
    pub cid: String,
    pub key: Vec<u8>,
    pub ciphertext_hash: Vec<u8>,
    pub ciphertext_size: u64,
    pub content_hash: Vec<u8>,
}

/// Display/encoding metadata for an image attachment.
pub(crate) struct ImageMeta {
    pub width: u32,
    pub height: u32,
    pub thumbhash: Vec<u8>,
    pub mime: String,
}

/// Events produced by background tasks and consumed by the main loop.
pub(crate) enum BgEvent {
    /// Network portion of poll_messages completed.
    PollFetched {
        participant_events: Vec<(Vec<usize>, moat_atproto::EventRecord, String)>,
        watched_events: Vec<(String, moat_atproto::EventRecord)>,
        new_rkeys: Vec<(String, String)>,
    },
    /// Network publish for send_message completed.
    SendPublished {
        uri: String,
        conv_id: String,
        tag: [u8; 16],
        /// The published ciphertext, forwarded to Drawbridge for relay delivery.
        ciphertext: Vec<u8>,
        /// MLS message ID, used to correlate with the pending stored message.
        message_id: Option<Vec<u8>>,
    },
    /// Network publish for send_message failed.
    SendFailed(String),
    /// Background auto-login completed.
    LoggedIn {
        client: MoatAtprotoClient,
        did: String,
        access_jwt: String,
        refresh_jwt: String,
    },
    /// Background login failed.
    LoginFailed(String),
    /// Background poll error (non-fatal).
    PollError(String),

    /// Drawbridge new_event notification received via relay.
    /// Includes optional inline payload for instant decryption.
    DrawbridgeNewEvent {
        tag: [u8; 16],
        rkey: String,
        /// Base64-decoded ciphertext, if included in the relay message.
        payload: Option<Vec<u8>>,
    },

    /// Own Drawbridge connection was lost.
    DrawbridgeDisconnected {
        url: String,
        reason: String,
    },

    /// Signal to connect to own Drawbridge (async, handled in main loop).
    DrawbridgeConnectOwn {
        url: String,
        did: String,
        signature_key: Vec<u8>,
    },

    /// Signal to notify own Drawbridge about a published event (async).
    DrawbridgeNotifyEventPosted {
        did: String,
        tag: [u8; 16],
        rkey: String,
        payload: Vec<u8>,
        drawbridge_urls: Vec<String>,
    },

    /// Signal to register watched tags on own Drawbridge (async).
    DrawbridgeWatchTags {
        tags: Vec<[u8; 16]>,
    },

    /// Relay config fetched for a partner DID.
    DrawbridgeConfigFetched {
        did: String,
        urls: Vec<String>,
    },

    /// Handle resolution completed for a welcome-joined conversation.
    HandleResolved {
        conv_id: String,
        did: String,
        handle: String,
    },

    /// Blob upload completed — MLS-encrypt and publish the long-text event.
    BlobUploaded {
        blob: UploadedBlob,
        preview_text: String,
        conv_id: String,
    },

    /// Blob fetch succeeded — update the in-memory message with full text.
    BlobFetched {
        message_id: Vec<u8>,
        full_text: String,
    },

    /// Blob fetch failed — show an inline error on the message.
    BlobFetchFailed {
        message_id: Vec<u8>,
        error: String,
    },

    /// Image processed and blob uploaded — MLS-encrypt and publish the image event.
    ImageUploaded {
        blob: UploadedBlob,
        image: ImageMeta,
        pending_message_id: Vec<u8>,
        conv_id: String,
    },

    /// Image blob fetch succeeded — decode and display the full image.
    ImageBlobFetched {
        message_id: Vec<u8>,
        /// Decrypted image bytes (JPEG or PNG).
        bytes: Vec<u8>,
    },

    // ── Drawbridge pairing (main WS control plane) ───────────────────────────

    /// Relay acknowledged our offer; waiting for a joiner.
    PairPending,
    /// Both sides matched; open the `/pair` WS.
    PairReady {
        pair_url: String,
        token: Vec<u8>,
    },
    /// A pairing session ended (either side closed).
    PairClosed {
        /// `None` only if the relay omitted it.
        session_token: Option<Vec<u8>>,
        reason: String,
    },
    /// Open and attach to the `/pair` WebSocket.
    DrawbridgeConnectPair {
        url: String,
        token: Vec<u8>,
    },
    /// Send binary data on the pair WS (ring-MLS ciphertext, or pairing AEAD
    /// ciphertext while a `PairingSession` is driving onboarding).
    DrawbridgeSendPairBinary {
        data: Vec<u8>,
    },
    /// New device: send `pair_offer{token}` on the main WS to start a live
    /// pairing session (device onboarding, not reconnect sync).
    DrawbridgeSendPairOffer {
        token: Vec<u8>,
    },
    /// Existing device: send `pair_join{token}` on the main WS in response
    /// to a scanned/typed pairing code.
    DrawbridgeSendPairJoin {
        token: Vec<u8>,
    },
    /// Existing device, right after a successful `approve()`: fan the
    /// newcomer into every pre-existing user conversation immediately
    /// (`poll_for_new_devices` is async; this hops through the async side
    /// since `approve_pending_pairing` itself is synchronous).
    PollForNewDevicesNow,
    /// New device, right after persisting ring membership (`Done`):
    /// proactively scan for the `UserConvWelcome`s an existing sibling's
    /// `PollForNewDevicesNow` may already have published, rather than
    /// waiting for the next periodic ring tick (every 30s) — same "shows
    /// conversations within seconds" promise as `PollForNewDevicesNow`,
    /// mirrored on the receiving side.
    RingTickNow,
    /// Existing device, on Approve: publish the ring Add commit to the PDS
    /// under `tag`, so a bystander sibling can pick it up on its own next
    /// poll (qr-pairing.md §6) — see `PairingCommand::PublishRingCommit`'s
    /// doc for why this is a second, PDS-borne path distinct from the
    /// `Welcome` riding the pair channel raw.
    PublishRingCommit { tag: [u8; 16], ciphertext: Vec<u8> },
    /// Publish a ring application event (`EventKind::RingMsg`) to our own
    /// repo and notify Drawbridge, so siblings holding a live relay
    /// connection see it at once instead of on their next 30 s poll.
    PublishRingEvent { tag: [u8; 16], ciphertext: Vec<u8> },

    /// A binary frame arrived on the pair WS.
    PairFrameReceived {
        data: Vec<u8>,
    },
    /// Pair WS is fully attached (both sides present).
    PairConnected,
}

impl BgEvent {
    /// Whether this event requires async handling (must be processed outside the
    /// synchronous drain loop). Shared by TUI and HTTP headless loop.
    ///
    /// Uses an exhaustive match so that adding a new variant is a compile error
    /// until you explicitly decide whether it needs async handling.
    pub(crate) fn is_async(&self) -> bool {
        match self {
            BgEvent::DrawbridgeConnectOwn { .. }
            | BgEvent::DrawbridgeNotifyEventPosted { .. }
            | BgEvent::DrawbridgeWatchTags { .. }
            | BgEvent::DrawbridgeConnectPair { .. }
            | BgEvent::DrawbridgeSendPairBinary { .. }
            | BgEvent::DrawbridgeSendPairOffer { .. }
            | BgEvent::DrawbridgeSendPairJoin { .. }
            | BgEvent::PollForNewDevicesNow
            | BgEvent::RingTickNow
            | BgEvent::PublishRingCommit { .. }
            | BgEvent::PublishRingEvent { .. } => true,

            BgEvent::PollFetched { .. }
            | BgEvent::SendPublished { .. }
            | BgEvent::SendFailed(_)
            | BgEvent::LoggedIn { .. }
            | BgEvent::LoginFailed(_)
            | BgEvent::PollError(_)
            | BgEvent::DrawbridgeNewEvent { .. }
            | BgEvent::DrawbridgeDisconnected { .. }
            | BgEvent::DrawbridgeConfigFetched { .. }
            | BgEvent::HandleResolved { .. }
            | BgEvent::BlobUploaded { .. }
            | BgEvent::BlobFetched { .. }
            | BgEvent::BlobFetchFailed { .. }
            | BgEvent::ImageUploaded { .. }
            | BgEvent::ImageBlobFetched { .. }
            | BgEvent::PairPending
            | BgEvent::PairReady { .. }
            | BgEvent::PairClosed { .. }
            | BgEvent::PairFrameReceived { .. }
            | BgEvent::PairConnected => false,
        }
    }
}

/// Stats returned from a completed poll (for HTTP API awaitable poll).
#[derive(Default)]
pub(crate) struct PollStats {
    pub new_messages: usize,
    pub new_conversations: usize,
}

/// Main application state
pub struct App {
    pub keys: KeyStore,
    pub client: Option<MoatAtprotoClient>,
    pub mls: MoatSession,
    mls_path: std::path::PathBuf,
    /// Persistent disk cache for decrypted blob content, keyed by content_hash.
    blob_cache: BlobCache,
    /// Terminal image renderer — auto-detects Kitty/Sixel/iTerm2/half-block protocol.
    picker: Picker,
    debug_log: DebugLog,

    // UI state
    pub focus: Focus,
    pub login_form: LoginForm,
    pub error_message: Option<String>,
    pub status_message: Option<String>,
    /// Cached handle of the logged-in user (for the info bar)
    pub logged_in_handle: Option<String>,

    // Conversations
    pub conversations: Vec<Conversation>,
    pub active_conversation: Option<usize>,

    // Messages for active conversation
    pub messages: Vec<DisplayMessage>,
    pub message_scroll: usize,
    pub selected_message: Option<usize>, // For message info feature
    pub show_message_info: bool,         // Toggle message info popup
    pub reaction_picker: Option<usize>,  // Emoji picker index (Some = popup open)

    // Device alerts (new devices joining conversations)
    pub device_alerts: Vec<DeviceAlert>,

    // Input
    pub input_buffer: String,
    pub cursor_position: usize,

    // New conversation input
    pub new_conv_handle: String,

    // Tag -> conversation mapping (tag -> hex-encoded group_id)
    pub tag_map: HashMap<[u8; 16], String>,

    // Events that were fetched but could not be processed (tag miss or decrypt
    // failure). Retried each poll cycle after new events are processed, since
    // commits in new events may advance epochs and unlock these, until
    // `moat_core::keep_for_retry` says they are no longer worth it.
    unprocessed_events: Vec<crate::retry_buffer::UnprocessedEvent>,

    // Polling state
    last_poll: Option<Instant>,
    last_device_poll: Option<Instant>,

    // DIDs to watch for incoming invites
    watched_dids: std::collections::HashSet<String>,
    pub watch_handle_input: String,
    pub pair_enter_code_input: String,

    // Background task channel
    bg_tx: mpsc::UnboundedSender<BgEvent>,
    pub(crate) bg_rx: mpsc::UnboundedReceiver<BgEvent>,

    // Prevent overlapping background tasks
    pub(crate) poll_in_flight: bool,

    // Drawbridge connection manager
    pub(crate) drawbridge: DrawbridgeManager,
    /// Drawbridge URL for this device (from --drawbridge-url or persisted state)
    pub(crate) drawbridge_url: Option<String>,
    /// Cache of partner relay configurations (DID -> relay URLs)
    drawbridge_config_cache: drawbridge::DrawbridgeConfigCache,

    // HTTP API support (Some only when running in --http mode)
    /// Broadcast channel for SSE events.
    pub(crate) event_broadcast: Option<tokio::sync::broadcast::Sender<String>>,
    /// Oneshot sender to resolve a pending POST /poll request.
    pub(crate) pending_poll_result: Option<tokio::sync::oneshot::Sender<PollStats>>,

    /// PDS URL override from `--pds-url`. When set, all ATProto client
    /// instances use this URL for both authentication and peer DID resolution.
    /// Used for integration tests against a local Postern instance.
    pds_url: Option<String>,

    /// Override for the automatic poll interval, set via `POST /poll/{seconds}`.
    /// `None`  — use the default adaptive interval (5s idle, 30s with Drawbridge).
    /// `Some(0)` — disable auto-polling entirely (push-only mode for tests).
    /// `Some(n)` — poll every n seconds regardless of Drawbridge state.
    pub(crate) poll_interval_override: Option<u64>,

    /// Device ring state machine — persisted to `ring.json` in the keys dir.
    ring_driver: DeviceRingState,

    /// When was the last ring tick run?
    last_ring_tick: Option<Instant>,

    /// Active history sync session (Some while a pair WS session is in progress).
    sync_session: Option<crate::sync::SyncSession>,

    /// Ex-members this poll cycle actually asked for events, as
    /// `(conv_id, did)`. Cleared from `pending_ex_members` once the
    /// results have been processed — see the note where it is populated.
    swept_ex_members: Vec<(String, String)>,

    /// The device on the other end of the current sync, as MLS named it
    /// on the frames it sent. Read from the leaf credential rather than
    /// the payload, so it is the device the history actually came from —
    /// which is what makes "nothing new" actionable: the user learns
    /// *which* sibling had no more than they did.
    sync_peer_name: Option<String>,

    /// Pairing token for the in-flight pair WS session.
    pending_pair_token: Option<Vec<u8>>,

    /// Cached per-sibling stealth address records (`scan_pubkey` +
    /// `device_id`), refreshed each `ring_tick_inner` from
    /// `fetch_stealth_addresses`.  Needed by any code path that stealth-
    /// encrypts a `CoordMsg` to a sibling (same-user KP lane) outside the
    /// tick's own fresh fetch — `poll_for_new_devices` in particular.  A
    /// one-tick-stale cache is fine: the consumer-driven low-water
    /// `KpRequest` retries self-heal any miss caused by a sibling whose
    /// stealth record hasn't propagated yet.
    cached_sibling_stealth: Vec<moat_core::SiblingStealth>,

    // ── Live pairing (QR / text code) device onboarding ─────────────────────
    /// Active pairing exchange, once `/pair/new` or `/pair/confirm` has been
    /// called. Left in place (not cleared) once terminal (`Done` or
    /// `Failed`) — `ui_state()`/`GET /pair/status` must keep reporting the
    /// real outcome after completion, not just at the instant it happens.
    /// The single source of truth for pairing progress: every render/
    /// dispatch site reads it via `pairing_ui_state()` rather than caching
    /// its own copy of the code, the pending prompt, or a done flag.
    pairing_session: Option<PairingSession>,
    /// Which role `pairing_session` is playing: `Some(true)` for the new
    /// (joining) device, `Some(false)` for the existing (approving) device.
    /// Tells the `PairConnected` handler whether to call `start_enroll`.
    pairing_is_new_device: Option<bool>,
    /// The rendezvous token for an in-flight `pair_offer`/`pair_join` that
    /// hasn't been acknowledged (`pair_ready`) yet. If the main WS drops and
    /// reconnects while this is still set, the reconnect handler resends
    /// the offer/join — otherwise a `pair_join` that raced an
    /// not-yet-registered `pair_offer` (relay: "token not found or
    /// expired") would leave the session stuck forever with no retry.
    pending_pair_rendezvous_token: Option<Vec<u8>>,
    /// Present while a `PairingCommand::StartSync`-triggered history sync is
    /// running: the pairing channel's AEAD keys, captured from
    /// `PairingSession::channel_keys` at handoff. Distinguishes "still
    /// sealing/opening under the pairing AEAD" from the established-devices
    /// reconnect-sync path (`sync_session` alone, ring-MLS-encrypted) — see
    /// `interpret_pairing_commands`'s `StartSync` arm and the `PairFrameReceived`
    /// dispatch in `handle_bg_event`.
    pairing_sync_keys: Option<moat_core::PairingChannelKeys>,
    /// Next unused counter for pairing-AEAD sync frames *we* send,
    /// continuing `PairingSession::next_send_counter`'s sequence — must
    /// never restart at 0 (nonce reuse under the same key).
    pairing_sync_send_counter: u64,
    /// Next unused counter for pairing-AEAD sync frames *we* expect to
    /// receive, continuing `PairingSession::next_recv_counter`'s sequence.
    pairing_sync_recv_counter: u64,

    // ── User-initiated sync between established devices ─────────────────────
    /// The in-flight sync request, in either role: one we published
    /// (`/sync/request`) or one a sibling published and we are being asked
    /// to answer. Left in place once terminal so `/sync/status` reports the
    /// outcome rather than silently reverting to idle.
    sync_request: Option<SyncRequestSession>,
}

impl App {
    /// Create a new App instance
    ///
    /// If `storage_dir` is `None`, uses the default `~/.moat` directory.
    pub fn new(
        storage_dir: Option<std::path::PathBuf>,
        pds_url: Option<String>,
        drawbridge_url: Option<String>,
        picker: Picker,
    ) -> Result<Self> {
        // Determine the moat base directory (~/.moat or custom -s path).
        // User-managed files (e.g. credentials.txt) live here.
        let moat_dir = match storage_dir {
            Some(dir) => dir,
            None => dirs::home_dir()
                .ok_or_else(|| AppError::Other("home directory not found".to_string()))?
                .join(".moat"),
        };

        // All app-generated state lives in the data/ subdirectory.
        let data_dir = moat_dir.join("data");

        let keys = KeyStore::with_path(data_dir.join("keys"))?;

        // Initialize MoatSession - load from file if it exists, otherwise start fresh
        let mls_path = data_dir.join("mls.bin");

        // Ensure parent directory exists
        if let Some(parent) = mls_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::Other(format!("Failed to create data directory: {e}")))?;
        }

        let mls = if mls_path.exists() {
            let bytes = std::fs::read(&mls_path)
                .map_err(|e| AppError::Other(format!("Failed to read MLS state: {e}")))?;
            MoatSession::from_state(&bytes)?
        } else {
            MoatSession::new()
        };

        let blob_cache = BlobCache::new(data_dir.join("blobs"))
            .map_err(|e| AppError::Other(format!("Failed to create blob cache: {e}")))?;

        let debug_log = DebugLog::new(&data_dir);

        // If credentials.txt exists and no credentials are stored yet, import them.
        // Always read drawbridge URL from credentials.txt as a fallback.
        let credentials_txt_drawbridge = if let Ok(creds) = keys.load_credentials_txt() {
            if !keys.has_credentials() {
                let _ = keys.store_credentials(&creds.handle, &creds.password);
            }
            creds.drawbridge
        } else {
            None
        };

        let logged_in_handle = keys.load_credentials().ok().map(|(h, _)| h);

        let focus = if logged_in_handle.is_some() {
            Focus::Conversations
        } else {
            Focus::Login
        };

        let (bg_tx, bg_rx) = mpsc::unbounded_channel();

        // Load Drawbridge state, preferring CLI flag > credentials.txt > persisted state
        let drawbridge_state = keys.load_drawbridge_state().unwrap_or_default();
        let resolved_drawbridge_url = drawbridge_url
            .or(credentials_txt_drawbridge)
            .or(drawbridge_state.own_url.clone());

        let drawbridge = DrawbridgeManager::new(bg_tx.clone());

        let ring_driver = keys.load_ring_state().unwrap_or_default();
        let restored_unprocessed = keys.load_unprocessed_events().unwrap_or_default();

        Ok(Self {
            keys,
            client: None,
            mls,
            mls_path,
            blob_cache,
            picker,
            debug_log,
            focus,
            login_form: LoginForm::default(),
            error_message: None,
            status_message: None,
            logged_in_handle,
            conversations: Vec::new(),
            active_conversation: None,
            messages: Vec::new(),
            message_scroll: 0,
            selected_message: None,
            show_message_info: false,
            reaction_picker: None,
            device_alerts: Vec::new(),
            input_buffer: String::new(),
            cursor_position: 0,
            new_conv_handle: String::new(),
            tag_map: HashMap::new(),
            unprocessed_events: restored_unprocessed,
            last_poll: None,
            last_device_poll: None,
            watched_dids: std::collections::HashSet::new(),
            watch_handle_input: String::new(),
            pair_enter_code_input: String::new(),
            bg_tx,
            bg_rx,
            poll_in_flight: false,
            drawbridge,
            drawbridge_url: resolved_drawbridge_url,
            drawbridge_config_cache: HashMap::new(),
            event_broadcast: None,
            pending_poll_result: None,
            pds_url,
            poll_interval_override: None,
            ring_driver,
            last_ring_tick: None,
            sync_session: None,
            swept_ex_members: Vec::new(),
            sync_peer_name: None,
            pending_pair_token: None,
            cached_sibling_stealth: Vec::new(),
            pairing_session: None,
            pairing_is_new_device: None,
            sync_request: None,
            pending_pair_rendezvous_token: None,
            pairing_sync_keys: None,
            pairing_sync_send_counter: 0,
            pairing_sync_recv_counter: 0,
        })
    }

    /// Save MLS state to disk by exporting and writing to file.
    fn save_mls_state(&self) -> Result<()> {
        let state = self.mls.export_state()?;
        let temp_path = self.mls_path.with_extension("tmp");
        std::fs::write(&temp_path, &state)
            .map_err(|e| AppError::Other(format!("Failed to write MLS state: {e}")))?;
        std::fs::rename(&temp_path, &self.mls_path)
            .map_err(|e| AppError::Other(format!("Failed to rename MLS state: {e}")))?;
        Ok(())
    }

    /// Ensure identity key and stealth address are generated locally and published to PDS.
    /// Called from the auto-login path where do_login()'s provisioning may have been skipped.
    fn ensure_keys_provisioned(&mut self, client: &MoatAtprotoClient, did: &str) {
        let mut key_package_to_publish: Option<(Vec<u8>, String)> = None;
        let mut stealth_to_publish: Option<([u8; 32], String, [u8; 16])> = None;

        // Generate identity key if missing
        if !self.keys.has_identity_key() {
            self.debug_log
                .log("ensure_keys_provisioned: generating missing identity key");
            let device_name = match self.keys.get_or_create_device_name() {
                Ok(n) => n,
                Err(e) => {
                    self.debug_log
                        .log(&format!("ensure_keys_provisioned: device name error: {e}"));
                    return;
                }
            };
            let credential = MoatCredential::new(did, &device_name, *self.mls.device_id());
            match self.mls.generate_key_package(&credential) {
                Ok((key_package, key_bundle)) => {
                    let _ = self.save_mls_state();
                    let _ = self.keys.store_identity_key(&key_bundle);
                    let ciphersuite_name = format!("{:?}", CIPHERSUITE);
                    key_package_to_publish = Some((key_package, ciphersuite_name));
                }
                Err(e) => {
                    self.debug_log
                        .log(&format!("ensure_keys_provisioned: key gen error: {e}"));
                    return;
                }
            }
        }

        // Generate stealth address if missing
        if !self.keys.has_stealth_key() {
            self.debug_log
                .log("ensure_keys_provisioned: generating missing stealth address");
            let (stealth_privkey, stealth_pubkey) = generate_stealth_keypair();
            if let Err(e) = self.keys.store_stealth_key(&stealth_privkey) {
                self.debug_log
                    .log(&format!("ensure_keys_provisioned: store stealth key error: {e}"));
                return;
            }
            let device_name = match self.keys.get_or_create_device_name() {
                Ok(n) => n,
                Err(e) => {
                    self.debug_log
                        .log(&format!("ensure_keys_provisioned: device name error: {e}"));
                    return;
                }
            };
            stealth_to_publish = Some((stealth_pubkey, device_name, *self.mls.device_id()));
        }

        // Publish to PDS in a background task if anything needs publishing
        if key_package_to_publish.is_some() || stealth_to_publish.is_some() {
            let client = client.clone();
            let tx = self.bg_tx.clone();
            tokio::spawn(async move {
                if let Some((key_package, ciphersuite)) = key_package_to_publish {
                    if let Err(e) = client.publish_key_package(&key_package, &ciphersuite).await {
                        let _ = tx.send(BgEvent::PollError(format!(
                            "Failed to publish key package: {e}"
                        )));
                    }
                }
                if let Some((stealth_pubkey, device_name, device_id)) = stealth_to_publish {
                    if let Err(e) = client
                        .publish_stealth_address(&stealth_pubkey, &device_name, &device_id)
                        .await
                    {
                        let _ = tx.send(BgEvent::PollError(format!(
                            "Failed to publish stealth address: {e}"
                        )));
                    }
                }
            });
        }
    }

    /// Set an error message to display
    pub fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }

    /// Set a status message to display
    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some(msg);
    }

    /// Clear error message
    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    // ── HTTP API methods ──────────────────────────────────────────────

    /// HTTP: login with explicit credentials.
    pub async fn api_login(&mut self, handle: &str, password: &str) -> Result<()> {
        self.login_form.handle = handle.to_string();
        self.login_form.password = password.to_string();
        self.do_login().await
    }

    /// HTTP: set active conversation by group_id hex, loads messages.
    pub fn api_set_active_conversation(&mut self, group_id_hex: Option<&str>) -> Result<()> {
        match group_id_hex {
            None => {
                self.active_conversation = None;
                self.messages.clear();
                Ok(())
            }
            Some(id) => {
                match self.conversations.iter().position(|c| c.id == id) {
                    Some(idx) => {
                        self.active_conversation = Some(idx);
                        self.load_messages()
                    }
                    None => {
                        // Conv not in local MLS state yet (e.g. synced history before joining).
                        // Load from keystore directly so get_messages still works.
                        self.active_conversation = None;
                        self.messages.clear();
                        let local = self.keys.load_messages(id).unwrap_or_default();
                        for stored in &local.messages {
                            let from = if stored.is_own {
                                "You".to_string()
                            } else {
                                stored.sender_did.clone().unwrap_or_else(|| "Peer".to_string())
                            };
                            self.messages.push(DisplayMessage {
                                from,
                                content: stored.content.clone(),
                                timestamp: stored.timestamp,
                                is_own: stored.is_own,
                                sender_did: stored.sender_did.clone(),
                                sender_device: stored.sender_device.clone(),
                                message_id: stored.message_id.clone(),
                                reactions: vec![],
                                image_proto: None,
                                image_loading: false,
                                rkey: stored.rkey.clone(),
                            });
                        }
                        Ok(())
                    }
                }
            }
        }
    }

    /// HTTP: read messages for the active conversation via the same in-memory
    /// state the TUI renders from.  Callers must set the active conversation
    /// first (via `api_set_active_conversation`).
    pub fn api_get_messages(&self) -> &[DisplayMessage] {
        &self.messages
    }

    /// HTTP: load stored messages for a group, keyed by hex message_id.
    /// Used by the HTTP server to enrich `MessageDto` with attachment metadata.
    pub fn api_load_stored_messages(
        &self,
        group_id: &str,
    ) -> std::collections::HashMap<String, crate::keystore::StoredMessage> {
        self.keys
            .load_messages(group_id)
            .map(|cm| {
                cm.messages
                    .into_iter()
                    .filter_map(|m| {
                        let id_hex = m.message_id.as_ref().map(|id| hex::encode(id))?;
                        Some((id_hex, m))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// HTTP: send message to active conversation.
    pub fn api_send_message(&mut self, text: String) -> Result<()> {
        self.input_buffer = text;
        self.cursor_position = 0;
        self.send_message_nonblocking()
    }

    /// HTTP: send an image from already-loaded bytes (no temp file needed).
    pub fn api_send_image_bytes(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.send_image_bytes_nonblocking(bytes)
    }

    /// HTTP: fetch, decrypt, and return the image bytes for a received image message.
    pub async fn api_fetch_image_blob(&mut self, group_id: &str, message_id_hex: &str) -> Result<(Vec<u8>, String)> {
        use moat_core::blob_decrypt;

        let message_id = hex::decode(message_id_hex)
            .map_err(|e| AppError::Other(format!("invalid message_id: {e}")))?;

        // Load stored message to find blob metadata.
        let conv_messages = self.keys.load_messages(group_id)
            .map_err(|e| AppError::Other(format!("load messages failed: {e}")))?;
        let stored = conv_messages.messages.iter()
            .find(|m| m.message_id.as_ref() == Some(&message_id))
            .ok_or_else(|| AppError::Other("message not found".to_string()))?
            .clone();

        let uri = stored.blob_uri.ok_or_else(|| AppError::Other("not an image message".to_string()))?;
        let key_vec = stored.blob_key.ok_or_else(|| AppError::Other("missing blob key".to_string()))?;
        let ciphertext_hash = stored.blob_ciphertext_hash.ok_or_else(|| AppError::Other("missing ciphertext_hash".to_string()))?;
        let content_hash = stored.blob_content_hash.ok_or_else(|| AppError::Other("missing content_hash".to_string()))?;
        let mime = stored.blob_mime.unwrap_or_else(|| "image/jpeg".to_string());

        // Check disk cache first.
        if let Some(cached) = self.blob_cache.get(&content_hash) {
            return Ok((cached, mime));
        }

        // Parse at:// URI → (did, cid).
        let (did, cid) = uri.strip_prefix("at://")
            .and_then(|s| {
                let pos = s.find('/')?;
                Some((s[..pos].to_string(), s[pos + 1..].to_string()))
            })
            .ok_or_else(|| AppError::Other(format!("invalid blob URI: {uri}")))?;

        let key: [u8; 32] = key_vec.as_slice().try_into()
            .map_err(|_| AppError::Other("blob key has wrong length".to_string()))?;

        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?.clone();
        let blob_bytes = client.fetch_blob(&did, &cid).await
            .map_err(|e| AppError::Other(format!("fetch blob failed: {e}")))?;

        let plaintext = blob_decrypt(&blob_bytes, &key, &ciphertext_hash, &content_hash)
            .map_err(|e| AppError::Other(format!("blob decrypt failed: {e}")))?;

        let _ = self.blob_cache.put(&content_hash, &plaintext);

        Ok((plaintext, mime))
    }

    /// HTTP: send an emoji reaction by explicit message_id hex.
    pub async fn api_send_reaction(&mut self, message_id_hex: &str, emoji: &str) -> Result<()> {
        let target_message_id = hex::decode(message_id_hex)
            .map_err(|e| AppError::Other(format!("Invalid message_id hex: {}", e)))?;
        self.send_reaction_by_id(&target_message_id, emoji).await
    }

    /// Shared reaction logic: encrypt, publish, and locally toggle the reaction.
    /// Used by both TUI (send_reaction) and HTTP (api_send_reaction).
    async fn send_reaction_by_id(&mut self, target_message_id: &[u8], emoji: &str) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        let conv_idx = self.active_conversation.ok_or(AppError::NoConversation)?;
        let conv_id = self.conversations[conv_idx].id.clone();

        self.debug_log.log(&format!(
            "send_reaction_by_id: emoji={}, target_id={:02x?}",
            emoji,
            &target_message_id[..4.min(target_message_id.len())]
        ));

        let key_bundle = self.keys.load_identity_key()?;
        let group_id = hex::decode(&conv_id)
            .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

        let current_epoch = self.mls.get_group_epoch(&group_id)?.unwrap_or(1);
        let event = Event::reaction(
            group_id.clone(),
            current_epoch,
            target_message_id,
            emoji,
        );

        let encrypted = self.mls.encrypt_event(&group_id, &key_bundle, &event)?;
        self.save_mls_state()?;
        self.keys
            .store_group_state(&conv_id, &encrypted.new_group_state)?;

        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        client
            .publish_event(&encrypted.tag, &encrypted.ciphertext, None)
            .await?;

        self.tag_map.insert(encrypted.tag, conv_id.clone());

        // Apply reaction locally (toggle semantics)
        let my_did = self.client.as_ref().unwrap().did().to_string();
        if let Some(msg) = self.messages.iter_mut().find(|m| {
            m.message_id.as_deref() == Some(target_message_id)
        }) {
            let emoji_str = emoji.to_string();
            if let Some(pos) = msg
                .reactions
                .iter()
                .position(|r| r.emoji == emoji_str && r.sender_did == my_did)
            {
                msg.reactions.remove(pos);
            } else {
                msg.reactions.push(DisplayReaction {
                    emoji: emoji_str,
                    sender_did: my_did,
                });
            }
        }

        self.debug_log.log("send_reaction_by_id: published");
        Ok(())
    }

    /// HTTP: add a DID to the watch list.
    pub async fn api_watch_handle(&mut self, handle: &str) -> Result<()> {
        self.watch_handle(handle).await
    }

    /// HTTP: start a new conversation with recipient_handle.
    pub async fn api_start_conversation(&mut self, recipient_handle: &str) -> Result<String> {
        let conv_count_before = self.conversations.len();
        self.start_new_conversation(recipient_handle).await?;
        // Return the group_id of the newly created or selected conversation
        let id = if self.conversations.len() > conv_count_before {
            self.conversations.last().map(|c| c.id.clone())
        } else {
            self.active_conversation.and_then(|i| self.conversations.get(i).map(|c| c.id.clone()))
        };
        id.ok_or_else(|| AppError::Other("failed to determine conversation id".to_string()))
    }

    /// HTTP: add a member to an existing group conversation.
    pub async fn api_add_member(&mut self, group_id_hex: &str, handle: &str) -> Result<()> {
        self.add_member_to_group(group_id_hex, handle).await
    }

    /// HTTP: kick a member from a group conversation by handle.
    pub async fn api_kick_member(&mut self, group_id_hex: &str, handle: &str) -> Result<()> {
        self.kick_member_from_group(group_id_hex, handle).await
    }

    /// HTTP: delete a conversation locally.
    pub fn api_delete_conversation(&mut self, group_id_hex: &str) -> Result<()> {
        self.keys.delete_group_metadata(group_id_hex)?;
        self.conversations.retain(|c| c.id != group_id_hex);
        if let Some(idx) = self.active_conversation {
            if idx >= self.conversations.len() {
                self.active_conversation = if self.conversations.is_empty() {
                    None
                } else {
                    Some(self.conversations.len() - 1)
                };
                self.messages.clear();
            }
        }
        Ok(())
    }

    /// Clear login state (shared by TUI and HTTP).
    pub fn logout(&mut self) {
        self.client = None;
        self.logged_in_handle = None;
    }

    /// HTTP: list DIDs currently being watched for invites.
    pub fn api_watched_dids(&self) -> Vec<String> {
        self.watched_dids.iter().cloned().collect()
    }

    /// HTTP: remove a DID from the watch list.
    pub fn api_unwatch_did(&mut self, did: &str) {
        self.watched_dids.remove(did);
        let _ = self.keys.store_watched_dids(&self.watched_dids);
    }

    /// HTTP: set the automatic poll interval in seconds.
    /// `0` disables auto-polling (push-only mode); any positive value sets the interval.
    pub fn api_set_poll_interval(&mut self, seconds: u64) {
        self.poll_interval_override = Some(seconds);
    }

    /// HTTP: return the current device ring state for integration tests.
    ///
    /// Returns `(ring_group_id_hex, coord_group_count)`.
    /// Returns `(ring_group_id_hex, coord_group_count, ring_member_count)`.
    /// `ring_member_count` is this device's own MLS view of ring
    /// membership — 0 if not in a ring. Exists so a bystander sibling's
    /// convergence (or lack of it) after another device's pairing is
    /// observable at all; before this, `RingStatus` could only confirm
    /// "some ring exists," not who's actually in it.
    /// One linked device, as the Devices screen renders it. Names come
    /// from the ring's own MLS leaf credentials — the authenticated
    /// `device_id -> signature key` map the ring exists to be — so this
    /// list is exactly "who can read your messages", not a self-reported
    /// roster.
    pub fn api_ring_devices(&self) -> Vec<serde_json::Value> {
        let Some(ring_id) = self.ring_driver.ring_id() else {
            return Vec::new();
        };
        let Ok(members) = self.mls.get_group_members(ring_id) else {
            return Vec::new();
        };
        let my_device_id = *self.mls.device_id();
        let mut devices: Vec<serde_json::Value> = members
            .into_iter()
            .filter_map(|(leaf, cred)| {
                let cred = cred?;
                Some(serde_json::json!({
                    "leaf": leaf,
                    "device_id": hex::encode(cred.device_id()),
                    "device_name": cred.device_name(),
                    "is_self": cred.device_id() == &my_device_id,
                }))
            })
            .collect();
        // Stable order so the list doesn't reshuffle between polls.
        devices.sort_by_key(|d| d["leaf"].as_u64().unwrap_or(0));
        devices
    }

    pub fn api_ring_status(&self) -> (Option<String>, usize, usize) {
        let ring_group_id = self.ring_driver.ring_id();
        let coord_count = self.ring_driver.coord_group_count();
        let member_count = ring_group_id
            .and_then(|id| self.mls.get_group_members(id).ok())
            .map(|m| m.len())
            .unwrap_or(0);
        (ring_group_id.map(hex::encode), coord_count, member_count)
    }

    /// HTTP `POST /pair/new` — new device requests a pairing code. Requires
    /// being logged in (pairing presupposes a logged-in device —
    /// qr-pairing.md §2). Returns the text-form code; kicks off the
    /// Drawbridge rendezvous (`pair_offer`) asynchronously.
    pub fn api_pair_new(&mut self) -> Result<String> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        use rand::RngCore;
        let mut token = [0u8; moat_core::PAIRING_TOKEN_LEN];
        let mut secret = [0u8; moat_core::PAIRING_SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut token);
        rand::thread_rng().fill_bytes(&mut secret);

        let payload = PairingPayload { token, secret };
        let code = payload.to_text();

        // A previous pairing's pair WS / sync state (if any) is now
        // superseded — a device only ever drives one pairing exchange at a
        // time, and leaving the old `pairing_sync_keys` set would route
        // this new pairing's incoming frames through the *old* AEAD
        // channel's dispatch, misinterpreting them (see the dispatch note
        // on `PairFrameReceived`).
        self.drawbridge.clear_pair();
        self.sync_session = None;
        self.pairing_sync_keys = None;
        self.pairing_session = Some(PairingSession::new_device(&payload));
        self.pairing_is_new_device = Some(true);
        self.pending_pair_rendezvous_token = Some(token.to_vec());

        let _ = self
            .bg_tx
            .send(BgEvent::DrawbridgeSendPairOffer { token: token.to_vec() });

        Ok(code)
    }

    /// HTTP `POST /pair/confirm` — existing device enters a pairing code.
    /// Parses the code, starts a `PairingSession::existing_device`, and
    /// kicks off the Drawbridge rendezvous (`pair_join`) asynchronously.
    /// Approval of the resulting `Enroll` is a separate, explicit step —
    /// `confirm` no longer implies it. Poll `GET /pair/status` for
    /// `awaiting_approval` and call `POST /pair/approve` (or `/pair/reject`)
    /// once it arrives; no host — including `--http` — auto-approves.
    pub fn api_pair_confirm(&mut self, code: &str) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        let payload = PairingPayload::from_text(code).map_err(AppError::Mls)?;

        // See the matching note in `api_pair_new`: supersede any previous
        // pairing's pair WS / sync state before starting this one.
        self.drawbridge.clear_pair();
        self.sync_session = None;
        self.pairing_sync_keys = None;
        self.pairing_session =
            Some(PairingSession::existing_device(&payload.secret, &payload.token));
        self.pairing_is_new_device = Some(false);
        self.pending_pair_rendezvous_token = Some(payload.token.to_vec());

        let _ = self.bg_tx.send(BgEvent::DrawbridgeSendPairJoin {
            token: payload.token.to_vec(),
        });

        Ok(())
    }

    /// HTTP `POST /pair/approve` — existing device: approve the `Enroll`
    /// `ui_state()` reports as `awaiting_approval`. Errors if there is no
    /// active session or nothing pending (mirrors `PairingSession::approve`'s
    /// own guard).
    pub fn api_pair_approve(&mut self) -> Result<()> {
        self.approve_pending_pairing()
    }

    /// HTTP `POST /pair/reject` — existing device: decline the pending
    /// `Enroll`, moving the session to `Failed`.
    pub fn api_pair_reject(&mut self) -> Result<()> {
        let session = self
            .pairing_session
            .as_mut()
            .ok_or_else(|| AppError::Other("no active pairing session".to_string()))?;
        session.reject().map_err(AppError::Mls)?;
        self.pending_pair_rendezvous_token = None;
        self.drawbridge.clear_pair();
        Ok(())
    }

    /// HTTP `POST /pair/cancel` — either role: abort an in-flight pairing
    /// before it reaches a terminal state, moving the session to `Failed`.
    pub fn api_pair_cancel(&mut self) -> Result<()> {
        let session = self
            .pairing_session
            .as_mut()
            .ok_or_else(|| AppError::Other("no active pairing session".to_string()))?;
        session.cancel().map_err(AppError::Mls)?;
        self.pending_pair_rendezvous_token = None;
        self.drawbridge.clear_pair();
        Ok(())
    }

    /// HTTP `GET /pair/status` — returns the serialized `PairingUiState`
    /// verbatim; every host renders this, none derives its own notion of
    /// pairing progress.
    pub fn api_pair_status(&self) -> PairingUiState {
        self.pairing_ui_state()
    }

    /// The current pairing UI state — `Idle` if no pairing is in flight
    /// (`pairing_session` is `None`), otherwise the active session's
    /// `ui_state()`. The single source of truth every render/dispatch site
    /// (TUI popups, `GET /pair/status`) reads instead of deriving its own.
    pub(crate) fn pairing_ui_state(&self) -> PairingUiState {
        self.pairing_session
            .as_ref()
            .map(|s| s.ui_state())
            .unwrap_or(PairingUiState::Idle)
    }

    /// `true` once the active pairing (if any) has nothing left to do —
    /// reached a terminal state (`Done`/`Failed`), or there is no session
    /// at all. Used by the TUI popups to know when any key should dismiss
    /// rather than be interpreted as approve/reject/cancel.
    pub(crate) fn pairing_is_terminal(&self) -> bool {
        matches!(
            self.pairing_ui_state(),
            PairingUiState::Idle | PairingUiState::Done { .. } | PairingUiState::Failed { .. }
        )
    }

    // ── End HTTP API methods ──────────────────────────────────────────

    /// Handle a key event, returns true if should quit
    pub async fn handle_key(&mut self, key: KeyEvent) -> Result<bool> {
        // Clear error on any key press
        self.clear_error();

        // Dismiss device alert on any key press if one is showing
        if !self.device_alerts.is_empty() {
            self.dismiss_device_alert();
            return Ok(false);
        }

        match self.focus {
            Focus::Login => self.handle_login_key(key).await,
            Focus::Conversations => self.handle_conversations_key(key).await,
            Focus::Messages => self.handle_messages_key(key).await,
            Focus::Input => self.handle_input_key(key), // sync — no await
            Focus::NewConversation => self.handle_new_conversation_key(key).await,
            Focus::WatchHandle => self.handle_watch_handle_key(key).await,
            Focus::PairShowCode => self.handle_pair_show_code_key(key), // sync — no await
            Focus::PairEnterCode => self.handle_pair_enter_code_key(key),
            Focus::PairApprove => self.handle_pair_approve_key(key), // sync — no await
            Focus::SyncApprove => self.handle_sync_approve_key(key), // sync — no await
            Focus::Devices => self.handle_devices_key(key), // sync — no await
        }
    }

    /// Periodic tick — spawns background tasks and is non-blocking.
    pub fn tick(&mut self) {
        // Auto-login if credentials exist but not logged in
        if self.client.is_none() && self.keys.has_credentials() && !self.poll_in_flight {
            self.spawn_auto_login();
        }

        // Spawn background poll for new messages.
        // Priority: poll_interval_override > adaptive (30s with Drawbridge, 5s idle).
        // Some(0) disables auto-polling entirely (push-only mode).
        if self.client.is_some() && !self.poll_in_flight {
            let poll_interval_secs = match self.poll_interval_override {
                Some(0) => None, // disabled
                Some(n) => Some(n),
                None => Some(if self.drawbridge.active_connection_count() > 0 {
                    30
                } else {
                    5
                }),
            };
            if let Some(interval) = poll_interval_secs {
                let should_poll = self
                    .last_poll
                    .map(|t| t.elapsed().as_secs() >= interval)
                    .unwrap_or(true);

                if should_poll {
                    self.last_poll = Some(Instant::now());
                    self.spawn_poll_messages();
                }
            }
        }

        // Device polling is handled by the main loop via should_poll_devices()/do_device_poll()
    }

    /// Spawn auto-login in background.
    fn spawn_auto_login(&mut self) {
        self.poll_in_flight = true;
        self.set_status("Logging in...".to_string());

        let has_session = self.keys.has_session();
        let stored_session = if has_session {
            self.keys.load_session().ok()
        } else {
            None
        };
        let credentials = self.keys.load_credentials().ok();
        let tx = self.bg_tx.clone();
        let pds_url = self.pds_url.clone();

        tokio::spawn(async move {
            // Try session resume first
            if let Some(session) = stored_session {
                let resume_result = if let Some(ref url) = pds_url {
                    MoatAtprotoClient::resume_session_with_pds(
                        &session.did,
                        &session.access_jwt,
                        &session.refresh_jwt,
                        url,
                    )
                    .await
                    .map(|c| c.with_pds_override(url.clone()))
                } else {
                    MoatAtprotoClient::resume_session(
                        &session.did,
                        &session.access_jwt,
                        &session.refresh_jwt,
                    )
                    .await
                };
                if let Ok(client) = resume_result {
                    let (aj, rj) = client
                        .get_session_tokens()
                        .await
                        .unwrap_or((session.access_jwt, session.refresh_jwt));
                    let _ = tx.send(BgEvent::LoggedIn {
                        did: client.did().to_string(),
                        client,
                        access_jwt: aj,
                        refresh_jwt: rj,
                    });
                    return;
                }
            }

            // Fresh login
            if let Some((handle, password)) = credentials {
                let login_result = if let Some(ref url) = pds_url {
                    MoatAtprotoClient::login_with_pds(&handle, &password, url)
                        .await
                        .map(|c| c.with_pds_override(url.clone()))
                } else {
                    MoatAtprotoClient::login(&handle, &password).await
                };
                match login_result {
                    Ok(client) => {
                        let (aj, rj) = client.get_session_tokens().await.unwrap_or_default();
                        let _ = tx.send(BgEvent::LoggedIn {
                            did: client.did().to_string(),
                            client,
                            access_jwt: aj,
                            refresh_jwt: rj,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(BgEvent::LoginFailed(format!("{e}")));
                    }
                }
            } else {
                let _ = tx.send(BgEvent::LoginFailed("No credentials".to_string()));
            }
        });
    }

    /// Spawn the network portion of message polling in a background task.
    pub(crate) fn spawn_poll_messages(&mut self) {
        let client = match self.client.as_ref() {
            Some(c) => c.clone(),
            None => return,
        };
        self.poll_in_flight = true;
        let my_did = client.did().to_string();

        // Collect DIDs and their last rkeys
        let mut dids_to_poll: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, conv) in self.conversations.iter().enumerate() {
            for did in &conv.participant_dids {
                dids_to_poll
                    .entry(did.clone())
                    .or_default()
                    .push(idx);
            }
        }

        // Members are not the whole story: someone who left still has
        // messages on their own PDS that this device may never have asked
        // for. `pending_ex_members` holds them for exactly one sweep after
        // their removal — see MULTI_DEVICE.md, "Catch-Up Across Membership
        // Changes".
        //
        // Which ones this cycle actually asks is captured *now*, before any
        // event is processed. A departure discovered later in this same
        // cycle must not be cleared by it: the fetch already happened, so
        // it would be cleared without ever having been swept.
        let mut swept_ex_members: Vec<(String, String)> = Vec::new();
        for (idx, conv) in self.conversations.iter().enumerate() {
            let pending = self
                .keys
                .load_group_metadata(&conv.id)
                .map(|m| m.pending_ex_members)
                .unwrap_or_default();
            for did in pending {
                dids_to_poll.entry(did.clone()).or_default().push(idx);
                swept_ex_members.push((conv.id.clone(), did));
            }
        }
        self.swept_ex_members = swept_ex_members;
        // Always poll own DID — needed to receive coord-group messages from sibling
        // devices even when there are no user conversations yet.
        {
            let all_conv_indices: Vec<usize> = (0..self.conversations.len()).collect();
            dids_to_poll.entry(my_did).or_insert(all_conv_indices);
        }

        // Watching a DID for invites keeps its own cursor. Sharing the
        // conversation cursor would let a watch fetch move past messages this
        // device cannot read yet — from a group whose Welcome is still on
        // another member's PDS — and joining would never fetch them again.
        let watched: Vec<(String, String, Option<String>)> = self
            .watched_dids
            .iter()
            .filter(|did| !dids_to_poll.contains_key(*did))
            .map(|did| {
                let cursor_key = format!("watch:{did}");
                let last_rkey = self.keys.get_last_rkey(&cursor_key).ok().flatten();
                (did.clone(), cursor_key, last_rkey)
            })
            .collect();

        let dids_with_rkeys: Vec<(String, Vec<usize>, Option<String>)> = dids_to_poll
            .into_iter()
            .map(|(did, indices)| {
                let last_rkey = self.keys.get_last_rkey(&did).ok().flatten();
                (did, indices, last_rkey)
            })
            .collect();

        let tx = self.bg_tx.clone();

        tokio::spawn(async move {
            let mut participant_events = Vec::new();
            let mut new_rkeys = Vec::new();

            for (participant_did, conv_indices, last_rkey) in &dids_with_rkeys {
                if let Ok(events) = client
                    .fetch_events_from_did(participant_did, last_rkey.as_deref())
                    .await {
                    let mut max_rkey: Option<String> = last_rkey.clone();
                    for event in events {
                        if let Some(ref last) = last_rkey {
                            if event.rkey <= *last {
                                continue;
                            }
                        }
                        if max_rkey.as_ref().map_or(true, |m| event.rkey > *m) {
                            max_rkey = Some(event.rkey.clone());
                        }
                        participant_events.push((
                            conv_indices.clone(),
                            event,
                            participant_did.clone(),
                        ));
                    }
                    if let Some(rkey) = max_rkey {
                        new_rkeys.push((participant_did.clone(), rkey));
                    }
                }
            }

            let mut watched_events = Vec::new();
            for (did, cursor_key, last_rkey) in &watched {
                if let Ok(events) = client
                    .fetch_events_from_did(did, last_rkey.as_deref())
                    .await {
                    let mut max_rkey = last_rkey.clone();
                    for event in events {
                        if let Some(ref last) = last_rkey {
                            if event.rkey <= *last {
                                continue;
                            }
                        }
                        if max_rkey.as_ref().map_or(true, |m| event.rkey > *m) {
                            max_rkey = Some(event.rkey.clone());
                        }
                        watched_events.push((did.clone(), event));
                    }
                    if let Some(rkey) = max_rkey {
                        new_rkeys.push((cursor_key.clone(), rkey));
                    }
                }
            }

            let _ = tx.send(BgEvent::PollFetched {
                participant_events,
                watched_events,
                new_rkeys,
            });
        });
    }

    /// Check if device polling should run now.
    pub fn should_poll_devices(&self) -> bool {
        self.client.is_some()
            && self
                .last_device_poll
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true)
    }

    /// True when the ring tick is due (every 30 s, same cadence as device poll).
    pub fn should_do_ring_tick(&self) -> bool {
        self.client.is_some()
            && self
                .last_ring_tick
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true)
    }

    /// Run device polling (async, called from the main loop periodically).
    pub async fn do_device_poll(&mut self) {
        self.last_device_poll = Some(Instant::now());
        if let Err(e) = self.poll_for_new_devices().await {
            self.debug_log.log(&format!("Device poll error: {e}"));
        }
    }

    /// Process a background event. Called from the main loop.
    pub fn handle_bg_event(&mut self, event: BgEvent) {
        match event {
            BgEvent::LoggedIn {
                client,
                did,
                access_jwt,
                refresh_jwt,
            } => {
                self.poll_in_flight = false;
                let _ = self.keys.store_session(&StoredSession {
                    did: did.clone(),
                    access_jwt,
                    refresh_jwt,
                });
                self.client = Some(client.clone());
                self.status_message = None;
                self.load_conversations_sync();

                // Resolve handles for all conversations on login
                for conv in self.conversations.clone() {
                    self.resolve_conversation_handle(&conv);
                }

                // Ensure identity key + stealth address are provisioned.
                // These may be missing if the initial do_login() was interrupted
                // or if auto-login resumed a session before they were published.
                self.ensure_keys_provisioned(&client, &did);

                // Connect to own Drawbridge if configured (async, via BgEvent signal)
                if let Some(ref url) = self.drawbridge_url.clone() {
                    if let Ok(sig_key) = self.keys.load_identity_key() {
                        let _ = self.bg_tx.send(BgEvent::DrawbridgeConnectOwn {
                            url: url.clone(),
                            did,
                            signature_key: sig_key,
                        });
                    }
                }
            }
            BgEvent::LoginFailed(e) => {
                self.poll_in_flight = false;
                self.set_error(format!(
                    "Login failed: {e}\n\nIf you hit rate limits, wait before trying again."
                ));
                self.focus = Focus::Login;
            }
            BgEvent::PollFetched {
                participant_events,
                watched_events,
                new_rkeys,
            } => {
                self.poll_in_flight = false;
                let stats =
                    self.process_poll_results(participant_events, watched_events, new_rkeys);
                // Notify HTTP API waiter (if any).
                if let Some(tx) = self.pending_poll_result.take() {
                    let _ = tx.send(stats);
                }
                // Broadcast SSE poll_complete event.
                if let Some(ref bcast) = self.event_broadcast {
                    let payload = serde_json::json!({
                        "type": "poll_complete",
                    });
                    let _ = bcast.send(payload.to_string());
                }
            }
            BgEvent::PollError(e) => {
                self.poll_in_flight = false;
                self.set_error(format!("Poll error: {e}"));
            }
            BgEvent::SendPublished { uri, conv_id, tag, ciphertext, message_id } => {
                self.debug_log
                    .log(&format!("send_message: published to PDS, uri={}", uri));
                self.tag_map.insert(tag, conv_id.clone());

                let rkey = uri.split('/').next_back().unwrap_or("").to_string();

                // Fix up the "pending" rkey in storage to the real one
                if !rkey.is_empty() {
                    if let Err(e) = self.keys.fixup_pending_rkey_by_message_id(&conv_id, &rkey, message_id.as_deref()) {
                        self.debug_log.log(&format!(
                            "send_message: failed to fixup pending rkey: {e}"
                        ));
                    }
                    // Also fix up in-memory display messages
                    if let Some(dm) = self.messages.iter_mut().rev().find(|m| {
                        m.rkey == "pending" && (message_id.is_none() || m.message_id.as_ref() == message_id.as_ref())
                    }) {
                        dm.rkey = rkey.clone();
                    }
                    // Re-sort display messages by rkey
                    self.messages.sort_by(|a, b| a.rkey.cmp(&b.rkey));
                }

                // Notify Drawbridge about the published event with payload + relay URLs.
                // Include our own DID in the envelope so the relay can use it for
                // PDS verification without storing it on the connection.
                if self.drawbridge.has_own_connection() {
                    let did = self.client.as_ref().map(|c| c.did().to_string()).unwrap_or_default();
                    let drawbridge_urls = self.drawbridge_urls_for_conversation(&conv_id);
                    let _ = self.bg_tx.send(BgEvent::DrawbridgeNotifyEventPosted {
                        did,
                        tag,
                        rkey,
                        payload: ciphertext,
                        drawbridge_urls,
                    });
                }
            }
            BgEvent::SendFailed(e) => {
                self.set_error(format!("Send error: {e}"));
            }
            BgEvent::DrawbridgeNewEvent { tag, rkey, payload } => {
                self.debug_log.log(&format!(
                    "drawbridge: new_event tag={} rkey={} payload={}",
                    hex::encode(&tag),
                    &rkey,
                    if payload.is_some() { "yes" } else { "no" }
                ));

                // Try to decrypt inline payload first
                if let Some(ref ciphertext) = payload {
                    if let Some(conv_id) = self.tag_map.get(&tag).cloned() {
                        let group_id = hex::decode(&conv_id).unwrap_or_default();
                        if let Ok(decrypted) = self.mls.decrypt_event(&group_id, ciphertext) {
                            self.debug_log.log("drawbridge: inline payload decrypted successfully");
                            self.note_tag_seen(&conv_id, &tag);
                            // Process the decrypted event inline — skip PDS fetch
                            self.process_inline_decrypted(&conv_id, &rkey, decrypted);
                            self.save_mls_state().ok();
                        }
                    }
                }

                // No inline payload (or decrypt failed): next regular poll picks it up.
                // The relay no longer includes sender DID in new_event; per-event
                // targeted fetches are not needed since polling is the reliable path.
            }

            BgEvent::DrawbridgeDisconnected { url, reason } => {
                self.drawbridge.clear_connection();
                let delay = self.drawbridge.next_reconnect_delay();
                self.debug_log.log(&format!(
                    "drawbridge: disconnected from {}: {} (reconnecting in {}s)",
                    url, reason, delay.as_secs()
                ));

                // Schedule reconnect after backoff delay
                if let (Some(client), Ok(sig_key)) =
                    (self.client.as_ref(), self.keys.load_identity_key())
                {
                    let did = client.did().to_string();
                    let bg_tx = self.bg_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = bg_tx.send(BgEvent::DrawbridgeConnectOwn {
                            url,
                            did,
                            signature_key: sig_key,
                        });
                    });
                }
            }

            // Async Drawbridge events are handled by handle_bg_event_async
            BgEvent::DrawbridgeConnectOwn { .. } => {}
            BgEvent::DrawbridgeNotifyEventPosted { .. } => {}
            BgEvent::DrawbridgeWatchTags { .. } => {}
            BgEvent::DrawbridgeConfigFetched { did, urls } => {
                self.debug_log.log(&format!(
                    "drawbridge: cached relay config for {}: {} url(s)",
                    &did[..20.min(did.len())],
                    urls.len()
                ));
                self.drawbridge_config_cache.insert(did, drawbridge::CachedDrawbridgeConfig { urls });
            }
            BgEvent::HandleResolved {
                conv_id,
                did,
                handle,
            } => {
                // Update the resolved handle for this DID in the conversation
                if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == conv_id) {
                    if let Some(pos) = conv.participant_dids.iter().position(|d| d == &did) {
                        // Update existing entry
                        if pos < conv.participant_handles.len() {
                            conv.participant_handles[pos] = handle.clone();
                        } else {
                            // Handles vec was shorter — extend to match
                            conv.participant_handles.resize(pos, did.clone());
                            conv.participant_handles.push(handle.clone());
                        }
                    }
                    let _ = self.keys.store_group_metadata(
                        &conv_id,
                        &GroupMetadata {
                            participant_dids: conv.participant_dids.clone(),
                            participant_handles: conv.participant_handles.clone(),
                            kind: GroupKind::User,
                            pending_ex_members: Vec::new(),
                            member_device_ids: Default::default(),
                        },
                    );
                }
            }

            BgEvent::BlobUploaded { blob, preview_text, conv_id } => {
                self.handle_blob_uploaded(blob, preview_text, conv_id);
            }

            BgEvent::BlobFetched { message_id, full_text } => {
                // Update the in-memory DisplayMessage to show full text.
                if let Some(msg) = self.messages.iter_mut().find(|m| m.message_id.as_ref() == Some(&message_id)) {
                    msg.content = full_text;
                }
            }

            BgEvent::BlobFetchFailed { message_id, error } => {
                if let Some(msg) = self
                    .messages
                    .iter_mut()
                    .find(|m| m.message_id.as_ref() == Some(&message_id))
                {
                    msg.content = format!("{} [download failed: {}]", msg.content, error);
                    msg.image_loading = false;
                }
            }

            BgEvent::ImageUploaded { blob, image, pending_message_id, conv_id } => {
                self.handle_image_uploaded(
                    blob,
                    image,
                    pending_message_id,
                    conv_id,
                );
            }

            BgEvent::ImageBlobFetched { message_id, bytes } => {
                if let Ok(img) = image::load_from_memory(&bytes) {
                    let proto = self.picker.new_resize_protocol(img);
                    if let Some(msg) = self
                        .messages
                        .iter_mut()
                        .find(|m| m.message_id.as_ref() == Some(&message_id))
                    {
                        msg.image_proto = Some(ImageProto(proto));
                        msg.image_loading = false;
                    }
                }
            }

            // ── Drawbridge pairing (async side handled by handle_bg_event_async) ──
            BgEvent::DrawbridgeConnectPair { .. }
            | BgEvent::DrawbridgeSendPairBinary { .. }
            | BgEvent::DrawbridgeSendPairOffer { .. }
            | BgEvent::DrawbridgeSendPairJoin { .. }
            | BgEvent::PollForNewDevicesNow
            | BgEvent::RingTickNow
            | BgEvent::PublishRingCommit { .. }
            | BgEvent::PublishRingEvent { .. } => {}

            BgEvent::PairPending => {
                self.debug_log.log("sync: pair offer registered, waiting for joiner");
            }

            BgEvent::PairReady { pair_url, token } => {
                self.debug_log.log(&format!("sync: pair_ready — opening pair WS at {pair_url}"));
                // The rendezvous succeeded — no more resend-on-reconnect needed.
                self.pending_pair_rendezvous_token = None;
                // Build the sync session now so it's ready when PairConnected arrives.
                self.pending_pair_token = Some(token.clone());
                let _ = self.bg_tx.send(BgEvent::DrawbridgeConnectPair {
                    url: pair_url,
                    token,
                });
            }

            BgEvent::PairClosed { session_token, reason } => {
                // A completed round's teardown notice routinely lands after
                // the next round has started. The reconnect-sync path has no
                // `PairingSession`, so fall back to `pending_pair_token`.
                let live_session_token: Option<Vec<u8>> = match self.pairing_session.as_ref() {
                    Some(s) => Some(s.rendezvous_token().to_vec()),
                    None => self.pending_pair_token.clone(),
                };
                if let (Some(closed), Some(live)) =
                    (session_token.as_ref(), live_session_token.as_ref())
                {
                    if closed != live {
                        self.debug_log.log(&format!(
                            "sync: ignoring pair_closed ({reason}) for a superseded session"
                        ));
                        return;
                    }
                }

                self.debug_log.log(&format!("sync: pair WS closed: {reason}"));
                self.drawbridge.clear_pair();
                self.sync_session = None;
                self.pending_pair_token = None;
                self.pairing_sync_keys = None;
                // A transfer cut short must say so. `fail` is a no-op once
                // the session completed, which is the ordinary case: the
                // relay closes the channel right after a successful sync.
                if let Some(session) = self.sync_request.as_mut() {
                    session.fail(moat_core::SyncFailure::ChannelClosed {
                        detail: reason.clone(),
                    });
                }
                // Peer walked away / relay TTL: cancel so `ui_state()`
                // reports why rather than stalling. No-op if terminal.
                if let Some(session) = self.pairing_session.as_mut() {
                    let _ = session.cancel();
                }
            }

            BgEvent::PairConnected => {
                // Two possible occupants of the same pair channel: a live
                // PairingSession (device onboarding — this pairing) or the
                // established-devices reconnect-sync path (start_sync_session,
                // pre-existing). At most one is ever active at a time.
                match self.pairing_is_new_device {
                    Some(true) => {
                        self.debug_log.log("pairing: pair WS paired — sending Enroll");
                        self.start_pairing_enroll();
                    }
                    Some(false) => {
                        self.debug_log
                            .log("pairing: pair WS paired — waiting for Enroll");
                    }
                    None => {
                        self.debug_log.log("sync: pair WS paired — starting sync session");
                        if let Some(session) = self.sync_request.as_mut() {
                            if let Err(e) = session.on_channel_up() {
                                self.debug_log
                                    .log(&format!("sync: channel up on a finished request: {e}"));
                            }
                        }
                        self.start_sync_session();
                    }
                }
            }

            BgEvent::PairFrameReceived { data } => {
                // Three possible occupants of the pair channel: still mid
                // Enroll/Admit/Done (PairingSession), past Done and running
                // history sync under the *same* pairing AEAD (pairing_sync_keys
                // — qr-pairing.md §3.2), or the established-devices
                // reconnect-sync path (ring-MLS `sync_session` alone, no
                // PairingSession involved at all).
                if self.pairing_sync_keys.is_some() {
                    self.process_pairing_sync_frame(data);
                } else if self.pairing_session.as_ref().map(|s| !s.is_done()).unwrap_or(false) {
                    self.handle_pairing_frame(data);
                } else {
                    self.process_sync_frame(data);
                }
            }
        }
    }

    /// MLS-encrypt a long-text event after blob upload succeeded, then publish.
    fn handle_blob_uploaded(
        &mut self,
        blob: UploadedBlob,
        preview_text: String,
        conv_id: String,
    ) {
        let Some(client) = self.client.as_ref() else {
            self.set_error("blob uploaded but client is gone".to_string());
            return;
        };

        let uri = format!("at://{}/{}", client.did(), blob.cid);

        let key_arr: [u8; 32] = match blob.key.try_into() {
            Ok(k) => k,
            Err(_) => {
                self.set_error("blob key has wrong length".to_string());
                return;
            }
        };

        let external = match ExternalBlob::new(
            uri,
            key_arr.to_vec(),
            blob.ciphertext_hash,
            blob.ciphertext_size,
            blob.content_hash,
        ) {
            Ok(e) => e,
            Err(e) => {
                self.set_error(format!("failed to build ExternalBlob: {e}"));
                return;
            }
        };

        let payload = MessagePayload::LongText(LongTextMessage {
            preview_text: preview_text.clone(),
            mime: None,
            external,
        });

        let group_id = match hex::decode(&conv_id) {
            Ok(id) => id,
            Err(e) => {
                self.set_error(format!("invalid conv_id in BlobUploaded: {e}"));
                return;
            }
        };

        let key_bundle = match self.keys.load_identity_key() {
            Ok(k) => k,
            Err(e) => {
                self.set_error(format!("failed to load identity key: {e}"));
                return;
            }
        };

        let current_epoch = self.mls.get_group_epoch(&group_id).ok().flatten().unwrap_or(1);
        // Same reasoning as the image path below: the optimistic row is
        // already stored under this id, and the rkey fix-up on publish
        // matches on it. Looked up before encrypting because
        // `encrypt_event` copies whatever id the event carries.
        let pending_message_id = self
            .messages
            .iter()
            .rev()
            .find(|m| m.is_own && m.content.contains("[long text — uploading…]"))
            .and_then(|m| m.message_id.clone());
        let mut event = Event::message(group_id.clone(), current_epoch, &payload);
        if let Some(id) = &pending_message_id {
            event.message_id = Some(id.clone());
        }

        let encrypted = match self.mls.encrypt_event(&group_id, &key_bundle, &event) {
            Ok(e) => e,
            Err(e) => {
                self.set_error(format!("MLS encrypt failed for long text: {e}"));
                return;
            }
        };

        if let Err(e) = self.save_mls_state() {
            self.debug_log.log(&format!("blob_uploaded: failed to save MLS state: {e}"));
        }
        if let Err(e) = self.keys.store_group_state(&conv_id, &encrypted.new_group_state) {
            self.debug_log.log(&format!("blob_uploaded: failed to store group state: {e}"));
        }

        // Update the pending optimistic message to the real preview.
        let display_content = format!("{preview_text} [long text]");
        if let Some(msg) = self.messages.iter_mut().rev().find(|m| m.is_own && m.content.contains("[long text — uploading…]")) {
            msg.content = display_content.clone();
            if let Some(msg_id) = &msg.message_id {
                let _ = self.keys.append_message(&conv_id, crate::keystore::StoredMessage {
                    rkey: "pending".to_string(),
                    content: display_content,
                    timestamp: msg.timestamp,
                    is_own: true,
                    message_id: Some(msg_id.clone()),
                    sender_did: msg.sender_did.clone(),
                    sender_device: msg.sender_device.clone(),
                    blob_uri: None, blob_key: None, blob_ciphertext_hash: None, blob_ciphertext_size: None, blob_content_hash: None, blob_mime: None, blob_width: None, blob_height: None, blob_thumbhash: None,
                    reactions: Vec::new(),
                });
            }
        }

        // Publish the MLS-encrypted event.
        let client = self.client.as_ref().unwrap().clone();
        let tag = encrypted.tag;
        let ciphertext = encrypted.ciphertext;
        let msg_id = encrypted.message_id.clone();
        let tx = self.bg_tx.clone();
        tokio::spawn(async move {
            match client.publish_event(&tag, &ciphertext, None).await {
                Ok(uri) => {
                    let _ = tx.send(BgEvent::SendPublished { uri, conv_id, tag, ciphertext, message_id: msg_id });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::SendFailed(format!("{e}")));
                }
            }
        });
    }

    /// Handle async BgEvents that require await (called from the main loop).
    pub async fn handle_bg_event_async(&mut self, event: BgEvent) {
        match event {
            BgEvent::DrawbridgeConnectOwn {
                url,
                did,
                signature_key,
            } => {
                self.debug_log.log(&format!(
                    "drawbridge: connecting to own relay at {}",
                    url
                ));
                match self
                    .drawbridge
                    .connect_own(&url, &did, &signature_key)
                    .await
                {
                    Ok(()) => {
                        self.debug_log
                            .log(&format!("drawbridge: connected to own relay at {}", url));
                        self.save_drawbridge_state();

                        // Register all current tags on our own relay
                        self.send_all_watched_tags().await;

                        // Register push token so the relay can suppress FCM while
                        // this WebSocket is live and deliver when we disconnect.
                        {
                            let device_id_hex = hex::encode(self.mls.device_id());
                            let token = format!("moat-cli-{device_id_hex}");
                            let tags: Vec<[u8; 16]> = self.tag_map.keys().copied().collect();
                            if let Err(e) = self.drawbridge.register_push(&device_id_hex, &token, &tags).await {
                                self.debug_log.log(&format!("drawbridge: register_push failed: {e}"));
                            }
                        }

                        // Publish our relay config so partners can discover us
                        if let Some(ref client) = self.client {
                            let client = client.clone();
                            let url = url.clone();
                            tokio::spawn(async move {
                                if let Err(e) = client.publish_drawbridge_config(&url).await {
                                    eprintln!("drawbridge: failed to publish relay config: {e}");
                                }
                            });
                        }

                        // Resend a pairing rendezvous message that hasn't been
                        // acknowledged (`pair_ready`) yet. Covers both a plain
                        // reconnect and the specific race where a `pair_join`
                        // reached the relay before the peer's `pair_offer` had
                        // registered — the relay rejects that with a
                        // connection-fatal "token not found" error (see the
                        // field doc on `pending_pair_rendezvous_token`), so
                        // without this the session would otherwise hang
                        // forever with no retry.
                        if let Some(token) = self.pending_pair_rendezvous_token.clone() {
                            match self.pairing_is_new_device {
                                Some(true) => {
                                    let _ = self
                                        .bg_tx
                                        .send(BgEvent::DrawbridgeSendPairOffer { token });
                                }
                                Some(false) => {
                                    let _ = self
                                        .bg_tx
                                        .send(BgEvent::DrawbridgeSendPairJoin { token });
                                }
                                None => {}
                            }
                        }
                    }
                    Err(e) => {
                        let delay = self.drawbridge.next_reconnect_delay();
                        self.debug_log.log(&format!(
                            "drawbridge: failed to connect to {}: {} (retrying in {}s)",
                            url, e, delay.as_secs()
                        ));
                        let bg_tx = self.bg_tx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = bg_tx.send(BgEvent::DrawbridgeConnectOwn {
                                url,
                                did,
                                signature_key,
                            });
                        });
                    }
                }
            }
            BgEvent::DrawbridgeNotifyEventPosted { did, tag, rkey, payload, drawbridge_urls } => {
                if let Err(e) = self.drawbridge.notify_event_posted(&did, &tag, &rkey, &payload, &drawbridge_urls).await {
                    self.debug_log
                        .log(&format!("drawbridge: event_posted failed: {}", e));
                }
            }
            BgEvent::DrawbridgeWatchTags { tags } => {
                if let Err(e) = self.drawbridge.watch_tags(&tags).await {
                    self.debug_log
                        .log(&format!("drawbridge: watch_tags failed: {}", e));
                }
                // Keep the push registration in sync with the live tag set so
                // FCM is fired for newly-joined conversations even when the
                // device is offline at the time of delivery.
                let device_id_hex = hex::encode(self.mls.device_id());
                let token = format!("moat-cli-{device_id_hex}");
                if let Err(e) = self.drawbridge.register_push(&device_id_hex, &token, &tags).await {
                    self.debug_log
                        .log(&format!("drawbridge: register_push (tag-sync) failed: {e}"));
                }
            }
            BgEvent::DrawbridgeConnectPair { url, token } => {
                self.debug_log.log(&format!("sync: connecting to pair WS at {url}"));
                match self.drawbridge.connect_pair(&url, &token).await {
                    Ok(()) => {
                        self.debug_log.log("sync: pair WS connected, waiting for paired");
                    }
                    Err(e) => {
                        self.debug_log.log(&format!("sync: pair WS connect failed: {e}"));
                        self.sync_session = None;
                        self.pending_pair_token = None;
                        // Transport failure the session never saw — cancel
                        // explicitly so `ui_state()` reports `Failed`.
                        if let Some(session) = self.pairing_session.as_mut() {
                            let _ = session.cancel();
                        }
                        self.pairing_is_new_device = None;
                        self.pending_pair_rendezvous_token = None;
                    }
                }
            }
            BgEvent::DrawbridgeSendPairBinary { data } => {
                if let Err(e) = self.drawbridge.send_pair_binary(data).await {
                    self.debug_log.log(&format!("sync: send_pair_binary failed: {e}"));
                }
            }
            BgEvent::DrawbridgeSendPairOffer { token } => {
                if let Err(e) = self.drawbridge.send_pair_offer(&token).await {
                    self.debug_log.log(&format!("pairing: send_pair_offer failed: {e}"));
                    if let Some(session) = self.pairing_session.as_mut() {
                        let _ = session.cancel();
                    }
                    self.pairing_is_new_device = None;
                    self.pending_pair_rendezvous_token = None;
                }
            }
            BgEvent::DrawbridgeSendPairJoin { token } => {
                if let Err(e) = self.drawbridge.send_pair_join(&token).await {
                    self.debug_log.log(&format!("pairing: send_pair_join failed: {e}"));
                    if let Some(session) = self.pairing_session.as_mut() {
                        let _ = session.cancel();
                    }
                    self.pairing_is_new_device = None;
                    self.pending_pair_rendezvous_token = None;
                }
            }
            BgEvent::PollForNewDevicesNow => {
                if let Err(e) = self.poll_for_new_devices().await {
                    self.debug_log
                        .log(&format!("pairing: poll_for_new_devices failed: {e}"));
                }
            }
            BgEvent::RingTickNow => {
                self.do_ring_tick().await;
            }
            BgEvent::PublishRingCommit { tag, ciphertext } => {
                let Some(client) = self.client.clone() else { return };
                match client.publish_event(&tag, &ciphertext, None).await {
                    Ok(_) => self.debug_log.log("pairing: published ring Add commit"),
                    Err(e) => self
                        .debug_log
                        .log(&format!("pairing: publish ring Add commit failed: {e}")),
                }
            }

            BgEvent::PublishRingEvent { tag, ciphertext } => {
                let Some(client) = self.client.clone() else { return };
                match client.publish_event(&tag, &ciphertext, None).await {
                    Ok(uri) => {
                        self.debug_log.log("sync: published ring message");
                        // `publish_event` hands back the record's AT URI;
                        // the relay verifies against the bare rkey.
                        let rkey = uri.split('/').next_back().unwrap_or("").to_string();
                        // Siblings watch the ring's candidate tags, so the
                        // relay can hand them this event immediately rather
                        // than leaving it for the next poll.
                        if self.drawbridge.has_own_connection() {
                            let did = self
                                .client
                                .as_ref()
                                .map(|c| c.did().to_string())
                                .unwrap_or_default();
                            let _ = self.bg_tx.send(BgEvent::DrawbridgeNotifyEventPosted {
                                did,
                                tag,
                                rkey,
                                payload: ciphertext,
                                drawbridge_urls: Vec::new(),
                            });
                        }
                    }
                    Err(e) => {
                        self.debug_log
                            .log(&format!("sync: publish ring message failed: {e}"));
                        if let Some(session) = self.sync_request.as_mut() {
                            session.fail(moat_core::SyncFailure::PublishFailed {
                                detail: e.to_string(),
                            });
                        }
                    }
                }
            }
            _ => {} // Non-async events handled by handle_bg_event
        }
    }

    /// Spawn an immediate targeted fetch for a specific DID (triggered by Drawbridge notification).
    /// Spawn an async task to fetch, decrypt, and cache the blob for a received
    /// `LongText` message. When done, sends `BgEvent::BlobFetched` or
    /// `BgEvent::BlobFetchFailed` with the `message_id` for in-place UI update.
    fn spawn_blob_fetch_long_text(
        &mut self,
        external: &moat_core::ExternalBlob,
        message_id: Option<Vec<u8>>,
    ) {
        let message_id = match message_id {
            Some(id) => id,
            None => return, // no ID to update — skip
        };

        // Check disk cache first.
        if let Some(cached) = self.blob_cache.get(&external.content_hash) {
            if let Ok(text) = String::from_utf8(cached) {
                let _ = self.bg_tx.send(BgEvent::BlobFetched {
                    message_id,
                    full_text: text,
                });
                return;
            }
        }

        let Some(client) = self.client.as_ref() else { return };

        // Parse `at://{did}/{cid}` URI.
        let uri = external.uri.clone();
        let (did, cid) = match uri.strip_prefix("at://").and_then(|s| {
            let pos = s.find('/')?;
            Some((s[..pos].to_string(), s[pos + 1..].to_string()))
        }) {
            Some(pair) => pair,
            None => {
                self.debug_log.log(&format!("blob_fetch: invalid URI: {}", uri));
                return;
            }
        };

        let key: [u8; 32] = match external.key.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => {
                self.debug_log.log("blob_fetch: blob key has wrong length");
                return;
            }
        };
        let ciphertext_hash = external.ciphertext_hash.clone();
        let content_hash = external.content_hash.clone();

        let client = client.clone();
        let tx = self.bg_tx.clone();
        let blob_cache_dir = self.blob_cache.dir.clone();

        tokio::spawn(async move {
            let blob = match client.fetch_blob(&did, &cid).await {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(BgEvent::BlobFetchFailed {
                        message_id,
                        error: e.to_string(),
                    });
                    return;
                }
            };

            match blob_decrypt(&blob, &key, &ciphertext_hash, &content_hash) {
                Ok(plaintext) => {
                    // Cache to disk.
                    let cache = BlobCache { dir: blob_cache_dir };
                    let _ = cache.put(&content_hash, &plaintext);

                    match String::from_utf8(plaintext) {
                        Ok(text) => {
                            let _ = tx.send(BgEvent::BlobFetched { message_id, full_text: text });
                        }
                        Err(e) => {
                            let _ = tx.send(BgEvent::BlobFetchFailed {
                                message_id,
                                error: format!("blob is not valid UTF-8: {e}"),
                            });
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::BlobFetchFailed {
                        message_id,
                        error: e.to_string(),
                    });
                }
            }
        });
    }

    /// Process and upload an image, then MLS-encrypt and publish an `Image` event.
    /// Core image send logic: takes already-loaded raw image bytes, spawns the
    /// processing/upload/publish pipeline in the background.
    fn send_image_bytes_nonblocking(&mut self, bytes: Vec<u8>) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        let conv_idx = self.active_conversation.ok_or(AppError::NoConversation)?;
        let conv_id = self.conversations[conv_idx].id.clone();

        // Generate a temporary ID to match the optimistic DisplayMessage.
        let pending_message_id: Vec<u8> = {
            use rand::RngCore;
            let mut id = vec![0u8; 16];
            rand::thread_rng().fill_bytes(&mut id);
            id
        };

        // Optimistic UI.
        let timestamp = chrono::Utc::now();
        let my_did = self.client.as_ref().unwrap().did().to_string();
        let device_name = self.keys.get_or_create_device_name().ok();
        self.messages.push(DisplayMessage {
            from: "You".to_string(),
            content: "[image — processing…]".to_string(),
            timestamp,
            is_own: true,
            sender_did: Some(my_did.clone()),
            sender_device: device_name.clone(),
            message_id: Some(pending_message_id.clone()),
            reactions: vec![],
            image_proto: None,
            image_loading: true,
            rkey: "pending".to_string(),
        });

        // Persist the placeholder so the message survives a restart.
        let stored_msg = crate::keystore::StoredMessage {
            rkey: "pending".to_string(),
            content: "[image — processing…]".to_string(),
            timestamp,
            is_own: true,
            message_id: Some(pending_message_id.clone()),
            sender_did: Some(my_did),
            sender_device: device_name,
            blob_uri: None, blob_key: None, blob_ciphertext_hash: None,
            blob_ciphertext_size: None, blob_content_hash: None, blob_mime: None,
            blob_width: None, blob_height: None, blob_thumbhash: None,
            reactions: Vec::new(),
        };
        if let Err(e) = self.keys.append_message(&conv_id, stored_msg) {
            self.debug_log
                .log(&format!("send_image: failed to store locally: {e}"));
        }

        self.input_buffer.clear();
        self.cursor_position = 0;

        let client = self.client.as_ref().unwrap().clone();
        let tx = self.bg_tx.clone();

        tokio::spawn(async move {
            // Image processing runs on the blocking thread pool.
            let result = tokio::task::spawn_blocking(move || {
                image_processing::process_image_from_bytes(&bytes)
            })
            .await;

            let processed = match result {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    let _ = tx.send(BgEvent::SendFailed(format!("image processing failed: {e}")));
                    return;
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::SendFailed(format!("image task panicked: {e}")));
                    return;
                }
            };
            let (image_bytes, width, height, thumbhash, mime) = (
                processed.bytes,
                processed.width,
                processed.height,
                processed.thumbhash,
                processed.mime,
            );

            // Encrypt blob (fast, CPU-only).
            let encrypted = match moat_core::blob_encrypt(&image_bytes) {
                Ok(r) => r,
                Err(e) => {
                    let _ =
                        tx.send(BgEvent::SendFailed(format!("blob encrypt failed: {e}")));
                    return;
                }
            };
            let ciphertext_size = encrypted.blob.len() as u64;

            // Upload blob to PDS.
            let cid = match client.upload_blob(&encrypted.blob).await {
                Ok(cid) => cid,
                Err(e) => {
                    let _ = tx.send(BgEvent::SendFailed(format!("blob upload failed: {e}")));
                    return;
                }
            };

            let _ = tx.send(BgEvent::ImageUploaded {
                blob: UploadedBlob {
                    cid,
                    key: encrypted.key.to_vec(),
                    ciphertext_hash: encrypted.ciphertext_hash,
                    ciphertext_size,
                    content_hash: encrypted.content_hash,
                },
                image: ImageMeta { width, height, thumbhash, mime },
                pending_message_id,
                conv_id,
            });
        });

        Ok(())
    }

    /// TUI entry point: read the file at `path` then call [`send_image_bytes_nonblocking`].
    fn send_image_nonblocking(&mut self, path: &str) -> Result<()> {
        let expanded = image_processing::expand_tilde(path);
        let bytes = std::fs::read(&expanded)
            .map_err(|e| AppError::Other(format!("Cannot read {}: {}", expanded, e)))?;
        self.send_image_bytes_nonblocking(bytes)
    }

    /// MLS-encrypt an image event after blob upload succeeded, then publish.
    fn handle_image_uploaded(
        &mut self,
        blob: UploadedBlob,
        image: ImageMeta,
        pending_message_id: Vec<u8>,
        conv_id: String,
    ) {
        let UploadedBlob { cid, key, ciphertext_hash, ciphertext_size, content_hash } = blob;
        let ImageMeta { width, height, thumbhash, mime } = image;

        let Some(client) = self.client.as_ref() else {
            self.set_error("image uploaded but client is gone".to_string());
            return;
        };

        let uri = format!("at://{}/{}", client.did(), cid);

        let key_arr: [u8; 32] = match key.try_into() {
            Ok(k) => k,
            Err(_) => {
                self.set_error("image blob key has wrong length".to_string());
                return;
            }
        };

        let external = match ExternalBlob::new(
            uri,
            key_arr.to_vec(),
            ciphertext_hash.clone(),
            ciphertext_size,
            content_hash.clone(),
        ) {
            Ok(e) => e,
            Err(e) => {
                self.set_error(format!("failed to build ExternalBlob for image: {e}"));
                return;
            }
        };

        let payload = MessagePayload::Image(MediaMessage {
            preview_thumbhash: thumbhash.clone(),
            width: Some(width),
            height: Some(height),
            mime: Some(mime.clone()),
            external,
        });

        let group_id = match hex::decode(&conv_id) {
            Ok(id) => id,
            Err(e) => {
                self.set_error(format!("invalid conv_id in ImageUploaded: {e}"));
                return;
            }
        };

        let key_bundle = match self.keys.load_identity_key() {
            Ok(k) => k,
            Err(e) => {
                self.set_error(format!("failed to load identity key for image: {e}"));
                return;
            }
        };

        let current_epoch = self.mls.get_group_epoch(&group_id).ok().flatten().unwrap_or(1);
        let mut event = Event::message(group_id.clone(), current_epoch, &payload);
        // Publish under the id the optimistic row already carries, rather
        // than the fresh one `Event::message` mints. That id is the
        // message's identity from the moment the user hit send, and it is
        // what `fixup_pending_rkey_by_message_id` matches on when the
        // publish returns. Mint a new one and the match fails, the row
        // keeps its "pending" rkey forever, and every sync skips it —
        // meaning a device never sends anyone the images it took.
        event.message_id = Some(pending_message_id.clone());

        let encrypted = match self.mls.encrypt_event(&group_id, &key_bundle, &event) {
            Ok(e) => e,
            Err(e) => {
                self.set_error(format!("MLS encrypt failed for image: {e}"));
                return;
            }
        };

        if let Err(e) = self.save_mls_state() {
            self.debug_log
                .log(&format!("image_uploaded: failed to save MLS state: {e}"));
        }
        if let Err(e) = self.keys.store_group_state(&conv_id, &encrypted.new_group_state) {
            self.debug_log
                .log(&format!("image_uploaded: failed to store group state: {e}"));
        }

        // Decode ThumbHash for placeholder rendering and update the pending message.
        let display_content = format!("[image {mime} {width}×{height}]");
        if let Some(msg) = self
            .messages
            .iter_mut()
            .rev()
            .find(|m| m.message_id.as_ref() == Some(&pending_message_id))
        {
            msg.content = display_content.clone();
            msg.image_loading = false;
            // Update the locally stored entry with the final display string and
            // full blob metadata so the /image endpoint can fetch and decrypt later.
            let blob_uri_str = format!("at://{}/{}", client.did(), cid);
            let _ = self.keys.append_message(
                &conv_id,
                crate::keystore::StoredMessage {
                    rkey: "pending".to_string(),
                    content: display_content,
                    timestamp: msg.timestamp,
                    is_own: true,
                    message_id: Some(pending_message_id.clone()),
                    sender_did: msg.sender_did.clone(),
                    sender_device: msg.sender_device.clone(),
                    blob_uri: Some(blob_uri_str),
                    blob_key: Some(key_arr.to_vec()),
                    blob_ciphertext_hash: Some(ciphertext_hash),
                    blob_ciphertext_size: Some(ciphertext_size),
                    blob_content_hash: Some(content_hash),
                    blob_mime: Some(mime.clone()),
                    blob_width: Some(width),
                    blob_height: Some(height),
                    blob_thumbhash: Some(thumbhash.clone()),
                    reactions: Vec::new(),
                },
            );
            if let Some(thumb_img) = image_processing::decode_thumbhash(&thumbhash) {
                msg.image_proto = Some(ImageProto(self.picker.new_resize_protocol(thumb_img)));
            }
        }

        // Publish the MLS-encrypted event, including the blob ref so the PDS
        // promotes the uploaded blob from temporary to permanent storage.
        let blob_ref = BlobRef::new(&cid, ciphertext_size);
        let client = self.client.as_ref().unwrap().clone();
        let tag = encrypted.tag;
        let ciphertext = encrypted.ciphertext;
        let msg_id = encrypted.message_id.clone();
        let tx = self.bg_tx.clone();
        tokio::spawn(async move {
            match client.publish_event(&tag, &ciphertext, Some(blob_ref)).await {
                Ok(uri) => {
                    let _ = tx.send(BgEvent::SendPublished { uri, conv_id, tag, ciphertext, message_id: msg_id });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::SendFailed(format!("{e}")));
                }
            }
        });
    }

    /// Fetch an image blob for a received `Image` message.
    fn spawn_blob_fetch_image(
        &mut self,
        external: &moat_core::ExternalBlob,
        message_id: Option<Vec<u8>>,
    ) {
        let message_id = match message_id {
            Some(id) => id,
            None => return,
        };

        // Check disk cache first.
        if let Some(cached) = self.blob_cache.get(&external.content_hash) {
            let tx = self.bg_tx.clone();
            let _ = tx.send(BgEvent::ImageBlobFetched {
                message_id,
                bytes: cached,
            });
            return;
        }

        let Some(client) = self.client.as_ref() else {
            return;
        };

        let uri = external.uri.clone();
        let (did, cid) = match uri.strip_prefix("at://").and_then(|s| {
            let pos = s.find('/')?;
            Some((s[..pos].to_string(), s[pos + 1..].to_string()))
        }) {
            Some(pair) => pair,
            None => {
                self.debug_log
                    .log(&format!("image blob fetch: invalid URI: {}", uri));
                return;
            }
        };

        let key: [u8; 32] = match external.key.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => {
                self.debug_log.log("image blob fetch: key has wrong length");
                return;
            }
        };
        let ciphertext_hash = external.ciphertext_hash.clone();
        let content_hash = external.content_hash.clone();

        let client = client.clone();
        let tx = self.bg_tx.clone();
        let blob_cache_dir = self.blob_cache.dir.clone();

        tokio::spawn(async move {
            let blob = match client.fetch_blob(&did, &cid).await {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(BgEvent::BlobFetchFailed {
                        message_id,
                        error: e.to_string(),
                    });
                    return;
                }
            };

            match blob_decrypt(&blob, &key, &ciphertext_hash, &content_hash) {
                Ok(plaintext) => {
                    let cache = BlobCache { dir: blob_cache_dir };
                    let _ = cache.put(&content_hash, &plaintext);
                    let _ = tx.send(BgEvent::ImageBlobFetched {
                        message_id,
                        bytes: plaintext,
                    });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::BlobFetchFailed {
                        message_id,
                        error: e.to_string(),
                    });
                }
            }
        });
    }

    /// Save Drawbridge state to disk.
    fn save_drawbridge_state(&self) {
        let state = self.drawbridge.export_state(&self.drawbridge_url);
        if let Err(e) = self.keys.store_drawbridge_state(&state) {
            self.debug_log
                .log(&format!("drawbridge: failed to save state: {}", e));
        }
    }

    /// Collect all watched tags and send to own Drawbridge.
    async fn send_all_watched_tags(&mut self) {
        let tags: Vec<[u8; 16]> = self.tag_map.keys().copied().collect();
        if !tags.is_empty() {
            let _ = self.bg_tx.send(BgEvent::DrawbridgeWatchTags { tags });
        }
    }

    /// Update watched tags on own Drawbridge after epoch change.
    /// Called after epoch changes (Commit events) when tags are regenerated.
    fn schedule_watch_tags_update(&self) {
        if !self.drawbridge.has_own_connection() {
            return;
        }
        let tags: Vec<[u8; 16]> = self.tag_map.keys().copied().collect();
        if !tags.is_empty() {
            let _ = self.bg_tx.send(BgEvent::DrawbridgeWatchTags { tags });
        }
    }

    /// Collect relay URLs for all partner DIDs in a conversation.
    fn drawbridge_urls_for_conversation(&self, conv_id: &str) -> Vec<String> {
        let conv = match self.conversations.iter().find(|c| c.id == *conv_id) {
            Some(c) => c,
            None => return Vec::new(),
        };

        let mut urls = Vec::new();
        for did in &conv.participant_dids {
            if let Some(config) = self.drawbridge_config_cache.get(did) {
                for url in &config.urls {
                    if !urls.contains(url) {
                        urls.push(url.clone());
                    }
                }
            }
        }
        urls
    }

    /// Fetch relay configs for all partner DIDs in a conversation (background).
    fn fetch_partner_drawbridge_configs(&self, conv_id: &str) {
        let conv = match self.conversations.iter().find(|c| c.id == *conv_id) {
            Some(c) => c,
            None => return,
        };

        let client = match self.client.as_ref() {
            Some(c) => c.clone(),
            None => return,
        };

        for did in &conv.participant_dids {
            let did = did.clone();
            let client = client.clone();
            let tx = self.bg_tx.clone();
            tokio::spawn(async move {
                if let Ok(Some(config)) = client.fetch_drawbridge_config(&did).await {
                    let urls: Vec<String> = config.drawbridges.iter().map(|r| r.url.clone()).collect();
                    // Send back to main loop for caching
                    let _ = tx.send(BgEvent::DrawbridgeConfigFetched {
                        did,
                        urls,
                    });
                }
            });
        }
    }

    /// Process a decrypted event received inline via Drawbridge payload.
    fn process_inline_decrypted(&mut self, conv_id: &str, rkey: &str, outcome: moat_core::DecryptOutcome) {
        let decrypted = outcome.into_result();
        let conv_idx = self.conversations.iter().position(|c| c.id == *conv_id);
        let my_did = self.client.as_ref().map(|c| c.did().to_string()).unwrap_or_default();

        match decrypted.event.kind {
            EventKind::Message(_) => {
                let parsed = decrypted.event.parse_message_payload();
                let content = parsed
                    .as_ref()
                    .map(render_message_preview)
                    .unwrap_or_else(|| String::from_utf8_lossy(&decrypted.event.payload).to_string());
                let (sender_did, sender_device) = decrypted
                    .sender
                    .map(|s| (Some(s.did), Some(s.device_name)))
                    .unwrap_or((None, None));
                let is_own = sender_did.as_ref() == Some(&my_did);
                let timestamp = chrono::Utc::now();

                // Persist received message locally
                let stored_msg = crate::keystore::StoredMessage {
                    rkey: rkey.to_string(),
                    content: content.clone(),
                    timestamp,
                    is_own,
                    message_id: decrypted.event.message_id.clone(),
                    sender_did: sender_did.clone(),
                    sender_device: sender_device.clone(),
                    blob_uri: None, blob_key: None, blob_ciphertext_hash: None, blob_ciphertext_size: None, blob_content_hash: None, blob_mime: None, blob_width: None, blob_height: None, blob_thumbhash: None,
                    reactions: Vec::new(),
                };
                match self.keys.append_message(conv_id, stored_msg) {
                    Ok(false) => {
                        // Duplicate rkey — already stored
                        self.keys.store_group_state(conv_id, &decrypted.new_group_state).ok();
                        return;
                    }
                    Err(e) => {
                        self.debug_log
                            .log(&format!("drawbridge: failed to store message: {}", e));
                    }
                    Ok(true) => {}
                }

                // Update display
                if self.active_conversation == conv_idx {
                    let dm = DisplayMessage {
                        from: sender_did.as_deref().unwrap_or("Unknown").to_string(),
                        content,
                        timestamp,
                        is_own,
                        sender_did,
                        sender_device,
                        message_id: decrypted.event.message_id.clone(),
                        reactions: vec![],
                        image_proto: None,
                        image_loading: false,
                        rkey: rkey.to_string(),
                    };
                    let pos = self
                        .messages
                        .partition_point(|m| m.rkey <= dm.rkey);
                    self.messages.insert(pos, dm);
                } else if let Some(idx) = conv_idx {
                    if let Some(conv) = self.conversations.get_mut(idx) {
                        conv.unread += 1;
                    }
                }

                // Store group state update
                self.keys.store_group_state(conv_id, &decrypted.new_group_state).ok();
            }
            EventKind::Control(ControlKind::Commit) => {
                // Epoch advanced — regenerate candidate tags
                if let Some(idx) = conv_idx {
                    let group_id = hex::decode(conv_id).unwrap_or_default();
                    self.register_group_tags(conv_id, &group_id);
                    self.conversations[idx].current_epoch += 1;
                }
                self.keys.store_group_state(conv_id, &decrypted.new_group_state).ok();
            }
            _ => {
                // Other event types — store state update, next poll handles display
                self.keys.store_group_state(conv_id, &decrypted.new_group_state).ok();
            }
        }
    }

    /// Spawn background handle resolution for a single conversation.
    fn resolve_conversation_handle(&self, conv: &Conversation) {
        let client = match self.client.as_ref() {
            Some(c) => c.clone(),
            None => return,
        };
        if conv.participant_dids.is_empty() {
            return;
        }
        let tx = self.bg_tx.clone();
        let did = conv.participant_dids[0].clone();
        let conv_id = conv.id.clone();
        tokio::spawn(async move {
            if let Ok(handle) = client.resolve_handle(&did).await {
                let _ = tx.send(BgEvent::HandleResolved {
                    conv_id,
                    did,
                    handle,
                });
            }
        });
    }

    /// Synchronous version of load_conversations (no network calls).
    fn load_conversations_sync(&mut self) {
        // Restore watched DIDs from disk so invite polling survives restarts.
        match self.keys.load_watched_dids() {
            Ok(dids) => self.watched_dids = dids,
            Err(e) => self.debug_log.log(&format!("load: failed to load watched DIDs: {e}")),
        }

        let group_ids = match self.keys.list_groups() {
            Ok(ids) => ids,
            Err(e) => {
                self.set_error(format!("Failed to load conversations: {e}"));
                return;
            }
        };

        self.conversations.clear();
        for group_id in group_ids {
            let mut meta = self.keys.load_group_metadata(&group_id).unwrap_or_default();
            let group_id_bytes = hex::decode(&group_id).unwrap_or_default();

            // Populate member_device_ids from current MLS membership.
            // This fills the map on first run (migration) and keeps it
            // current for members still in the group.
            if let Ok(members) = self.mls.get_group_members(&group_id_bytes) {
                let mut changed = false;
                for (_leaf_idx, cred) in &members {
                    if let Some(c) = cred {
                        let did = c.did().to_string();
                        let dev = c.device_id().to_vec();
                        if meta.member_device_ids.get(&did) != Some(&dev) {
                            meta.member_device_ids.insert(did, dev);
                            changed = true;
                        }
                    }
                }
                if changed {
                    let _ = self.keys.store_group_metadata(&group_id, &meta);
                }
            }

            // Ring and DeviceCoord groups are infrastructure — hide from the conversation list
            // but still populate their candidate tags for event routing.
            if meta.kind != GroupKind::User {
                self.populate_candidate_tags(&group_id, &group_id_bytes);
                continue;
            }
            let (participant_dids, participant_handles) =
                (meta.participant_dids, meta.participant_handles);

            // One lookup answers both questions: a group with no local
            // MLS state is one we hold history for but are not yet in.
            let local_epoch = self.mls.get_group_epoch(&group_id_bytes).ok().flatten();
            let is_member = local_epoch.is_some();
            let current_epoch = local_epoch.unwrap_or(1);

            self.populate_candidate_tags(&group_id, &group_id_bytes);

            self.conversations.push(Conversation {
                id: group_id,
                name: None,
                participant_dids,
                participant_handles,
                current_epoch,
                unread: 0,
                is_member,
            });
        }
    }

    /// Populate the tag_map with candidate tags for all members of a conversation.
    ///
    /// Generates tags for each member device using the GAP_LIMIT window.
    /// Tags map back to the hex-encoded group_id for routing.
    fn populate_candidate_tags(&mut self, conv_id: &str, group_id: &[u8]) {
        let extras = self.extra_members_for_tags(conv_id);
        let extra_refs: Vec<(&str, &[u8; 16])> = extras
            .iter()
            .filter_map(|(did, dev)| {
                <&[u8; 16]>::try_from(dev.as_slice())
                    .ok()
                    .map(|d| (did.as_str(), d))
            })
            .collect();
        match self.mls.populate_candidate_tags(group_id, &extra_refs) {
            Ok(tags) => {
                for tag in tags {
                    self.tag_map.insert(tag, conv_id.to_string());
                }
            }
            Err(e) => {
                self.debug_log
                    .log(&format!("populate_tags: failed for {}: {}", conv_id, e));
            }
        }
    }

    /// Populate a group's candidate tags and bring the Drawbridge watch list
    /// up to date with them.
    fn register_group_tags(&mut self, conv_id: &str, group_id: &[u8]) {
        self.populate_candidate_tags(conv_id, group_id);
        self.schedule_watch_tags_update();
    }

    /// Advance the scanning window for a tag that matched `conv_id`, and
    /// register whatever candidate tags that newly covers.
    fn note_tag_seen(&mut self, conv_id: &str, tag: &[u8; 16]) {
        let added = self.mls.advance_scan_window(tag);
        if added.is_empty() {
            return;
        }
        for t in added {
            self.tag_map.insert(t, conv_id.to_string());
        }
        self.schedule_watch_tags_update();
    }

    /// Collect (DID, device_id) pairs for pending ex-members whose device_ids
    /// are known from the persisted member_device_ids map.
    fn extra_members_for_tags(&self, conv_id: &str) -> Vec<(String, Vec<u8>)> {
        let meta = match self.keys.load_group_metadata(conv_id) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        meta.pending_ex_members
            .iter()
            .filter_map(|did| {
                meta.member_device_ids
                    .get(did)
                    .map(|dev| (did.clone(), dev.clone()))
            })
            .collect()
    }

    /// Process poll results on the main thread (decrypt, update state).
    fn process_poll_results(
        &mut self,
        participant_events: Vec<(Vec<usize>, moat_atproto::EventRecord, String)>,
        mut watched_events: Vec<(String, moat_atproto::EventRecord)>,
        new_rkeys: Vec<(String, String)>,
    ) -> PollStats {
        let conv_count_before = self.conversations.len();
        let mut new_messages: usize = 0;
        let my_did = self
            .client
            .as_ref()
            .map(|c| c.did().to_string())
            .unwrap_or_default();

        // Combine new events with previously unprocessed cached events.
        // Sort by rkey so events are processed in chronological order.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cached_count = self.unprocessed_events.len();
        let mut all_events = std::mem::take(&mut self.unprocessed_events);
        let new_count = participant_events.len();
        all_events.extend(participant_events.into_iter().map(|(conv_indices, record, source_did)| {
            crate::retry_buffer::UnprocessedEvent {
                conv_indices,
                record,
                source_did,
                first_seen_ms: now_ms,
                attempts: 0,
            }
        }));
        all_events.sort_by(|a, b| a.record.rkey.cmp(&b.record.rkey));

        if !all_events.is_empty() {
            self.debug_log.log(&format!(
                "poll: processing {} events ({} new, {} cached)",
                all_events.len(),
                new_count,
                cached_count,
            ));
        }

        // Process events in a loop: commits may advance epochs and unlock
        // previously unprocessable events (new tags or new decryption keys).
        loop {
            let mut made_progress = false;
            let mut still_unprocessed = Vec::new();

            for event in all_events {
                let event_record = &event.record;
                let tag_hex: String =
                    event_record.tag.iter().map(|b| format!("{b:02x}")).collect();

                if self.tag_map.contains_key(&event_record.tag) {
                    self.debug_log.log(&format!(
                        "poll: tag matched: {} rkey={}",
                        tag_hex, event_record.rkey
                    ));
                    match self.process_matched_event(&event.conv_indices, event_record, &my_did) {
                        Ok(true) => {
                            new_messages += 1;
                            made_progress = true;
                        }
                        Ok(false) => {
                            made_progress = true;
                        }
                        // This device's own event, or one from an epoch
                        // already left: no later event can make it decrypt.
                        Err(e) if e.is_permanent() => {}
                        Err(_) => {
                            still_unprocessed.push(event);
                        }
                    }
                } else {
                    // Unknown tag — try as welcome
                    if self.try_process_welcome_sync(
                        &event_record.ciphertext,
                        &event_record.author_did,
                        event_record.tag,
                    ) {
                        made_progress = true;
                    } else {
                        // Neither tag match nor welcome — cache for retry,
                        // unless it is on our own PDS: a stealth payload this
                        // device published never decrypts here, and would be
                        // retried forever.
                        if event.source_did != my_did {
                            still_unprocessed.push(event);
                        }
                    }
                }
            }

            all_events = still_unprocessed;
            if !made_progress {
                break;
            }
        }

        // One more cycle failed for whatever is left; keep only what is still
        // worth retrying on the next poll.
        let before_expiry = all_events.len();
        all_events.retain_mut(|e| {
            e.attempts = e.attempts.saturating_add(1);
            moat_core::keep_for_retry(e.first_seen_ms, e.attempts, now_ms)
        });
        let expired = before_expiry - all_events.len();
        if expired > 0 {
            self.debug_log.log(&format!(
                "poll: stopped retrying {expired} event(s) that never became readable",
            ));
        }
        self.unprocessed_events = all_events;

        // Sort watched events by rkey (ascending) so Welcomes are processed
        // before derived-tag events.
        watched_events.sort_by(|a, b| a.1.rkey.cmp(&b.1.rkey));

        if !watched_events.is_empty() {
            self.debug_log.log(&format!(
                "poll: processing {} watched events",
                watched_events.len(),
            ));
        }

        let mut reprocess = Vec::new();
        for (did, event_record) in watched_events {
            let tag_hex: String = event_record.tag.iter().map(|b| format!("{b:02x}")).collect();
            if self.tag_map.contains_key(&event_record.tag) {
                // Tag matched a known conversation — decrypt instead of trying as Welcome.
                let conv_indices: Vec<usize> = self
                    .conversations
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.participant_dids.contains(&did))
                    .map(|(i, _)| i)
                    .collect();
                if !conv_indices.is_empty() {
                    reprocess.push((conv_indices, event_record, did));
                }
                continue;
            }
            self.debug_log.log(&format!(
                "poll: watched tag {} rkey={} from {}, trying as welcome",
                tag_hex,
                event_record.rkey,
                &event_record.author_did[..20.min(event_record.author_did.len())]
            ));
            if self.try_process_welcome_sync(
                &event_record.ciphertext,
                &event_record.author_did,
                event_record.tag,
            ) {
                self.watched_dids.remove(&did);
                let _ = self.keys.store_watched_dids(&self.watched_dids);
            }
        }
        // Decrypt watched events that matched the tag_map (e.g. events
        // arriving in the same batch as the Welcome that created the conversation).
        for (conv_indices, event_record, _did) in reprocess {
            if let Ok(true) = self.process_matched_event(&conv_indices, &event_record, &my_did) { new_messages += 1; }
        }

        // Save MLS state if modified
        if self.mls.has_pending_changes() {
            if let Err(e) = self.save_mls_state() {
                self.debug_log
                    .log(&format!("poll: failed to save MLS state: {}", e));
            }
        }

        // Persist rkeys
        for (did, rkey) in new_rkeys {
            if let Err(e) = self.keys.set_last_rkey(&did, &rkey) {
                self.debug_log.log(&format!(
                    "poll: failed to save rkey for {}: {}",
                    &did[..20.min(did.len())],
                    e
                ));
            }
        }

        // Persist unprocessed events so they survive a restart. Without
        // this the cursor advances past them and they are lost.
        if let Err(e) = self.keys.store_unprocessed_events(&self.unprocessed_events) {
            self.debug_log.log(&format!(
                "poll: failed to persist unprocessed events: {e}",
            ));
        }

        // The ex-members this cycle asked for events have now been swept:
        // their PDS was fetched after they left, so everything they could
        // ever have published to the group has been seen. Stop asking.
        //
        // Only the DIDs captured at fetch time are cleared. Someone whose
        // departure was discovered while processing *these* events is not
        // among them, and stays pending for the next cycle — which is the
        // cycle that will actually fetch from them.
        for (conv_id, did) in std::mem::take(&mut self.swept_ex_members) {
            if let Ok(mut meta) = self.keys.load_group_metadata(&conv_id) {
                if let Some(pos) = meta.pending_ex_members.iter().position(|d| *d == did) {
                    meta.pending_ex_members.remove(pos);
                    let _ = self.keys.store_group_metadata(&conv_id, &meta);
                    self.debug_log
                        .log(&format!("poll: swept {did} for {conv_id}; no longer polling them"));
                }
            }
        }

        PollStats {
            new_messages,
            new_conversations: self.conversations.len().saturating_sub(conv_count_before),
        }
    }

    /// Decrypt and handle a single event whose tag matched the tag_map.
    /// Returns `Ok(true)` if a new message was stored, `Ok(false)` if
    /// processed successfully but no message (commit/reaction), or the
    /// decryption error — [`moat_core::Error::is_permanent`] tells the caller
    /// whether keeping the event for retry can help.
    fn process_matched_event(
        &mut self,
        conv_indices: &[usize],
        event_record: &moat_atproto::EventRecord,
        my_did: &str,
    ) -> std::result::Result<bool, moat_core::Error> {
        let conv_id = match self.tag_map.get(&event_record.tag).cloned() {
            Some(id) => id,
            None => return Ok(false),
        };
        let group_id = match hex::decode(&conv_id) {
            Ok(id) => id,
            Err(_) => return Ok(false),
        };

        let mut msg_stored = false;
        match self.mls.decrypt_event(&group_id, &event_record.ciphertext) {
            Ok(outcome) => {
                self.note_tag_seen(&conv_id, &event_record.tag);
                for w in outcome.warnings() {
                    self.debug_log
                        .log(&format!("poll: transcript warning: {}", w));
                }
                let decrypted = outcome.into_result();

                if let Err(e) = self
                    .keys
                    .store_group_state(&conv_id, &decrypted.new_group_state)
                {
                    self.debug_log
                        .log(&format!("poll: failed to store group state: {}", e));
                }

                let conv_idx = conv_indices.first().copied();

                match decrypted.event.kind {
                    EventKind::Message(_) => {
                        let parsed = decrypted.event.parse_message_payload();
                        let content = parsed
                            .as_ref()
                            .map(render_message_preview)
                            .unwrap_or_else(|| "(invalid message payload)".to_string());
                        let (sender_did, sender_device) = decrypted
                            .sender
                            .map(|s| (Some(s.did), Some(s.device_name)))
                            .unwrap_or((None, None));

                        let is_own =
                            sender_did.as_ref().is_some_and(|did| did == my_did);

                        // Extract ExternalBlob metadata for image messages (for HTTP download).
                        let (blob_uri, blob_key, blob_ciphertext_hash, blob_ciphertext_size, blob_content_hash, blob_mime, blob_width, blob_height, blob_thumbhash) =
                            if let Some(moat_core::ParsedMessagePayload::Structured(
                                moat_core::MessagePayload::Image(ref m),
                            )) = parsed
                            {
                                (
                                    Some(m.external.uri.clone()),
                                    Some(m.external.key.clone()),
                                    Some(m.external.ciphertext_hash.clone()),
                                    Some(m.external.ciphertext_size),
                                    Some(m.external.content_hash.clone()),
                                    m.mime.clone(),
                                    m.width,
                                    m.height,
                                    // Kept rather than only decoded for
                                    // display: a device receiving this
                                    // message through history sync cannot
                                    // recover it from the PDS, because the
                                    // event carrying it predates its
                                    // membership.
                                    Some(m.preview_thumbhash.clone()),
                                )
                            } else {
                                (None, None, None, None, None, None, None, None, None)
                            };

                        // Persist received message locally
                        let stored_msg = crate::keystore::StoredMessage {
                            rkey: event_record.rkey.clone(),
                            content: content.clone(),
                            timestamp: event_record.created_at,
                            is_own,
                            message_id: decrypted.event.message_id.clone(),
                            sender_did: sender_did.clone(),
                            sender_device: sender_device.clone(),
                            blob_uri,
                            blob_key,
                            blob_ciphertext_hash,
                            blob_ciphertext_size,
                            blob_content_hash,
                            blob_mime,
                            blob_width,
                            blob_height,
                            blob_thumbhash,
                            reactions: Vec::new(),
                        };
                        match self.keys.append_message(&conv_id, stored_msg) {
                            Err(e) => {
                                self.debug_log
                                    .log(&format!("poll: failed to store message: {}", e));
                            }
                            Ok(false) => {
                                // Duplicate rkey — already stored, skip in-memory insert.
                                return Ok(msg_stored);
                            }
                            Ok(true) => {
                                msg_stored = true;
                            }
                        }

                        if self.active_conversation == conv_idx {
                            let dm = DisplayMessage {
                                from: conv_idx
                                    .and_then(|idx| self.conversations.get(idx))
                                    .map(|c| c.display_name())
                                    .unwrap_or_else(|| "Unknown".to_string()),
                                content,
                                timestamp: event_record.created_at,
                                is_own,
                                sender_did,
                                sender_device,
                                message_id: decrypted.event.message_id.clone(),
                                reactions: vec![],
                                image_proto: None,
                                image_loading: false,
                                rkey: event_record.rkey.clone(),
                            };
                            let pos = self
                                .messages
                                .partition_point(|m| m.rkey <= dm.rkey);
                            self.messages.insert(pos, dm);
                        } else if let Some(idx) = conv_idx {
                            if let Some(conv) = self.conversations.get_mut(idx) {
                                conv.unread += 1;
                            }
                        }

                        // Eagerly fetch the blob for LongText and Image messages.
                        if let Some(moat_core::ParsedMessagePayload::Structured(
                            moat_core::MessagePayload::LongText(ref msg),
                        )) = parsed
                        {
                            self.spawn_blob_fetch_long_text(
                                &msg.external,
                                decrypted.event.message_id.clone(),
                            );
                        }

                        if let Some(moat_core::ParsedMessagePayload::Structured(
                            moat_core::MessagePayload::Image(ref media_msg),
                        )) = parsed
                        {
                            let mid = decrypted.event.message_id.clone();
                            // Try disk cache first.
                            let cached = self.blob_cache.get(&media_msg.external.content_hash);
                            if let Some(bytes) = cached {
                                if let Ok(img) = image::load_from_memory(&bytes) {
                                    let proto = self.picker.new_resize_protocol(img);
                                    if let Some(dm) = self
                                        .messages
                                        .iter_mut()
                                        .rev()
                                        .find(|m| m.message_id == mid)
                                    {
                                        dm.image_proto = Some(ImageProto(proto));
                                        dm.image_loading = false;
                                    }
                                }
                            } else {
                                // No cache — show ThumbHash placeholder and fetch.
                                if let Some(thumb_img) = image_processing::decode_thumbhash(
                                    &media_msg.preview_thumbhash,
                                ) {
                                    let proto = self.picker.new_resize_protocol(thumb_img);
                                    if let Some(dm) = self
                                        .messages
                                        .iter_mut()
                                        .rev()
                                        .find(|m| m.message_id == mid)
                                    {
                                        dm.image_proto = Some(ImageProto(proto));
                                        dm.image_loading = true;
                                    }
                                }
                                self.spawn_blob_fetch_image(
                                    &media_msg.external,
                                    decrypted.event.message_id.clone(),
                                );
                            }
                        }
                    }
                    EventKind::Control(ControlKind::Commit) => {
                        let new_epoch = decrypted.event.epoch;
                        if let Some(conv) =
                            self.conversations.iter_mut().find(|c| c.id == conv_id)
                        {
                            conv.current_epoch = new_epoch;
                        }

                        // Update member list from MLS group state (may have changed due to add/remove)
                        let my_did_str = my_did.to_string();
                        let old_dids: Vec<String> = self
                            .conversations
                            .iter()
                            .find(|c| c.id == conv_id)
                            .map(|c| c.participant_dids.clone())
                            .unwrap_or_default();

                        if let Ok(all_dids) = self.mls.get_group_dids(&group_id) {
                            let member_dids: Vec<String> = all_dids
                                .into_iter()
                                .filter(|d| d != &my_did_str)
                                .collect();
                            if member_dids != old_dids {
                                // Build updated handles: preserve known handles for existing
                                // members, use DIDs as placeholders for new ones.
                                let old_handles: Vec<String> = self
                                    .conversations
                                    .iter()
                                    .find(|c| c.id == conv_id)
                                    .map(|c| c.participant_handles.clone())
                                    .unwrap_or_default();
                                let new_handles: Vec<String> = member_dids
                                    .iter()
                                    .map(|did| {
                                        // If this DID was already known, reuse its handle
                                        old_dids
                                            .iter()
                                            .position(|d| d == did)
                                            .and_then(|i| old_handles.get(i).cloned())
                                            .unwrap_or_else(|| did.clone())
                                    })
                                    .collect();

                                if let Some(conv) =
                                    self.conversations.iter_mut().find(|c| c.id == conv_id)
                                {
                                    conv.participant_dids = member_dids.clone();
                                    conv.participant_handles = new_handles.clone();
                                }
                                // Anyone who just left still has messages
                                // on their own PDS that this device may
                                // never have fetched — it only ever asks
                                // the DIDs in `participant_dids`, and this
                                // assignment has just removed them from
                                // it. Hold them for one sweep.
                                //
                                // Without this, a device offline while
                                // someone joins, speaks and leaves handles
                                // the Add and the Remove in a single
                                // catch-up pass and never polls them at
                                // all. See MULTI_DEVICE.md, "Catch-Up
                                // Across Membership Changes".
                                let existing_meta = self
                                    .keys
                                    .load_group_metadata(&conv_id)
                                    .unwrap_or_default();
                                let mut pending_ex_members = existing_meta.pending_ex_members;
                                let mut member_device_ids = existing_meta.member_device_ids;
                                // Refresh device_ids for current members (captures newcomers)
                                if let Ok(members) = self.mls.get_group_members(&group_id) {
                                    for (_leaf_idx, cred) in &members {
                                        if let Some(c) = cred {
                                            member_device_ids.insert(
                                                c.did().to_string(),
                                                c.device_id().to_vec(),
                                            );
                                        }
                                    }
                                }
                                for departed in &old_dids {
                                    if !member_dids.contains(departed)
                                        && !pending_ex_members.contains(departed)
                                    {
                                        self.debug_log.log(&format!(
                                            "poll: {departed} left {conv_id}; holding for one sweep"
                                        ));
                                        pending_ex_members.push(departed.clone());
                                    }
                                }

                                // Update stored metadata
                                let _ = self.keys.store_group_metadata(
                                    &conv_id,
                                    &GroupMetadata {
                                        participant_dids: member_dids,
                                        participant_handles: new_handles,
                                        kind: GroupKind::User,
                                        pending_ex_members,
                                        member_device_ids,
                                    },
                                );
                                // Fetch relay configs for any new members
                                self.fetch_partner_drawbridge_configs(&conv_id);
                            }
                        }

                        // Regenerate candidate tags for the new epoch
                        self.register_group_tags(&conv_id, &group_id);
                    }
                    EventKind::Modifier(ModifierKind::Reaction) => {
                        if let Some(rp) = decrypted.event.reaction_payload() {
                            let sender_did =
                                decrypted.sender.map(|s| s.did).unwrap_or_default();
                            // Persist first, and unconditionally. Storage
                            // is what history sync serves from, and a
                            // device receiving this message later cannot
                            // rebuild the reaction from the PDS: the event
                            // carrying it predates that device's
                            // membership. Doing this only for the open
                            // conversation also lost reactions on every
                            // other one outright.
                            if let Err(e) = self.keys.toggle_reaction(
                                &conv_id,
                                &rp.target_message_id,
                                &rp.emoji,
                                &sender_did,
                            ) {
                                self.debug_log
                                    .log(&format!("poll: failed to store reaction: {e}"));
                            }
                            // Mirror it into the display list when the
                            // conversation is on screen.
                            if self.active_conversation == conv_idx {
                                if let Some(msg) = self.messages.iter_mut().find(|m| {
                                    m.message_id.as_ref() == Some(&rp.target_message_id)
                                }) {
                                    if let Some(pos) = msg.reactions.iter().position(|r| {
                                        r.emoji == rp.emoji && r.sender_did == sender_did
                                    }) {
                                        msg.reactions.remove(pos);
                                    } else {
                                        msg.reactions.push(DisplayReaction {
                                            emoji: rp.emoji,
                                            sender_did,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    EventKind::RingMsg => {
                        // Ring application traffic. The sender's identity is
                        // whatever MLS says it is — the payload declares no
                        // device of its own.
                        let sender_name = decrypted
                            .sender
                            .as_ref()
                            .map(|s| s.device_name.clone())
                            .unwrap_or_else(|| "an unnamed device".to_string());
                        let sender_did = decrypted.sender.as_ref().map(|s| s.did.clone());
                        if sender_did.as_deref() != Some(my_did) {
                            self.debug_log.log(
                                "poll: ignoring a ring message whose sender is not us",
                            );
                        } else {
                            match moat_core::decode_ring_msg(&decrypted.event.payload) {
                                Ok(RingMsg::SyncRequest {
                                    token,
                                    target_device_id,
                                }) => {
                                    // A request naming someone else is
                                    // not ours to answer: prompting here
                                    // would ask the user about another
                                    // device's business, and two
                                    // approvals race for a rendezvous
                                    // that admits two attaches.
                                    let for_us = target_device_id
                                        .is_none_or(|t| &t == self.mls.device_id());
                                    if for_us {
                                        self.on_sync_request_received(token, sender_name);
                                    } else {
                                        self.debug_log.log(
                                            "sync: ignoring a request addressed to another device",
                                        );
                                    }
                                }
                                Ok(RingMsg::SyncOffer { token, target_device_id }) => {
                                    if &target_device_id == self.mls.device_id() {
                                        self.on_sync_offer_received(token, sender_name);
                                    } else {
                                        self.debug_log.log(
                                            "sync: ignoring an offer addressed to another device",
                                        );
                                    }
                                }
                                Err(e) => self
                                    .debug_log
                                    .log(&format!("poll: undecodable ring message: {e}")),
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                self.debug_log
                    .log(&format!("poll: decryption failed: {}", e));
                return Err(e);
            }
        }
        Ok(msg_stored)
    }

    /// Synchronous welcome processing (no handle resolution — uses DID as name).
    fn try_process_welcome_sync(
        &mut self,
        ciphertext: &[u8],
        _author_did: &str,
        _tag: [u8; 16],
    ) -> bool {
        let stealth_privkey = match self.keys.load_stealth_key() {
            Ok(key) => key,
            Err(e) => {
                self.debug_log.log(&format!("try_welcome: failed to load stealth key: {e}"));
                return false;
            }
        };

        let plaintext = match try_decrypt_stealth(&stealth_privkey, ciphertext) {
            Some(bytes) => bytes,
            None => {
                self.debug_log.log("try_welcome: stealth decryption failed (not for us)");
                return false;
            }
        };

        // Decode welcome envelope (may contain bundled Drawbridge hints)
        let (welcome_bytes, _hint_bundle) = match decode_welcome_envelope(&plaintext) {
            Ok(result) => result,
            Err(e) => {
                self.debug_log.log(&format!("try_welcome: {e}"));
                return false;
            }
        };

        let group_id = match self.mls.process_welcome(&welcome_bytes) {
            Ok(id) => id,
            Err(e) => {
                self.debug_log.log(&format!("try_welcome: MLS process_welcome failed: {e}"));
                return false;
            }
        };

        let conv_id = hex::encode(&group_id);

        // Get all member DIDs from the MLS group (includes ourselves)
        let my_did = self.client.as_ref().map(|c| c.did().to_string()).unwrap_or_default();
        let all_dids = self.mls.get_group_dids(&group_id).unwrap_or_default();
        let participant_dids: Vec<String> = all_dids
            .into_iter()
            .filter(|d| d != &my_did)
            .collect();

        // A group where all members share our DID cannot legitimately arrive
        // via this cross-user stealth path: ring membership changes ride the
        // pairing channel or `MoatSession::add_member` directly. Register
        // tags so we don't lose track of an already-joined MLS group, but
        // don't surface a conversation.
        if participant_dids.is_empty() {
            self.register_group_tags(&conv_id, &group_id);
            self.replenish_key_package();
            self.debug_log.log(
                "process_welcome: same-DID Welcome via stealth is unexpected (registered tags only)",
            );
            return true;
        }

        // Use DIDs as placeholder handles; will be resolved in background
        let participant_handles: Vec<String> = participant_dids.clone();

        let _ = self.keys.store_group_metadata(
            &conv_id,
            &GroupMetadata {
                participant_dids: participant_dids.clone(),
                participant_handles: participant_handles.clone(),
                kind: GroupKind::User,
                pending_ex_members: Vec::new(),
                member_device_ids: Default::default(),
            },
        );

        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name: None,
            participant_dids,
            participant_handles,
            current_epoch: 1,
            unread: 1,
            is_member: true,
        });

        self.register_group_tags(&conv_id, &group_id);

        // Resolve DID → handle in background for each participant
        if let Some(conv) = self.conversations.last() {
            self.resolve_conversation_handle(conv);
        }

        // Fetch relay configs for the new conversation's partners
        self.fetch_partner_drawbridge_configs(&conv_id);

        self.debug_log
            .log("process_welcome: successfully joined group");

        // Replenish key package so we can be re-added to this (or another)
        // group in the future.  Key packages are single-use: OpenMLS deletes
        // the init key after a Welcome is consumed, so without replenishment
        // a removed member can never rejoin.
        self.replenish_key_package();

        true
    }

    /// Generate a fresh key package (reusing the existing signing key) and publish
    /// it to the PDS in the background.
    ///
    /// Called after every successful Welcome join so the member can be re-added.
    /// Unlike the initial key-package generation, this preserves the existing
    /// signing key so that in-progress group operations remain valid.
    fn replenish_key_package(&mut self) {
        let client = match &self.client {
            Some(c) => c.clone(),
            None => return,
        };
        let did = client.did().to_string();
        let device_name = match self.keys.get_or_create_device_name() {
            Ok(n) => n,
            Err(_) => return,
        };
        let key_bundle = match self.keys.load_identity_key() {
            Ok(b) => b,
            Err(_) => return,
        };
        let credential = MoatCredential::new(&did, &device_name, *self.mls.device_id());
        let key_package = match self.mls.replenish_key_package(&credential, &key_bundle) {
            Ok(kp) => kp,
            Err(e) => {
                self.debug_log
                    .log(&format!("replenish_key_package: generate failed: {e}"));
                return;
            }
        };
        let _ = self.save_mls_state();
        let ciphersuite_name = format!("{:?}", CIPHERSUITE);
        let tx = self.bg_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = client.publish_key_package(&key_package, &ciphersuite_name).await {
                let _ = tx.send(BgEvent::PollError(format!(
                    "replenish_key_package: publish failed: {e}"
                )));
            }
        });
    }

    async fn handle_login_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Tab => {
                self.login_form.field = match self.login_form.field {
                    LoginField::Handle => LoginField::Password,
                    LoginField::Password => LoginField::Handle,
                };
            }
            KeyCode::Enter => {
                if self.login_form.field == LoginField::Password {
                    self.do_login().await?;
                } else {
                    self.login_form.field = LoginField::Password;
                }
            }
            KeyCode::Char(c) => {
                let field = match self.login_form.field {
                    LoginField::Handle => &mut self.login_form.handle,
                    LoginField::Password => &mut self.login_form.password,
                };
                field.push(c);
            }
            KeyCode::Backspace => {
                let field = match self.login_form.field {
                    LoginField::Handle => &mut self.login_form.handle,
                    LoginField::Password => &mut self.login_form.password,
                };
                field.pop();
            }
            KeyCode::Esc => return Ok(true),
            _ => {}
        }
        Ok(false)
    }

    async fn do_login(&mut self) -> Result<()> {
        let handle = self.login_form.handle.clone();
        let password = self.login_form.password.clone();

        self.set_status("Logging in...".to_string());

        let client = if let Some(ref pds_url) = self.pds_url {
            MoatAtprotoClient::login_with_pds(&handle, &password, pds_url)
                .await?
                .with_pds_override(pds_url.clone())
        } else {
            MoatAtprotoClient::login(&handle, &password).await?
        };

        // Store credentials
        self.keys.store_credentials(&handle, &password)?;

        // Store session tokens to avoid future logins (prevents rate limiting)
        if let Some((access_jwt, refresh_jwt)) = client.get_session_tokens().await {
            let _ = self.keys.store_session(&StoredSession {
                did: client.did().to_string(),
                access_jwt,
                refresh_jwt,
            });
        }

        // Generate identity key if needed (using MoatSession for persistence)
        if !self.keys.has_identity_key() {
            self.set_status("Generating identity key...".to_string());

            // Get or create device name for multi-device support
            let device_name = self.keys.get_or_create_device_name()?;
            let credential = MoatCredential::new(client.did(), &device_name, *self.mls.device_id());

            // Use MoatSession for persistent key generation
            let (key_package, key_bundle) = self.mls.generate_key_package(&credential)?;
            self.save_mls_state()?;

            // Store key bundle locally (needed for encryption operations)
            self.keys.store_identity_key(&key_bundle)?;

            // Publish key package to PDS
            self.set_status("Publishing key package...".to_string());
            let ciphersuite_name = format!("{:?}", CIPHERSUITE);
            client
                .publish_key_package(&key_package, &ciphersuite_name)
                .await?;
        }

        // Generate stealth address if needed (for receiving private invites)
        // Each device has its own stealth address
        if !self.keys.has_stealth_key() {
            self.set_status("Generating stealth address...".to_string());

            let (stealth_privkey, stealth_pubkey) = generate_stealth_keypair();

            // Store private key locally
            self.keys.store_stealth_key(&stealth_privkey)?;

            // Publish public key to PDS with device name and device id
            self.set_status("Publishing stealth address...".to_string());
            let device_name = self.keys.get_or_create_device_name()?;
            let device_id = *self.mls.device_id();
            client
                .publish_stealth_address(&stealth_pubkey, &device_name, &device_id)
                .await?;
        }

        let did = client.did().to_string();
        self.client = Some(client);
        self.status_message = None;
        self.logged_in_handle = Some(handle);
        self.focus = Focus::Conversations;

        self.load_conversations_sync();

        // Resolve handles for all conversations on login
        for conv in self.conversations.clone() {
            self.resolve_conversation_handle(&conv);
        }

        // Connect to own Drawbridge.
        //
        // URL resolution order:
        //   1. Explicit --drawbridge-url override
        //   2. PDS-advertised via com.atproto.server.describeServer
        //   3. Hardcoded default (wss://moat-drawbridge.fly.dev/ws)
        {
            let url = if let Some(ref explicit) = self.drawbridge_url {
                Some(explicit.clone())
            } else if let Some(client) = &self.client {
                client
                    .describe_server_drawbridge_url(&self.pds_url.clone().unwrap_or_else(|| {
                        moat_atproto::DEFAULT_PDS_URL.to_string()
                    }))
                    .await
                    .or_else(|| Some(moat_atproto::DEFAULT_DRAWBRIDGE_URL.to_string()))
            } else {
                Some(moat_atproto::DEFAULT_DRAWBRIDGE_URL.to_string())
            };

            if let Some(url) = url {
                // Persist the resolved URL so auto-login on restart can connect
                // without repeating the describeServer discovery.
                self.drawbridge_url = Some(url.clone());
                if let Ok(sig_key) = self.keys.load_identity_key() {
                    let _ = self.bg_tx.send(BgEvent::DrawbridgeConnectOwn {
                        url,
                        did: did.clone(),
                        signature_key: sig_key,
                    });
                }
            }
        }

        // Fetch relay configs for all conversation partners
        for conv in &self.conversations {
            self.fetch_partner_drawbridge_configs(&conv.id.clone());
        }

        Ok(())
    }

    async fn handle_conversations_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('n') => {
                // Switch to new conversation input mode
                self.focus = Focus::NewConversation;
                self.new_conv_handle.clear();
            }
            KeyCode::Char('w') => {
                // Switch to watch handle input mode
                self.focus = Focus::WatchHandle;
                self.watch_handle_input.clear();
            }
            KeyCode::Char('p') => {
                // New device: request a pairing code and show it.
                match self.api_pair_new() {
                    Ok(_) => self.focus = Focus::PairShowCode,
                    Err(e) => self.set_error(format!("Link this device failed: {e}")),
                }
            }
            KeyCode::Char('P') => {
                // Existing device: enter a pairing code shown elsewhere.
                self.focus = Focus::PairEnterCode;
                self.pair_enter_code_input.clear();
            }
            KeyCode::Char('d') => {
                // Linked devices, and the state of any sync in flight.
                self.focus = Focus::Devices;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.conversations.is_empty() {
                    let current = self.active_conversation.unwrap_or(0);
                    self.active_conversation = Some(current.saturating_sub(1));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.conversations.is_empty() {
                    let current = self.active_conversation.unwrap_or(0);
                    let max = self.conversations.len().saturating_sub(1);
                    self.active_conversation = Some((current + 1).min(max));
                }
            }
            KeyCode::Enter => {
                if let Some(idx) = self.active_conversation {
                    if let Some(conv) = self.conversations.get(idx) {
                        self.resolve_conversation_handle(conv);
                    }
                    self.load_messages()?;
                    self.message_scroll = 0;
                    self.focus = Focus::Input;
                }
            }
            KeyCode::Tab => {
                self.focus = Focus::Messages;
            }
            _ => {}
        }
        Ok(false)
    }

    async fn handle_new_conversation_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Enter => {
                if !self.new_conv_handle.is_empty() {
                    let handle = self.new_conv_handle.clone();
                    self.start_new_conversation(&handle).await?;
                }
            }
            KeyCode::Char(c) => {
                self.new_conv_handle.push(c);
            }
            KeyCode::Backspace => {
                self.new_conv_handle.pop();
            }
            KeyCode::Esc => {
                self.focus = Focus::Conversations;
                self.new_conv_handle.clear();
            }
            _ => {}
        }
        Ok(false)
    }

    async fn handle_watch_handle_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Enter => {
                if !self.watch_handle_input.is_empty() {
                    let handle = self.watch_handle_input.clone();
                    self.watch_handle(&handle).await?;
                }
            }
            KeyCode::Char(c) => {
                self.watch_handle_input.push(c);
            }
            KeyCode::Backspace => {
                self.watch_handle_input.pop();
            }
            KeyCode::Esc => {
                self.focus = Focus::Conversations;
                self.watch_handle_input.clear();
            }
            _ => {}
        }
        Ok(false)
    }

    /// New device: showing the pairing code (rendered from `ui_state()` —
    /// see `draw_pair_show_code_popup`). Any key dismisses once terminal
    /// (`Done` or `Failed`); Esc while still showing the code aborts the
    /// pairing via `cancel()`.
    fn handle_pair_show_code_key(&mut self, key: KeyEvent) -> Result<bool> {
        let terminal = self.pairing_is_terminal();
        match key.code {
            KeyCode::Esc => {
                if !terminal {
                    let _ = self.api_pair_cancel();
                }
                self.focus = Focus::Conversations;
            }
            _ if terminal => {
                self.focus = Focus::Conversations;
            }
            _ => {}
        }
        Ok(false)
    }

    /// Existing device: text-entry for a pairing code.
    fn handle_pair_enter_code_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Enter => {
                if !self.pair_enter_code_input.is_empty() {
                    let code = self.pair_enter_code_input.clone();
                    match self.api_pair_confirm(&code) {
                        Ok(()) => {
                            self.pair_enter_code_input.clear();
                            self.focus = Focus::Conversations;
                        }
                        Err(e) => self.set_error(format!("pairing code rejected: {e}")),
                    }
                }
            }
            KeyCode::Char(c) => {
                self.pair_enter_code_input.push(c);
            }
            KeyCode::Backspace => {
                self.pair_enter_code_input.pop();
            }
            KeyCode::Esc => {
                self.focus = Focus::Conversations;
                self.pair_enter_code_input.clear();
            }
            _ => {}
        }
        Ok(false)
    }

    /// Existing device: confirmation screen naming the peer awaiting
    /// approval (rendered from `ui_state()` — see `draw_pair_approve_popup`).
    /// Enter/`y` approves; Esc/`n` rejects. Any key dismisses once terminal
    /// — reached either by this key's own approve/reject, or by a
    /// background failure since the prompt was shown (surfaced via
    /// `ui_state()`'s `Failed` instead of a silent teardown).
    fn handle_pair_approve_key(&mut self, key: KeyEvent) -> Result<bool> {
        if self.pairing_is_terminal() {
            self.focus = Focus::Conversations;
            return Ok(false);
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') => {
                // On failure, stay on this screen — `ui_state()` now shows
                // `Failed { reason }`, dismissible by the next key press.
                if self.approve_pending_pairing().is_ok() {
                    self.focus = Focus::Conversations;
                }
            }
            KeyCode::Esc | KeyCode::Char('n') => {
                let _ = self.api_pair_reject();
                self.focus = Focus::Conversations;
            }
            _ => {}
        }
        Ok(false)
    }

    /// Devices screen: `s` asks the other devices for history, Esc leaves.
    ///
    /// Requesting from here rather than from a bare keystroke on the
    /// conversation list is deliberate — this is the screen that then
    /// *shows* what the request is doing, which a fire-and-forget key
    /// press never did.
    fn handle_devices_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('s') => {
                if let Err(e) = self.api_sync_request() {
                    self.set_error(format!("Sync history failed: {e}"));
                }
            }
            // Send this device's history to the other device in the ring.
            // Pressing this *is* the approval; the other side joins without
            // a prompt. With more than one other device, the first one
            // listed is the target.
            KeyCode::Char('o') => {
                let target = self
                    .api_ring_devices()
                    .into_iter()
                    .find(|d| !d["is_self"].as_bool().unwrap_or(false))
                    .and_then(|d| d["device_id"].as_str().map(str::to_string))
                    .and_then(|hex_id| hex::decode(&hex_id).ok())
                    .and_then(|b| <[u8; moat_core::DEVICE_ID_LEN]>::try_from(b.as_slice()).ok());
                match target {
                    Some(device_id) => {
                        if let Err(e) = self.api_sync_offer(device_id) {
                            self.set_error(format!("Send history failed: {e}"));
                        }
                    }
                    None => self.set_error("No other linked device.".to_string()),
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.focus = Focus::Conversations;
            }
            _ => {}
        }
        Ok(false)
    }

    /// Approval screen for a sibling's sync request: `y`/Enter sends this
    /// device's history, `n`/Esc refuses. Refusing is local — the sibling
    /// keeps waiting for another device.
    fn handle_sync_approve_key(&mut self, key: KeyEvent) -> Result<bool> {
        if !matches!(
            self.sync_request_ui_state(),
            SyncRequestUiState::AwaitingApproval { .. }
        ) {
            self.focus = Focus::Conversations;
            return Ok(false);
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') => {
                if let Err(e) = self.api_sync_accept() {
                    self.set_error(format!("Send history failed: {e}"));
                }
                self.focus = Focus::Conversations;
            }
            KeyCode::Esc | KeyCode::Char('n') => {
                let _ = self.api_sync_decline();
                self.focus = Focus::Conversations;
            }
            _ => {}
        }
        Ok(false)
    }

    async fn watch_handle(&mut self, handle: &str) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }

        self.set_status(format!("Resolving {}...", handle));

        // Resolve handle to DID
        let did = self.client.as_ref().unwrap().resolve_did(handle).await?;

        // Add to watched DIDs and persist so it survives restarts.
        self.watched_dids.insert(did);
        let _ = self.keys.store_watched_dids(&self.watched_dids);

        self.status_message = None;
        self.focus = Focus::Conversations;
        self.watch_handle_input.clear();

        Ok(())
    }

    async fn start_new_conversation(&mut self, recipient_handle: &str) -> Result<()> {
        // Check login first
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }

        self.set_status(format!("Resolving {}...", recipient_handle));

        // 1. Resolve handle to DID first so we can check for duplicates
        let recipient_did = self
            .client
            .as_ref()
            .unwrap()
            .resolve_did(recipient_handle)
            .await?;

        // Check if we already have a conversation with this participant
        if let Some(existing_idx) = self
            .conversations
            .iter()
            .position(|c| c.participant_dids.contains(&recipient_did))
        {
            // Switch to existing conversation instead of creating a duplicate
            self.active_conversation = Some(existing_idx);
            self.load_messages()?;
            self.focus = Focus::Input;
            self.new_conv_handle.clear();
            self.status_message = None;
            self.set_status(format!(
                "Switched to existing conversation with {}",
                recipient_handle
            ));
            return Ok(());
        }

        self.set_status(format!(
            "Fetching stealth addresses for {}...",
            recipient_handle
        ));

        // 2. Fetch all of the recipient's stealth addresses (one per device)
        let stealth_records = self
            .client
            .as_ref()
            .unwrap()
            .fetch_stealth_addresses(&recipient_did)
            .await?;

        if stealth_records.is_empty() {
            return Err(AppError::Other(format!(
                "No stealth address found for {}. They may need to update their Moat client.",
                recipient_handle
            )));
        }

        // Collect all device public keys for multi-recipient encryption
        let recipient_stealth_pubkeys: Vec<[u8; 32]> =
            stealth_records.iter().map(|r| r.scan_pubkey).collect();

        self.debug_log.log(&format!(
            "start_new_conversation: found {} stealth addresses for {}",
            recipient_stealth_pubkeys.len(),
            &recipient_did[..20.min(recipient_did.len())]
        ));

        self.set_status(format!("Fetching key package for {}...", recipient_handle));

        // 3. Fetch recipient's MLS key package
        let key_packages = self
            .client
            .as_ref()
            .unwrap()
            .fetch_key_packages(&recipient_did)
            .await?;
        let recipient_kp_bytes = key_packages
            .first()
            .ok_or_else(|| {
                AppError::Other(format!("No key package found for {}", recipient_handle))
            })?
            .key_package
            .clone();

        // 4. Load our key bundle and create credential
        let key_bundle = self.keys.load_identity_key()?;
        let did = self.client.as_ref().unwrap().did().to_string();
        let device_name = self.keys.get_or_create_device_name()?;
        let credential = MoatCredential::new(&did, &device_name, *self.mls.device_id());

        self.set_status("Creating encrypted group...".to_string());

        // 5. Create MLS group
        let group_id = self.mls.create_group(&credential, &key_bundle)?;

        // 6. Add recipient to group (generates MLS Welcome)
        let welcome_result = self
            .mls
            .add_member(&group_id, &key_bundle, &recipient_kp_bytes)?;
        self.save_mls_state()?;

        self.set_status("Publishing welcome message...".to_string());

        // 7. Encrypt Welcome for ALL of recipient's devices using key encapsulation
        // This allows any of their devices to decrypt and join the conversation
        let envelope = encode_welcome_envelope(&welcome_result.welcome, &[]);
        let stealth_ciphertext =
            encrypt_for_stealth(&recipient_stealth_pubkeys, &envelope)?;

        // 8. Publish with random tag (not group-derived, since recipient doesn't know group yet)
        let random_tag: [u8; 16] = rand::random();
        self.client
            .as_ref()
            .unwrap()
            .publish_event(&random_tag, &stealth_ciphertext, None)
            .await?;

        // 9. Store conversation metadata
        let conv_id = hex::encode(&group_id);
        self.keys.store_group_metadata(
            &conv_id,
            &GroupMetadata {
                participant_dids: vec![recipient_did.clone()],
                participant_handles: vec![recipient_handle.to_string()],
                kind: GroupKind::User,
                pending_ex_members: Vec::new(),
                member_device_ids: Default::default(),
            },
        )?;

        // 10. Update UI - add conversation to list
        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name: None,
            participant_dids: vec![recipient_did],
            participant_handles: vec![recipient_handle.to_string()],
            current_epoch: 1, // Post-add epoch
            unread: 0,
            is_member: true,
        });

        // 11. Register candidate tags for this conversation
        self.register_group_tags(&conv_id, &group_id);
        self.debug_log.log(&format!(
            "start_conv: registered candidate tags for conv {}",
            &conv_id[..16]
        ));

        // 12. Fetch partner relay configs
        self.fetch_partner_drawbridge_configs(&conv_id);

        // 13. Select the new conversation and switch to input mode
        self.active_conversation = Some(self.conversations.len() - 1);
        self.focus = Focus::Input;
        self.new_conv_handle.clear();
        self.status_message = None;

        // Load placeholder message for the new conversation
        self.messages.clear();
        self.messages.push(DisplayMessage {
            from: "System".to_string(),
            content: format!(
                "Conversation started with {}. Type a message below.",
                recipient_handle
            ),
            timestamp: chrono::Utc::now(),
            is_own: false,
            sender_did: None,
            sender_device: None,
            message_id: None,
            reactions: vec![],
            image_proto: None,
            image_loading: false,
            rkey: String::new(),
        });

        Ok(())
    }

    /// Add a new member to an existing group conversation.
    async fn add_member_to_group(&mut self, group_id_hex: &str, handle: &str) -> Result<()> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AppError::Other("not logged in".to_string()))?
            .clone();

        // 1. Resolve handle → DID
        let new_did = client.resolve_did(handle).await?;

        // 2. Check DID not already in group
        let group_id = hex::decode(group_id_hex)
            .map_err(|e| AppError::Other(format!("invalid group_id hex: {e}")))?;
        if self.mls.is_did_in_group(&group_id, &new_did)? {
            return Err(AppError::Other(format!(
                "{handle} is already in this group"
            )));
        }

        // 3. Fetch stealth addresses for new member
        let stealth_records = client.fetch_stealth_addresses(&new_did).await?;
        if stealth_records.is_empty() {
            return Err(AppError::Other(format!(
                "No stealth address found for {handle}"
            )));
        }
        let stealth_pubkeys: Vec<[u8; 32]> =
            stealth_records.iter().map(|r| r.scan_pubkey).collect();

        // 4. Fetch key package for new member — use the most recently uploaded
        //    package (last in ascending rkey order) so that a replenished key
        //    package takes precedence over an already-consumed earlier one.
        let key_packages = client.fetch_key_packages(&new_did).await?;
        let kp_bytes = key_packages
            .last()
            .ok_or_else(|| AppError::Other(format!("No key package found for {handle}")))?
            .key_package
            .clone();

        // 5. Load our key bundle
        let key_bundle = self.keys.load_identity_key()?;

        // 6. Add member to MLS group
        let welcome_result = self.mls.add_member(&group_id, &key_bundle, &kp_bytes)?;
        self.save_mls_state()?;

        // 8. Encrypt Welcome envelope for new member's stealth keys, publish with random tag
        let envelope = encode_welcome_envelope(&welcome_result.welcome, &[]);
        let stealth_ciphertext =
            moat_core::encrypt_for_stealth(&stealth_pubkeys, &envelope)?;
        let random_tag: [u8; 16] = rand::random();
        client
            .publish_event(&random_tag, &stealth_ciphertext, None)
            .await?;

        // 10. Publish the Commit with pre-epoch tag for existing members
        client
            .publish_event(&welcome_result.commit_tag, &welcome_result.commit, None)
            .await?;

        // 11. Update GroupMetadata — add new DID/handle
        if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == group_id_hex) {
            if !conv.participant_dids.contains(&new_did) {
                conv.participant_dids.push(new_did.clone());
            }
            conv.participant_handles.push(handle.to_string());

            let _ = self.keys.store_group_metadata(
                group_id_hex,
                &GroupMetadata {
                    participant_dids: conv.participant_dids.clone(),
                    participant_handles: conv.participant_handles.clone(),
                    kind: GroupKind::User,
                    pending_ex_members: Vec::new(),
                    member_device_ids: Default::default(),
                },
            );
        }

        // 12. Re-populate candidate tags for the new epoch
        self.register_group_tags(group_id_hex, &group_id);

        // 13. Fetch new member's relay config
        self.fetch_partner_drawbridge_configs(group_id_hex);

        self.debug_log.log(&format!(
            "add_member: added {handle} to group {}",
            &group_id_hex[..16.min(group_id_hex.len())]
        ));

        Ok(())
    }

    /// Remove (kick) a member from a group conversation by handle.
    async fn kick_member_from_group(&mut self, group_id_hex: &str, handle: &str) -> Result<()> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AppError::Other("not logged in".to_string()))?
            .clone();

        // 1. Resolve handle → DID
        let did_to_kick = client.resolve_did(handle).await?;

        // 2. Decode group_id
        let group_id = hex::decode(group_id_hex)
            .map_err(|e| AppError::Other(format!("invalid group_id hex: {e}")))?;

        // 3. Load key bundle
        let key_bundle = self.keys.load_identity_key()?;

        // 4. Kick user from MLS group
        let result = self.mls.kick_user(&group_id, &key_bundle, &did_to_kick)?;
        self.save_mls_state()?;

        // 6. Publish the Commit with pre-epoch tag
        client.publish_event(&result.commit_tag, &result.commit, None).await?;

        // 7. Update GroupMetadata — remove DID/handle
        if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == group_id_hex) {
            conv.participant_dids.retain(|d| d != &did_to_kick);
            conv.participant_handles.retain(|h| h != handle);

            let _ = self.keys.store_group_metadata(
                group_id_hex,
                &GroupMetadata {
                    participant_dids: conv.participant_dids.clone(),
                    participant_handles: conv.participant_handles.clone(),
                    kind: GroupKind::User,
                    pending_ex_members: Vec::new(),
                    member_device_ids: Default::default(),
                },
            );
        }

        // 8. Re-populate candidate tags for the new epoch
        self.register_group_tags(group_id_hex, &group_id);

        self.debug_log.log(&format!(
            "kick_member: removed {handle} ({did_to_kick}) from group {}",
            &group_id_hex[..16.min(group_id_hex.len())]
        ));

        Ok(())
    }

    /// Load messages from local storage.
    fn load_messages(&mut self) -> Result<()> {
        self.messages.clear();

        let Some(idx) = self.active_conversation else {
            return Ok(());
        };

        let conv_id = self.conversations[idx].id.clone();
        let conv_display_name = self.conversations[idx].display_name();

        let local_messages = self.keys.load_messages(&conv_id).unwrap_or_default();
        for stored in &local_messages.messages {
            let from = if stored.is_own {
                "You".to_string()
            } else {
                conv_display_name.clone()
            };
            self.messages.push(DisplayMessage {
                from,
                content: stored.content.clone(),
                timestamp: stored.timestamp,
                is_own: stored.is_own,
                sender_did: stored.sender_did.clone(),
                sender_device: stored.sender_device.clone(),
                message_id: stored.message_id.clone(),
                // From storage, not rebuilt by replaying events: history
                // that arrived by sync has no replayable events on this
                // device, so anything not read from here is invisible.
                reactions: stored
                    .reactions
                    .iter()
                    .map(|r| DisplayReaction {
                        emoji: r.emoji.clone(),
                        sender_did: r.sender_did.clone(),
                    })
                    .collect(),
                image_proto: None,
                image_loading: false,
                rkey: stored.rkey.clone(),
            });
        }

        // Clear unread count
        if let Some(conv) = self.conversations.get_mut(idx) {
            conv.unread = 0;
        }

        Ok(())
    }

    async fn handle_messages_key(&mut self, key: KeyEvent) -> Result<bool> {
        // If reaction picker popup is open, handle it separately
        if let Some(ref mut idx) = self.reaction_picker {
            match key.code {
                KeyCode::Enter => {
                    let emoji = QUICK_EMOJIS[*idx].to_string();
                    self.reaction_picker = None;
                    self.send_reaction(&emoji).await?;
                }
                KeyCode::Esc => {
                    self.reaction_picker = None;
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    *idx = idx.saturating_sub(1);
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    if *idx + 1 < QUICK_EMOJIS.len() {
                        *idx += 1;
                    }
                }
                _ => {}
            }
            return Ok(false);
        }

        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Tab => {
                self.focus = Focus::Input;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                // Scroll up (increase offset from bottom)
                let max_scroll = self.messages.len().saturating_sub(1);
                if self.message_scroll < max_scroll {
                    self.message_scroll += 1;
                }
                // Update selected message index (from bottom)
                self.selected_message = Some(self.message_scroll);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                // Scroll down (decrease offset from bottom)
                self.message_scroll = self.message_scroll.saturating_sub(1);
                // Update selected message index (from bottom)
                self.selected_message = Some(self.message_scroll);
            }
            KeyCode::Char('i') => {
                // Toggle message info popup for selected message
                if self.selected_message.is_some() && !self.messages.is_empty() {
                    self.show_message_info = !self.show_message_info;
                }
            }
            KeyCode::Char('r') => {
                // Open reaction picker for selected message
                if self.selected_message.is_some() && !self.messages.is_empty() {
                    self.reaction_picker = Some(0);
                }
            }
            KeyCode::Esc => {
                if self.show_message_info {
                    self.show_message_info = false;
                } else {
                    self.focus = Focus::Conversations;
                }
            }
            _ => {}
        }
        Ok(false)
    }

    /// Handle input key — fully synchronous for typing, crypto inline for send.
    fn handle_input_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Enter => {
                if self.input_buffer.starts_with("/image ") {
                    let path = self.input_buffer["/image ".len()..].trim().to_string();
                    self.send_image_nonblocking(&path)?;
                } else if !self.input_buffer.is_empty() {
                    self.send_message_nonblocking()?;
                }
            }
            KeyCode::Char(c) => {
                self.input_buffer.insert(self.cursor_position, c);
                self.cursor_position += 1;
            }
            KeyCode::Backspace => {
                if self.cursor_position > 0 {
                    self.cursor_position -= 1;
                    self.input_buffer.remove(self.cursor_position);
                }
            }
            KeyCode::Delete => {
                if self.cursor_position < self.input_buffer.len() {
                    self.input_buffer.remove(self.cursor_position);
                }
            }
            KeyCode::Left => {
                self.cursor_position = self.cursor_position.saturating_sub(1);
            }
            KeyCode::Right => {
                if self.cursor_position < self.input_buffer.len() {
                    self.cursor_position += 1;
                }
            }
            KeyCode::Home => {
                self.cursor_position = 0;
            }
            KeyCode::End => {
                self.cursor_position = self.input_buffer.len();
            }
            KeyCode::Tab => {
                self.focus = Focus::Conversations;
            }
            KeyCode::Esc => {
                self.focus = Focus::Messages;
            }
            _ => {}
        }
        Ok(false)
    }

    /// Encrypt inline (fast) and spawn the network publish to background.
    fn send_message_nonblocking(&mut self) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        let conv_idx = self.active_conversation.ok_or(AppError::NoConversation)?;
        // A conversation registered read-only from synced history has no
        // local MLS group, so there is nothing to encrypt to. The TUI
        // closes its composer, but the HTTP surface reaches here directly.
        if !self.conversations[conv_idx].is_member {
            return Err(AppError::Other(
                "waiting to be connected to this conversation".to_string(),
            ));
        }
        let conv_id = self.conversations[conv_idx].id.clone();

        self.debug_log.log(&format!(
            "send_message: conv_id={}, msg_len={}",
            &conv_id[..16],
            self.input_buffer.len()
        ));

        let key_bundle = self.keys.load_identity_key()?;
        let group_id = hex::decode(&conv_id)
            .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

        let current_epoch = self.mls.get_group_epoch(&group_id)?.unwrap_or(1);

        // Long text: encrypt blob, upload async, then MLS-encrypt on callback.
        if needs_blob_upload(&self.input_buffer) {
            let full_text = self.input_buffer.clone();
            let preview_text = truncate_to_preview(&full_text);

            // Blob-encrypt synchronously (fast — no I/O).
            let encrypted = blob_encrypt(full_text.as_bytes())
                .map_err(|e| AppError::Other(format!("blob encrypt failed: {e}")))?;
            let ciphertext_size = encrypted.blob.len() as u64;

            // Optimistic UI: show preview + uploading indicator.
            let timestamp = chrono::Utc::now();
            let my_did = self.client.as_ref().unwrap().did().to_string();
            let pending_message_id: Vec<u8> = {
                use rand::RngCore;
                let mut id = vec![0u8; 16];
                rand::thread_rng().fill_bytes(&mut id);
                id
            };
            let optimistic_content = format!("{preview_text} [long text — uploading…]");
            self.messages.push(DisplayMessage {
                from: "You".to_string(),
                content: optimistic_content.clone(),
                timestamp,
                is_own: true,
                sender_did: Some(my_did.clone()),
                sender_device: self.keys.get_or_create_device_name().ok(),
                message_id: Some(pending_message_id.clone()),
                reactions: vec![],
                image_proto: None,
                image_loading: false,
                rkey: "pending".to_string(),
            });

            let stored_msg = crate::keystore::StoredMessage {
                rkey: "pending".to_string(),
                content: optimistic_content,
                timestamp,
                is_own: true,
                message_id: Some(pending_message_id.clone()),
                sender_did: Some(my_did),
                sender_device: self.keys.get_or_create_device_name().ok(),
                blob_uri: None, blob_key: None, blob_ciphertext_hash: None, blob_ciphertext_size: None, blob_content_hash: None, blob_mime: None, blob_width: None, blob_height: None, blob_thumbhash: None,
                    reactions: Vec::new(),
            };
            if let Err(e) = self.keys.append_message(&conv_id, stored_msg) {
                self.debug_log
                    .log(&format!("send_message: failed to store locally: {e}"));
            }

            self.input_buffer.clear();
            self.cursor_position = 0;

            // Upload blob in background; BgEvent::BlobUploaded triggers MLS-encrypt + publish.
            let client = self.client.as_ref().unwrap().clone();
            let tx = self.bg_tx.clone();
            let conv_id_clone = conv_id;

            tokio::spawn(async move {
                match client.upload_blob(&encrypted.blob).await {
                    Ok(cid) => {
                        let _ = tx.send(BgEvent::BlobUploaded {
                            blob: UploadedBlob {
                                cid,
                                key: encrypted.key.to_vec(),
                                ciphertext_hash: encrypted.ciphertext_hash,
                                ciphertext_size,
                                content_hash: encrypted.content_hash,
                            },
                            preview_text,
                            conv_id: conv_id_clone,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(BgEvent::SendFailed(format!("blob upload failed: {e}")));
                    }
                }
            });

            return Ok(());
        }

        // Short / medium text: existing synchronous-crypto + async-publish path.
        let text_payload = build_text_payload(&self.input_buffer);
        let event = Event::message(group_id.clone(), current_epoch, &text_payload);
        let preview_payload = ParsedMessagePayload::Structured(text_payload.clone());
        let preview = render_message_preview(&preview_payload);

        // Encrypt synchronously (fast — pure crypto, no I/O)
        let encrypted = self.mls.encrypt_event(&group_id, &key_bundle, &event)?;
        self.save_mls_state()?;

        self.debug_log.log(&format!(
            "send_message: encrypted, tag={:02x?}",
            &encrypted.tag[..4]
        ));

        self.keys
            .store_group_state(&conv_id, &encrypted.new_group_state)?;

        // Optimistically update UI before network publish
        let timestamp = chrono::Utc::now();
        let my_did = self.client.as_ref().unwrap().did().to_string();
        self.messages.push(DisplayMessage {
            from: "You".to_string(),
            content: preview.clone(),
            timestamp,
            is_own: true,
            sender_did: Some(my_did.clone()),
            sender_device: self.keys.get_or_create_device_name().ok(),
            message_id: event.message_id.clone(),
            reactions: vec![],
            image_proto: None,
            image_loading: false,
            rkey: "pending".to_string(),
        });

        // Store locally with placeholder rkey (will be real once publish completes)
        let stored_msg = crate::keystore::StoredMessage {
            rkey: "pending".to_string(),
            content: preview,
            timestamp,
            is_own: true,
            message_id: encrypted.message_id.clone(),
            sender_did: Some(my_did),
            sender_device: self.keys.get_or_create_device_name().ok(),
            blob_uri: None, blob_key: None, blob_ciphertext_hash: None, blob_ciphertext_size: None, blob_content_hash: None, blob_mime: None, blob_width: None, blob_height: None, blob_thumbhash: None,
                    reactions: Vec::new(),
        };
        if let Err(e) = self.keys.append_message(&conv_id, stored_msg) {
            self.debug_log
                .log(&format!("send_message: failed to store locally: {}", e));
        }

        // Clear input immediately (before network)
        self.input_buffer.clear();
        self.cursor_position = 0;

        // Spawn network publish in background
        let client = self.client.as_ref().unwrap().clone();
        let tag = encrypted.tag;
        let ciphertext = encrypted.ciphertext;
        let msg_id = encrypted.message_id.clone();
        let conv_id_clone = conv_id;
        let tx = self.bg_tx.clone();

        tokio::spawn(async move {
            match client.publish_event(&tag, &ciphertext, None).await {
                Ok(uri) => {
                    let _ = tx.send(BgEvent::SendPublished {
                        uri,
                        conv_id: conv_id_clone,
                        tag,
                        ciphertext,
                        message_id: msg_id,
                    });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::SendFailed(format!("{e}")));
                }
            }
        });

        Ok(())
    }

    /// Send an emoji reaction to the currently selected message
    async fn send_reaction(&mut self, emoji: &str) -> Result<()> {
        // Find the selected message (selected_message is offset from bottom)
        let msg_index = {
            let offset = self.selected_message.unwrap_or(0);
            self.messages.len().saturating_sub(1).saturating_sub(offset)
        };
        let target_message_id = match self
            .messages
            .get(msg_index)
            .and_then(|m| m.message_id.clone())
        {
            Some(id) => id,
            None => {
                self.error_message = Some("Cannot react: message has no ID".to_string());
                return Ok(());
            }
        };

        self.send_reaction_by_id(&target_message_id, emoji).await
    }

    /// Poll for new devices belonging to our own DID and auto-add them.
    ///
    /// Each user is responsible for adding their own devices. This ensures:
    /// - The welcome is published to our own PDS where our new device can find it
    /// - No race conditions with other users trying to add the same device
    /// - Simple, predictable behavior
    async fn poll_for_new_devices(&mut self) -> Result<()> {
        // Same-user fan-out: we walk every confirmed ring sibling, and
        // for each user conversation they are not yet in we draw a
        // fresh KP from the pool, MLS-add them, and ship the Welcome
        // as a `CoordMsg::UserConvWelcome` stealth event addressed to
        // the sibling.  If the local pool is empty for a sibling, we
        // emit one `CoordMsg::KpRequest` per poll cycle (also
        // stealth-addressed) and defer the add — the next tick
        // retries once the owner ships a fresh `CoordMsg::KpBatch`.
        // The init key consumed comes from the KP-lane pool, not the
        // PDS pool, so no replenish on the cross-user
        // `social.moat.keyPackage` pool is required.
        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?.clone();
        let my_did = client.did().to_string();

        // No ring → no ring-borne KPs → nothing to fan out.  Bootstrap
        // and ring formation happen elsewhere; we wait for them.
        if self.ring_driver.ring_id().is_none() {
            return Ok(());
        }

        let siblings = self.ring_driver.ring_joined_siblings(&self.mls);
        if siblings.is_empty() {
            return Ok(());
        }

        let key_bundle = self
            .keys
            .load_identity_key()
            .map_err(|e| AppError::Other(format!("poll_devices: load_identity_key: {e}")))?;
        let device_name = self
            .keys
            .get_or_create_device_name()
            .map_err(|e| AppError::Other(format!("poll_devices: get_device_name: {e}")))?;
        let credential = MoatCredential::new(&my_did, &device_name, *self.mls.device_id());
        let sibling_stealth = self.cached_sibling_stealth.clone();
        let env = StepEnv {
            my_did: &my_did,
            credential: &credential,
            key_bundle: &key_bundle,
            now_ms: chrono::Utc::now().timestamp_millis(),
            sibling_stealth: &sibling_stealth,
        };

        // Snapshot conversations so we can mutate `self` later.
        let groups: Vec<(Vec<u8>, String)> = self
            .conversations
            .iter()
            .filter_map(|c| hex::decode(&c.id).ok().map(|g| (g, c.id.clone())))
            .collect();

        // Once per cycle, send at most one KpRequest per sibling whose
        // pool is empty.  Without this, fan-out across N conversations
        // with an empty pool would emit N redundant requests.
        let mut requested_refill: HashSet<[u8; 16]> = HashSet::new();

        for (group_id, conv_id) in &groups {
            let current_members = match self.mls.get_group_members(group_id) {
                Ok(m) => m,
                Err(e) => {
                    self.debug_log
                        .log(&format!("poll_devices: get_group_members: {e}"));
                    continue;
                }
            };
            let existing_device_ids: HashSet<[u8; 16]> = current_members
                .iter()
                .filter_map(|(_, c)| c.as_ref().map(|c| *c.device_id()))
                .collect();

            self.debug_log.log(&format!(
                "poll_devices: group {} has {} devices",
                &conv_id[..16.min(conv_id.len())],
                existing_device_ids.len()
            ));

            for sibling_id in &siblings {
                if existing_device_ids.contains(sibling_id) {
                    continue;
                }

                // Ring-borne KP claim.  None ⇒ pool drained; defer.
                let kp = match self.ring_driver.claim_kp(sibling_id) {
                    Some(k) => k,
                    None => {
                        if requested_refill.insert(*sibling_id) {
                            let cmds = self.ring_driver.emit_kp_request_for(
                                &self.mls,
                                &env,
                                sibling_id,
                            );
                            for cmd in cmds {
                                self.publish_ring_command(&client, cmd).await;
                            }
                            self.debug_log.log(&format!(
                                "poll_devices: KP pool empty for sibling {}; emitted KpRequest, deferring",
                                hex::encode(sibling_id)
                            ));
                        }
                        continue;
                    }
                };

                let welcome_result = match self.mls.add_device(group_id, &key_bundle, &kp.key_package) {
                    Ok(w) => w,
                    Err(e) => {
                        self.debug_log.log(&format!(
                            "poll_devices: add_device for sibling {} failed: {e}",
                            hex::encode(sibling_id)
                        ));
                        continue;
                    }
                };

                if let Err(e) = self.save_mls_state() {
                    self.debug_log
                        .log(&format!("poll_devices: save_mls_state: {e}"));
                }

                self.register_group_tags(conv_id, group_id);

                if let Err(e) = client
                    .publish_event(&welcome_result.commit_tag, &welcome_result.commit, None)
                    .await
                {
                    self.debug_log
                        .log(&format!("poll_devices: publish commit: {e}"));
                } else {
                    self.debug_log.log("poll_devices: published commit");
                }

                // Stealth-addressed Welcome, same lane as sibling messages.
                // Other users in this group see the Commit via the PDS as
                // before; only the same-user delivery channel changes.
                let msg = CoordMsg::UserConvWelcome {
                    owner_device_id: sibling_id.to_vec(),
                    group_id: group_id.clone(),
                    welcome: welcome_result.welcome,
                };
                if let Some(cmd) =
                    self.ring_driver.encrypt_for_sibling(&self.mls, &env, sibling_id, &msg)
                {
                    self.publish_ring_command(&client, cmd).await;
                    self.debug_log.log(&format!(
                        "poll_devices: published UserConvWelcome for sibling {} in group {}",
                        hex::encode(sibling_id),
                        &conv_id[..16.min(conv_id.len())]
                    ));
                } else {
                    self.debug_log
                        .log("poll_devices: encrypt_for_sibling(UserConvWelcome) failed — sibling stealth record not yet known");
                }

                let conv_name = self
                    .conversations
                    .iter()
                    .find(|c| c.id == *conv_id)
                    .map(|c| c.display_name())
                    .unwrap_or_else(|| "Unknown".to_string());

                if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == *conv_id) {
                    if let Ok(Some(new_epoch)) = self.mls.get_group_epoch(group_id) {
                        conv.current_epoch = new_epoch;
                    }
                }

                let sibling_display = self
                    .ring_driver
                    .ring_id()
                    .map(<[u8]>::to_vec)
                    .and_then(|rid| self.mls.get_group_members(&rid).ok())
                    .and_then(|members| {
                        members.into_iter().find_map(|(_, c)| {
                            c.as_ref().and_then(|c| {
                                if c.device_id() == sibling_id {
                                    Some(c.device_name().to_string())
                                } else {
                                    None
                                }
                            })
                        })
                    })
                    .unwrap_or_else(|| hex::encode(sibling_id));

                self.device_alerts.push(DeviceAlert {
                    conversation_name: conv_name,
                    user_name: my_did.clone(),
                    device_name: sibling_display,
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        Ok(())
    }

    /// Publish a single [`RingCommand::PublishEvent`] produced by the
    /// ring driver (e.g., the `KpRequest` or `UserConvWelcome` that the
    /// same-user fan-out path emits outside the normal ring_tick loop).
    /// Any other variant is unexpected here — log and drop.
    async fn publish_ring_command(
        &mut self,
        client: &moat_atproto::MoatAtprotoClient,
        cmd: RingCommand,
    ) {
        match cmd {
            RingCommand::PublishStealthEvent { tag, ciphertext } => {
                // Same-user KP lane (KpBatch / KpRequest / UserConvWelcome),
                // stealth-addressed to a specific sibling.  Stealth payloads
                // are decrypted out-of-band by the recipient, so they are
                // never marked own.
                if let Err(e) = client.publish_event(&tag, &ciphertext, None).await {
                    self.debug_log
                        .log(&format!("publish_ring_command: stealth publish failed: {e}"));
                }
            }
            other => {
                self.debug_log.log(&format!(
                    "publish_ring_command: unexpected variant {other:?} — dropping"
                ));
            }
        }
    }

    // ── Device ring ───────────────────────────────────────────────────────────

    /// Periodic ring driver tick. Called from the main loop every ~30 s.
    pub async fn do_ring_tick(&mut self) {
        // The session has no clock of its own; this is the tick that
        // supplies one on the TUI, where nothing polls `/sync/status`.
        self.expire_sync_request_if_due();
        self.last_ring_tick = Some(Instant::now());
        if let Err(e) = self.ring_tick_inner().await {
            self.debug_log.log(&format!("ring_tick: {e}"));
        }
    }

    async fn ring_tick_inner(&mut self) -> Result<()> {
        use moat_core::{KeyPackageInput, OwnEventInput, TickInputs};

        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?.clone();
        let my_did = client.did().to_string();

        let key_bundle = self.keys.load_identity_key().map_err(|e| {
            AppError::Other(format!("ring: failed to load identity key: {e}"))
        })?;
        let stealth_privkey = self.keys.load_stealth_key().map_err(|e| {
            AppError::Other(format!("ring: failed to load stealth key: {e}"))
        })?;
        let device_name = self.keys.get_or_create_device_name().map_err(|e| {
            AppError::Other(format!("ring: failed to get device name: {e}"))
        })?;
        let credential = MoatCredential::new(&my_did, &device_name, *self.mls.device_id());

        // ── Gather inputs (host I/O) ─────────────────────────────────────────
        let key_package_records =
            client.fetch_key_packages(&my_did).await.unwrap_or_default();
        let key_packages: Vec<KeyPackageInput> = key_package_records
            .into_iter()
            .map(|kp| KeyPackageInput { key_package: kp.key_package })
            .collect();

        // Classify the pool exactly as `DeviceRingState::tick` will, so the
        // log answers "did the driver see any siblings at all?" directly.
        // A ring that never forms because the pool held nothing but our own
        // packages looks identical, from the outside, to one that fails for
        // a state-machine reason — and telling those apart from artifacts
        // alone is what this instrumentation exists for.
        let (mut kp_mine, mut kp_siblings, mut kp_unreadable, mut kp_foreign) = (0, 0, 0, 0);
        let mut kp_mine_live = 0;
        let mut sibling_ids: Vec<String> = Vec::new();
        for kp in &key_packages {
            match self.mls.extract_credential_from_key_package(&kp.key_package) {
                Ok(Some(cred)) => {
                    if cred.did() != my_did {
                        kp_foreign += 1;
                    } else if *cred.device_id() == *self.mls.device_id() {
                        kp_mine += 1;
                        // Published *and* still openable by us — the number of
                        // outstanding invitations to this device that could
                        // actually succeed. Zero means un-invitable.
                        if self.mls.holds_init_key(&kp.key_package) {
                            kp_mine_live += 1;
                        }
                    } else {
                        kp_siblings += 1;
                        let id = hex::encode(&cred.device_id()[..4]);
                        if !sibling_ids.contains(&id) {
                            sibling_ids.push(id);
                        }
                    }
                }
                _ => kp_unreadable += 1,
            }
        }

        let stealth_records = client
            .fetch_stealth_addresses(&my_did)
            .await
            .unwrap_or_default();
        let stealth_pubkeys: Vec<[u8; 32]> =
            stealth_records.iter().map(|r| r.scan_pubkey).collect();
        // Per-sibling addressing for the same-user KP lane: drop our own device
        let my_device_id = *self.mls.device_id();
        let sibling_stealth: Vec<moat_core::SiblingStealth> = stealth_records
            .iter()
            .filter(|r| r.device_id != [0u8; 16] && r.device_id != my_device_id)
            .map(|r| moat_core::SiblingStealth {
                scan_pubkey: r.scan_pubkey,
                device_id: r.device_id,
            })
            .collect();
        // Cache for callers outside this tick (poll_for_new_devices,
        // handle_coord_msg_sync) that also need to stealth-address a
        // sibling for the same-user KP lane.
        self.cached_sibling_stealth = sibling_stealth.clone();

        let event_records = client
            .fetch_events_from_did(&my_did, self.ring_driver.own_events_cursor())
            .await
            .unwrap_or_default();
        let own_events: Vec<OwnEventInput> = event_records
            .into_iter()
            .map(|e| OwnEventInput { rkey: e.rkey, ciphertext: e.ciphertext })
            .collect();

        let now_ms = chrono::Utc::now().timestamp_millis();

        self.debug_log.log(&format!(
            "ring: tick in  kp={} (mine={kp_mine} mine_live={kp_mine_live} siblings={kp_siblings} \
             foreign={kp_foreign} unreadable={kp_unreadable}) sibling_ids=[{}] stealth={} \
             sibling_stealth={} own_events={} | {}",
            key_packages.len(),
            sibling_ids.join(","),
            stealth_pubkeys.len(),
            sibling_stealth.len(),
            own_events.len(),
            self.ring_driver.debug_summary(),
        ));

        // ── Drive the ring state machine ─────────────────────────────────────
        let cmds = self.ring_driver.tick(
            &self.mls,
            TickInputs {
                key_packages: &key_packages,
                sibling_stealth: &sibling_stealth,
                own_events: &own_events,
                stealth_privkey: &stealth_privkey,
                credential: &credential,
                key_bundle: &key_bundle,
                now_ms,
                my_did: &my_did,
            },
        );

        let _ = self.save_mls_state();

        self.debug_log.log(&format!(
            "ring: tick out cmds=[{}] | {}",
            moat_core::summarize_ring_commands(&cmds),
            self.ring_driver.debug_summary(),
        ));
        // Persist the driver state now, not only on the periodic save. The
        // last on-disk snapshot is the primary post-mortem artifact for a
        // beacon failure, and if it lags the failure it reports peer state
        // that never caused anything.
        if let Err(e) = self.keys.save_ring_state(&self.ring_driver) {
            self.debug_log.log(&format!("ring: failed to persist ring state: {e}"));
        }

        // ── Interpret commands ───────────────────────────────────────────────
        let mut needs_poll_for_new_devices = false;
        for cmd in cmds {
            match cmd {
                RingCommand::PublishStealthEvent { tag, ciphertext } => {
                    if let Err(e) = client.publish_event(&tag, &ciphertext, None).await {
                        self.debug_log
                            .log(&format!("ring: failed to publish stealth event: {e}"));
                    }
                }
                RingCommand::RegisterGroup { group_id, kind } => {
                    let group_id_hex = hex::encode(&group_id);
                    let is_user_group = kind == GroupKind::User;
                    let _ = self.keys.store_group_metadata(
                        &group_id_hex,
                        &GroupMetadata {
                            participant_dids: vec![my_did.clone()],
                            participant_handles: vec![],
                            kind,
                            pending_ex_members: Vec::new(),
                            member_device_ids: Default::default(),
                        },
                    );
                    self.register_group_tags(&group_id_hex, &group_id);

                    // User conversations discovered via ring_tick step-3 stealth
                    // Welcome scan, and same-user fan-out via Phase E
                    // `UserConvWelcome`, both need to be surfaced in
                    // self.conversations here.  Whether the cross-user
                    // `social.moat.keyPackage` pool needs replenishing is
                    // signalled explicitly by `RingCommand::ReplenishKeyPackage`
                    // — the cross-user stealth-Welcome path emits it, the
                    // same-user `UserConvWelcome` path does not (the consumed
                    // init key came from the ring-borne pool).
                    if is_user_group {
                        let participant_dids = self
                            .mls
                            .get_group_dids(&group_id)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|d| d != &my_did)
                            .collect::<Vec<_>>();
                        let participant_handles = participant_dids.clone();
                        match self
                            .conversations
                            .iter_mut()
                            .find(|c| c.id == group_id_hex)
                        {
                            // A read-only placeholder: its history arrived
                            // by sync before the Add that put us in the
                            // group. This is the moment it stops being
                            // read-only, and the moment the participants
                            // become knowable from MLS rather than
                            // guessed from senders.
                            //
                            // Guarded on `!is_member` so a repeat
                            // registration of a conversation we are
                            // already in leaves it alone — overwriting
                            // there would replace resolved handles with
                            // bare DIDs.
                            Some(existing) if !existing.is_member => {
                                existing.is_member = true;
                                existing.participant_dids = participant_dids.clone();
                                existing.participant_handles = participant_handles;
                            }
                            Some(_) => {}
                            None => self.conversations.push(Conversation {
                                id: group_id_hex.clone(),
                                name: None,
                                participant_dids: participant_dids.clone(),
                                participant_handles,
                                current_epoch: 1,
                                unread: 1,
                                is_member: true,
                            }),
                        }
                    }
                }
                RingCommand::ReplenishKeyPackage => {
                    self.replenish_key_package();
                }
                RingCommand::PollForNewDevices => {
                    needs_poll_for_new_devices = true;
                }
            }
        }

        if needs_poll_for_new_devices {
            let _ = self.poll_for_new_devices().await;
        }

        // Persist ring state
        if let Err(e) = self.keys.save_ring_state(&self.ring_driver) {
            self.debug_log
                .log(&format!("ring: failed to save ring state: {e}"));
        }

        Ok(())
    }

    /// Dismiss the oldest device alert
    pub fn dismiss_device_alert(&mut self) {
        if !self.device_alerts.is_empty() {
            self.device_alerts.remove(0);
        }
    }

    // ── History sync ───────────────────────────────────────────────────────────

    /// Build and start a `SyncSession` once the pair WS reports `PairConnected`.
    fn start_sync_session(&mut self) {
        let ring_id = match self.ring_driver.ring_id().map(<[u8]>::to_vec) {
            Some(id) => id,
            None => return,
        };
        let key_bundle = match self.keys.load_identity_key() {
            Ok(k) => k,
            Err(_) => return,
        };
        let ring_epoch = self.mls.get_group_epoch(&ring_id).ok().flatten().unwrap_or(0);

        let (session, outputs) = self.build_paired_sync_session(ring_epoch);
        self.sync_session = Some(session);
        self.process_sync_outputs(outputs, &ring_id, &key_bundle);
    }

    /// Build a fresh `SyncSession` and its initial `on_paired` outputs, from
    /// local keystore/digest state. Shared by `start_sync_session`
    /// (established-devices reconnect-sync, ring-MLS wire encryption) and
    /// `start_pairing_sync_session` (pairing-driven onboarding sync,
    /// pairing-AEAD wire encryption per qr-pairing.md §3.2) — only the wire
    /// encryption differs between the two.
    fn build_paired_sync_session(
        &self,
        ring_epoch: u64,
    ) -> (crate::sync::SyncSession, Vec<crate::sync::SyncOutput>) {
        use crate::sync::ConvState;

        // Collect all user conversations with their digest state.
        let conv_ids: Vec<String> = self.conversations.iter().map(|c| c.id.clone()).collect();
        let mut session = crate::sync::SyncSession::new();

        for conv_id in &conv_ids {
            let group_id = match hex::decode(conv_id) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let our_messages = self.keys.load_messages(conv_id)
                .map(|cm| cm.messages)
                .unwrap_or_default();
            let our_messages: Vec<crate::sync::SyncMessage> = our_messages.into_iter()
                .filter(|m| m.rkey != "pending")
                .map(|m| crate::sync::sync_message_from_stored(&m))
                .collect();
            let has_history = !our_messages.is_empty();
            session.add_conv_plan(group_id.clone(), conv_id.clone(), our_messages, !has_history);
        }

        // Build our ConvState list for the Hello.
        let mut our_convs: Vec<ConvState> = conv_ids.iter().filter_map(|conv_id| {
            let group_id = hex::decode(conv_id).ok()?;
            // The rkeys we hold, so the peer sends exactly the complement
            // rather than its whole history. Read from the keystore rather
            // than `mls.range`, which only tracks events that arrived
            // through `decrypt_event` — messages received by an earlier
            // sync are in the keystore only, and omitting them would ask
            // for them all over again.
            let held: Vec<String> = self
                .keys
                .load_messages(conv_id)
                .map(|cm| cm.messages)
                .unwrap_or_default()
                .into_iter()
                .filter(|m| m.rkey != "pending")
                .map(|m| m.rkey)
                .collect();

            Some(ConvState {
                group_id,
                inventory: moat_core::ConvInventory::of(held),
            })
        }).collect();
        // One Hello carries every conversation, against a hard 1 MiB frame
        // limit that closes the connection rather than truncating — so the
        // budget has to be spent across the whole message.
        moat_core::fit_hello_inventories(&mut our_convs);

        let outputs = session.on_paired(our_convs, ring_epoch);
        (session, outputs)
    }

    /// Build and start a `SyncSession` under the *pairing* AEAD channel —
    /// the `PairingCommand::StartSync` handoff, driven by a `PairingSession`
    /// that just finished Enroll/Admit/Done. Per qr-pairing.md §3.2 this
    /// keeps using the pairing AEAD (continuing its counter sequence via
    /// `channel_keys`/`next_send_counter`/`next_recv_counter`) rather than
    /// re-keying to ring MLS like `start_sync_session` does — the new
    /// device in particular has no ring-MLS traffic history to fall back
    /// on for this exchange, and mixing the two wire formats on one pair
    /// WS is exactly the bug this split avoids.
    fn start_pairing_sync_session(&mut self) {
        let Some(pairing) = self.pairing_session.as_ref() else { return };
        self.pairing_sync_keys = Some(pairing.channel_keys().clone());
        self.pairing_sync_send_counter = pairing.next_send_counter();
        self.pairing_sync_recv_counter = pairing.next_recv_counter();

        let ring_id = match self.ring_driver.ring_id().map(<[u8]>::to_vec) {
            Some(id) => id,
            None => return,
        };
        let ring_epoch = self.mls.get_group_epoch(&ring_id).ok().flatten().unwrap_or(0);

        let (session, outputs) = self.build_paired_sync_session(ring_epoch);
        self.sync_session = Some(session);
        self.process_pairing_sync_outputs(outputs);
    }


    /// Surface a conversation whose history arrived by sync before we were
    /// a member of it.
    ///
    /// `handle_hello` plans for every conversation the peer has and we do
    /// not, so a donor can serve history for a group whose fan-out `Add`
    /// has not reached us yet. Without this the messages land in storage
    /// and are visible nowhere — the conversation list is built from
    /// group metadata, and there is none.
    ///
    /// Registered read-only: participants are inferred from who actually
    /// sent the messages, since there is no local MLS group to ask, and
    /// `is_member` stays false until the `Add` arrives and
    /// `RingCommand::RegisterGroup` upgrades it. The composer is closed
    /// meanwhile, because there is genuinely nothing to send into.
    ///
    /// Normally transient: the peer that had the history is in the
    /// conversation and its `poll_for_new_devices` adds us. Not
    /// guaranteed to be brief, though — an Add can only come from a
    /// member, so if the donor was the only one and it goes offline right
    /// after the transfer, nothing adds us until it returns.
    fn register_synced_conversation(&mut self, conv_id: &str, messages: &[crate::sync::SyncMessage]) {
        if self.conversations.iter().any(|c| c.id == conv_id) {
            return;
        }
        let Ok(group_id) = hex::decode(conv_id) else { return };
        // A group we are actually in has local MLS state; one we only
        // hold history for does not. Same check the conversation list
        // makes on load.
        if self.mls.get_group_epoch(&group_id).ok().flatten().is_some() {
            return;
        }

        let my_did = self.client.as_ref().map(|c| c.did().to_string());
        let mut participant_dids: Vec<String> = Vec::new();
        for m in messages {
            if Some(&m.sender_did) == my_did.as_ref() {
                continue;
            }
            if !participant_dids.contains(&m.sender_did) {
                participant_dids.push(m.sender_did.clone());
            }
        }

        let metadata = GroupMetadata {
            participant_dids: participant_dids.clone(),
            participant_handles: Vec::new(),
            kind: GroupKind::User,
            pending_ex_members: Vec::new(),
            member_device_ids: Default::default(),
        };
        if let Err(e) = self.keys.store_group_metadata(conv_id, &metadata) {
            self.debug_log
                .log(&format!("sync: could not persist synced conversation {conv_id}: {e}"));
            return;
        }

        self.debug_log.log(&format!(
            "sync: registering {conv_id} read-only — history arrived before membership"
        ));
        self.conversations.push(Conversation {
            id: conv_id.to_string(),
            name: None,
            participant_handles: participant_dids.clone(),
            participant_dids,
            current_epoch: 1,
            unread: messages.len(),
            is_member: false,
        });
    }

    /// Process `SyncOutput` actions from the state machine.
    fn process_sync_outputs(
        &mut self,
        outputs: Vec<crate::sync::SyncOutput>,
        ring_id: &[u8],
        key_bundle: &[u8],
    ) {
        use crate::sync::SyncOutput;

        for output in outputs {
            match output {
                SyncOutput::Send(msg) => {
                    let payload = crate::sync::encode_sync_msg(&msg);
                    let epoch = self.mls.get_group_epoch(ring_id).ok().flatten().unwrap_or(0);
                    let event = Event::sync_app(ring_id.to_vec(), epoch, payload);
                    if let Ok(enc) = self.mls.encrypt_event(ring_id, key_bundle, &event) {
                        let _ = self.save_mls_state();
                        let _ = self.bg_tx.send(BgEvent::DrawbridgeSendPairBinary { data: enc.ciphertext });
                    }
                }
                SyncOutput::Store { conv_id, messages } => {
                    self.register_synced_conversation(&conv_id, &messages);
                    let my_did = self.client.as_ref().map(|c| c.did().to_string());
                    for sync_msg in messages {
                        let mut stored = crate::sync::stored_from_sync_message(&sync_msg);
                        // Mark is_own based on sender_did vs our DID.
                        if let (Some(ref did), Some(ref sender)) = (&my_did, &stored.sender_did) {
                            stored.is_own = sender == did;
                        }
                        let _ = self.keys.append_message(&conv_id, stored);
                    }
                    self.debug_log.log(&format!("sync: stored batch for conv {conv_id}"));
                    // Refresh UI if this is the active conversation.
                    let active_id = self.active_conversation
                        .and_then(|i| self.conversations.get(i))
                        .map(|c| c.id.clone());
                    if active_id.as_deref() == Some(&conv_id) {
                        let _ = self.load_messages();
                    }
                }
            }
        }

        // Teardown happens after every output has been applied, never as
        // one of them: closing the channel mid-list would strand whatever
        // followed.
        if self.sync_session.as_ref().is_some_and(|s| s.is_done()) {
            let tally = self
                .sync_session
                .as_ref()
                .map(crate::sync::SyncSession::tally)
                .unwrap_or_default();
            self.debug_log.log(&format!(
                "sync: session complete — {} message(s) across {} conversation(s); closing pair WS",
                tally.messages, tally.conversations
            ));
            self.sync_session = None;
            self.pending_pair_token = None;
            self.drawbridge.clear_pair();
            let peer_name = self.sync_peer_name.take();
            if let Some(session) = self.sync_request.as_mut() {
                session.on_complete(tally, peer_name);
            }
        }
    }

    /// Decrypt and dispatch an incoming binary frame from the pair WS.
    fn process_sync_frame(&mut self, data: Vec<u8>) {
        use moat_core::EventKind;

        let ring_id = match self.ring_driver.ring_id().map(<[u8]>::to_vec) {
            Some(id) => id,
            None => return,
        };
        let key_bundle = match self.keys.load_identity_key() {
            Ok(k) => k,
            Err(_) => return,
        };
        // A precondition, not a value: the `Store` arm needs our DID to
        // decide which synced messages are our own, so a frame arriving
        // while logged out has nowhere to go.
        if self.client.is_none() {
            return;
        }

        let outcome = match self.mls.decrypt_event(&ring_id, &data) {
            Ok(o) => o,
            Err(e) => {
                self.debug_log.log(&format!("sync: decrypt_event failed: {e}"));
                return;
            }
        };
        let _ = self.save_mls_state();

        let decrypted = outcome.into_result();
        if !matches!(decrypted.event.kind, EventKind::SyncApp) {
            self.debug_log.log("sync: unexpected event kind on pair WS");
            return;
        }

        // Whoever is on the other end, named by MLS rather than by
        // anything the payload claims. Every frame carries it; keeping the
        // latest is enough, since a pair channel has exactly one peer.
        if let Some(sender) = decrypted.sender.as_ref() {
            self.sync_peer_name = Some(sender.device_name.clone());
        }

        let msg = match crate::sync::decode_sync_msg(&decrypted.event.payload) {
            Ok(m) => m,
            Err(e) => {
                self.debug_log.log(&format!("sync: decode_sync_msg failed: {e}"));
                return;
            }
        };

        let outputs = match self.sync_session.as_mut() {
            Some(session) => session.on_message(msg),
            None => {
                self.debug_log.log("sync: frame received but no active session");
                return;
            }
        };

        let ring_id_clone = ring_id.clone();
        let outputs = match outputs {
            Ok(o) => o,
            Err(e) => {
                // A message the session can't account for means the peer
                // believes it delivered something we did not take. Abort
                // loudly rather than continue a sync that is now wrong.
                self.debug_log.log(&format!("sync: protocol error: {e}"));
                self.sync_session = None;
                self.drawbridge.clear_pair();
                if let Some(req) = self.sync_request.as_mut() {
                    req.fail(moat_core::SyncFailure::ChannelClosed {
                        detail: e.to_string(),
                    });
                }
                return;
            }
        };
        self.process_sync_outputs(outputs, &ring_id_clone, &key_bundle);
    }

    /// Process `SyncOutput` actions under the pairing AEAD — the
    /// `process_sync_outputs` counterpart for the pairing-driven handoff
    /// (see `start_pairing_sync_session`). `Store`/`Complete` handling is
    /// identical; only `Send` differs (seal via pairing AEAD instead of
    /// ring-MLS `encrypt_event`).
    fn process_pairing_sync_outputs(&mut self, outputs: Vec<crate::sync::SyncOutput>) {
        use crate::sync::SyncOutput;

        for output in outputs {
            match output {
                SyncOutput::Send(msg) => {
                    let Some(keys) = self.pairing_sync_keys.clone() else { continue };
                    let send_key = match self.pairing_is_new_device {
                        Some(true) => &keys.k_new_to_old,
                        Some(false) => &keys.k_old_to_new,
                        None => continue,
                    };
                    let plaintext = crate::sync::encode_sync_msg(&msg);
                    let ciphertext = moat_core::seal_frame(
                        send_key,
                        self.pairing_sync_send_counter,
                        &plaintext,
                    );
                    self.pairing_sync_send_counter += 1;
                    let _ = self
                        .bg_tx
                        .send(BgEvent::DrawbridgeSendPairBinary { data: ciphertext });
                }
                SyncOutput::Store { conv_id, messages } => {
                    self.register_synced_conversation(&conv_id, &messages);
                    let my_did = self.client.as_ref().map(|c| c.did().to_string());
                    for sync_msg in messages {
                        let mut stored = crate::sync::stored_from_sync_message(&sync_msg);
                        // Mark is_own based on sender_did vs our DID.
                        if let (Some(ref did), Some(ref sender)) = (&my_did, &stored.sender_did) {
                            stored.is_own = sender == did;
                        }
                        let _ = self.keys.append_message(&conv_id, stored);
                    }
                    self.debug_log
                        .log(&format!("pairing-sync: stored batch for conv {conv_id}"));
                    let active_id = self.active_conversation
                        .and_then(|i| self.conversations.get(i))
                        .map(|c| c.id.clone());
                    if active_id.as_deref() == Some(&conv_id) {
                        let _ = self.load_messages();
                    }
                }
            }
        }

        // As in `process_sync_outputs`: tear down only once every output in
        // the batch has been applied, never as one of them.
        if self.sync_session.as_ref().is_some_and(|s| s.is_done()) {
            self.debug_log
                .log("pairing-sync: session complete — closing pair WS");
            self.sync_session = None;
            self.pairing_sync_keys = None;
            // Clear the role flag now — otherwise a later, unrelated
            // `PairConnected` (an established-devices reconnect-sync
            // session) would still route through the pairing-role match
            // arms instead of `start_sync_session`, since the flag outlives
            // this pairing and `pairing_session` itself is deliberately
            // never cleared (see its field doc).
            self.pairing_is_new_device = None;
            self.drawbridge.clear_pair();
        }
    }

    /// Open and dispatch an incoming binary frame under the pairing AEAD —
    /// the `process_sync_frame` counterpart for the pairing-driven handoff.
    fn process_pairing_sync_frame(&mut self, data: Vec<u8>) {
        let Some(keys) = self.pairing_sync_keys.clone() else { return };
        let recv_key = match self.pairing_is_new_device {
            Some(true) => &keys.k_old_to_new,
            Some(false) => &keys.k_new_to_old,
            None => return,
        };
        // A precondition, not a value: the `Store` arm needs our DID to
        // decide which synced messages are our own, so a frame arriving
        // while logged out has nowhere to go.
        if self.client.is_none() {
            return;
        }

        let plaintext = match moat_core::open_frame(recv_key, self.pairing_sync_recv_counter, &data)
        {
            Ok(p) => p,
            Err(e) => {
                self.debug_log
                    .log(&format!("pairing-sync: failed to open frame: {e}"));
                return;
            }
        };
        self.pairing_sync_recv_counter += 1;

        let msg = match crate::sync::decode_sync_msg(&plaintext) {
            Ok(m) => m,
            Err(e) => {
                // The new device's advisory `PairingMsg::Done` (a channel-
                // teardown courtesy, not load-bearing for either side's own
                // completion — see its doc in moat-core) can still be in
                // flight when the peer locally transitions to sync mode:
                // both sides do so as soon as *their own* processing
                // finishes, independent of what the other side has sent or
                // received yet. A `Done` that arrives after that transition
                // opens fine under the pairing AEAD (same channel, next
                // counter) but isn't a `SyncMsg` — recognize and ignore it
                // rather than logging a spurious decode error.
                if matches!(
                    moat_core::decode_pairing_msg(&plaintext),
                    Ok(moat_core::PairingMsg::Done)
                ) {
                    self.debug_log
                        .log("pairing-sync: received the pairing session's Done courtesy");
                } else {
                    self.debug_log.log(&format!("pairing-sync: decode_sync_msg failed: {e}"));
                }
                return;
            }
        };

        let outputs = match self.sync_session.as_mut() {
            Some(session) => session.on_message(msg),
            None => {
                self.debug_log
                    .log("pairing-sync: frame received but no active session");
                return;
            }
        };

        match outputs {
            Ok(o) => self.process_pairing_sync_outputs(o),
            Err(e) => {
                self.debug_log
                    .log(&format!("pairing-sync: protocol error: {e}"));
                self.sync_session = None;
                self.pairing_sync_keys = None;
                self.drawbridge.clear_pair();
            }
        }
    }

    /// Return the current sync status for the HTTP API.
    ///
    /// Takes `&mut self` so a request whose rendezvous has expired is
    /// reported as failed the moment it is *read*, not on the next 30s
    /// tick — a poller watching this endpoint would otherwise see
    /// `awaiting_peer` for up to half a minute after the token died.
    pub fn sync_status(&mut self) -> serde_json::Value {
        self.expire_sync_request_if_due();
        serde_json::json!({
            "active": self.sync_session.is_some(),
            "request": self.sync_request_ui_state(),
        })
    }

    // ── User-initiated sync between established devices ─────────────────────

    /// Move an unanswered sync request to `Failed` once its rendezvous
    /// token has expired. Driven from the periodic tick and from every
    /// read of the status, since the session has no clock of its own.
    pub fn expire_sync_request_if_due(&mut self) {
        let now_ms = chrono::Utc::now().timestamp_millis();
        if let Some(session) = self.sync_request.as_mut() {
            if session.expire_if_due(now_ms) {
                self.debug_log
                    .log("sync: request expired with no device answering");
            }
        }
    }

    /// Projection of the sync-request gesture, for `/sync/status` and the
    /// TUI. Never derived anywhere else — see [`SyncRequestSession`].
    pub fn sync_request_ui_state(&self) -> SyncRequestUiState {
        SyncRequestSession::ui_state_of(self.sync_request.as_ref())
    }

    /// HTTP `POST /sync/request` — ask the user's other devices for
    /// history this one is missing.
    ///
    /// Publishes a `RingMsg::SyncRequest` on the device ring and registers
    /// the same rendezvous token with the relay. Every online sibling
    /// prompts its user; whichever one they approve joins the rendezvous,
    /// and the transfer runs as an ordinary ring-encrypted
    /// [`crate::sync::SyncSession`]. There is no election and no automatic
    /// responder: the person holding the devices picks the one that has
    /// the history.
    pub fn api_sync_request(&mut self) -> Result<()> {
        self.api_sync_request_from(None)
    }

    /// HTTP `POST /sync/request` with a chosen donor.
    ///
    /// `target_device_id` names the sibling to ask; siblings that are not
    /// the target ignore the message rather than prompting about another
    /// device's business. `None` is the broadcast: every sibling prompts,
    /// and whichever the user approves on serves.
    pub fn api_sync_request_from(
        &mut self,
        target_device_id: Option<[u8; moat_core::DEVICE_ID_LEN]>,
    ) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        let ring_id = self
            .ring_driver
            .ring_id()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| AppError::Other("no device ring — pair a device first".to_string()))?;
        let key_bundle = self.keys.load_identity_key()?;

        use rand::RngCore;
        let mut token = [0u8; moat_core::SYNC_REQUEST_TOKEN_LEN];
        rand::thread_rng().fill_bytes(&mut token);

        // Seal the request to the ring first: if this fails there is no
        // point registering a rendezvous nobody will ever be told about.
        let epoch = self.mls.get_group_epoch(&ring_id).ok().flatten().unwrap_or(0);
        let payload =
            moat_core::encode_ring_msg(&RingMsg::SyncRequest { token, target_device_id });
        let event = Event::ring_msg(ring_id.clone(), epoch, payload);
        let encrypted = self
            .mls
            .encrypt_event(&ring_id, &key_bundle, &event)
            .map_err(AppError::Mls)?;
        let _ = self.save_mls_state();

        // Whatever occupied the pair channel before is superseded — a
        // device drives one pair session at a time (see `api_pair_new`).
        self.drawbridge.clear_pair();
        self.sync_session = None;
        self.pairing_sync_keys = None;
        self.pairing_session = None;
        // `None` routes `PairConnected` to `start_sync_session` — the
        // ring-MLS-encrypted path, not the pairing AEAD.
        self.pairing_is_new_device = None;
        self.pending_pair_rendezvous_token = Some(token.to_vec());
        self.sync_request = Some(SyncRequestSession::request(
            token,
            chrono::Utc::now().timestamp_millis(),
        ));

        let _ = self
            .bg_tx
            .send(BgEvent::DrawbridgeSendPairOffer { token: token.to_vec() });
        let _ = self.bg_tx.send(BgEvent::PublishRingEvent {
            tag: encrypted.tag,
            ciphertext: encrypted.ciphertext,
        });
        Ok(())
    }

    /// HTTP `POST /sync/offer` — send history to another device.
    ///
    /// The mirror of a request, for when the device holding the history
    /// is the one in the user's hands, so the user can send from here
    /// rather than walking to the other device to ask.
    ///
    /// This call *is* the human approval, so the target joins without a
    /// prompt of its own — exactly one approval per session, on the side
    /// that can judge. Always targeted: the relay admits two attaches, so
    /// an untargeted offer would pick its recipient arbitrarily.
    pub fn api_sync_offer(
        &mut self,
        target_device_id: [u8; moat_core::DEVICE_ID_LEN],
    ) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        if &target_device_id == self.mls.device_id() {
            return Err(AppError::Other("cannot offer history to this device".to_string()));
        }
        let ring_id = self
            .ring_driver
            .ring_id()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| AppError::Other("no device ring — pair a device first".to_string()))?;
        let key_bundle = self.keys.load_identity_key()?;

        use rand::RngCore;
        let mut token = [0u8; moat_core::SYNC_REQUEST_TOKEN_LEN];
        rand::thread_rng().fill_bytes(&mut token);

        // Seal to the ring first: there is no point registering a
        // rendezvous nobody will be told about.
        let epoch = self.mls.get_group_epoch(&ring_id).ok().flatten().unwrap_or(0);
        let payload = moat_core::encode_ring_msg(&RingMsg::SyncOffer {
            token,
            target_device_id,
        });
        let event = Event::ring_msg(ring_id.clone(), epoch, payload);
        let encrypted = self
            .mls
            .encrypt_event(&ring_id, &key_bundle, &event)
            .map_err(AppError::Mls)?;
        let _ = self.save_mls_state();

        self.drawbridge.clear_pair();
        self.sync_session = None;
        self.pairing_sync_keys = None;
        self.pairing_session = None;
        self.pairing_is_new_device = None;
        self.pending_pair_rendezvous_token = Some(token.to_vec());
        self.sync_request = Some(SyncRequestSession::offer(
            token,
            chrono::Utc::now().timestamp_millis(),
        ));

        let _ = self
            .bg_tx
            .send(BgEvent::DrawbridgeSendPairOffer { token: token.to_vec() });
        let _ = self.bg_tx.send(BgEvent::PublishRingEvent {
            tag: encrypted.tag,
            ciphertext: encrypted.ciphertext,
        });
        Ok(())
    }

    /// HTTP `POST /sync/accept` — send this device's history to the
    /// sibling that asked for it.
    pub fn api_sync_accept(&mut self) -> Result<()> {
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        let session = self
            .sync_request
            .as_mut()
            .ok_or_else(|| AppError::Other("no sync request to accept".to_string()))?;
        let token = session.accept().map_err(AppError::Mls)?;

        self.drawbridge.clear_pair();
        self.sync_session = None;
        self.pairing_sync_keys = None;
        self.pairing_session = None;
        self.pairing_is_new_device = None;
        self.pending_pair_rendezvous_token = Some(token.to_vec());

        let _ = self
            .bg_tx
            .send(BgEvent::DrawbridgeSendPairJoin { token: token.to_vec() });
        Ok(())
    }

    /// HTTP `POST /sync/decline` — refuse a sibling's request.
    ///
    /// Local only. With several siblings prompted, one refusal must not
    /// cancel the requester's outstanding request; it keeps waiting for
    /// another sibling or for its token to expire.
    pub fn api_sync_decline(&mut self) -> Result<()> {
        let session = self
            .sync_request
            .as_mut()
            .ok_or_else(|| AppError::Other("no sync request to decline".to_string()))?;
        session.decline();
        Ok(())
    }

    /// A sibling's `RingMsg::SyncRequest` arrived on the ring.
    ///
    /// `device_name` comes from the sender's MLS leaf credential, which is
    /// why this lane is the ring and not the stealth one: the prompt names
    /// an authenticated device rather than a self-declared payload field.
    fn on_sync_request_received(&mut self, token: [u8; 16], device_name: String) {
        let now_ms = chrono::Utc::now().timestamp_millis();

        // One sync session at a time. A live request of our own, or a
        // prompt the user is already looking at, outranks a new arrival —
        // superseding either would yank a decision out from under them.
        if let Some(existing) = self.sync_request.as_ref() {
            if !existing.is_terminal() && !existing.is_expired(now_ms) {
                self.debug_log
                    .log("sync: ignoring a sibling's request — one is already in flight");
                return;
            }
        }
        if self.pairing_session.as_ref().is_some_and(|s| !s.is_done()) {
            self.debug_log
                .log("sync: ignoring a sibling's request — a pairing is in flight");
            return;
        }

        self.debug_log
            .log(&format!("sync: {device_name} is asking for history"));
        self.sync_request = Some(SyncRequestSession::received(token, device_name, now_ms));
        self.focus = Focus::SyncApprove;
    }

    /// A sibling is offering us history.
    ///
    /// Joined without a prompt, deliberately. The rule is exactly one
    /// human approval per session, on the side that can judge — and for
    /// an offer that is the offerer, who already decided. Asking again
    /// here would be asking the user to approve receiving their own
    /// messages from a device that can already read them.
    ///
    /// Still refused while something else is in flight: an offer must not
    /// supersede a decision the user is already looking at.
    fn on_sync_offer_received(&mut self, token: [u8; 16], device_name: String) {
        let now_ms = chrono::Utc::now().timestamp_millis();

        if let Some(existing) = self.sync_request.as_ref() {
            if !existing.is_terminal() && !existing.is_expired(now_ms) {
                self.debug_log
                    .log("sync: ignoring an offer — a sync is already in flight");
                return;
            }
        }
        if self.pairing_session.as_ref().is_some_and(|s| !s.is_done()) {
            self.debug_log
                .log("sync: ignoring an offer — a pairing is in flight");
            return;
        }

        self.debug_log
            .log(&format!("sync: accepting {device_name}'s offer of history"));
        self.drawbridge.clear_pair();
        self.sync_session = None;
        self.pairing_sync_keys = None;
        self.pairing_session = None;
        // `None` routes `PairConnected` to `start_sync_session` — the
        // ring-MLS path, not the pairing AEAD.
        self.pairing_is_new_device = None;
        self.pending_pair_rendezvous_token = Some(token.to_vec());
        self.sync_request = Some(SyncRequestSession::accept_offer(token, now_ms));

        let _ = self
            .bg_tx
            .send(BgEvent::DrawbridgeSendPairJoin { token: token.to_vec() });
    }


    // ── Live pairing (QR / text code) device onboarding ─────────────────────

    /// Own credential/key_bundle/stealth pubkey, gathered synchronously the
    /// same way `ring_tick_inner`/`start_sync_session` do. `None` if any
    /// required local state is missing (not logged in, keys not loaded).
    fn own_pairing_identity(&self) -> Option<(MoatCredential, Vec<u8>, [u8; 32])> {
        let my_did = self.client.as_ref()?.did().to_string();
        let key_bundle = self.keys.load_identity_key().ok()?;
        let stealth_privkey = self.keys.load_stealth_key().ok()?;
        let device_name = self.keys.get_or_create_device_name().ok()?;
        let credential = MoatCredential::new(&my_did, &device_name, *self.mls.device_id());
        let stealth_pubkey = stealth_pubkey_from_privkey(&stealth_privkey);
        Some((credential, key_bundle, stealth_pubkey))
    }

    /// New device: build and send the `Enroll` frame once the pair WS
    /// reports `PairConnected`. No-op (logged) if local identity state
    /// isn't ready — there's no synchronous caller to report an error to.
    fn start_pairing_enroll(&mut self) {
        let Some((credential, key_bundle, stealth_pubkey)) = self.own_pairing_identity() else {
            self.debug_log.log("pairing: cannot start_enroll — identity not ready");
            return;
        };
        // Seed the approver's `kp_pools` entry for us directly
        // (`Enroll.conv_kps`), so it can fan us into pre-existing user
        // conversations immediately instead of waiting on a
        // KpRequest/KpBatch round trip over the stealth lane — this field's
        // whole purpose per qr-pairing.md §3.3. Mirrors
        // `DeviceRingState::build_kp_batch`'s generation (seq allocation +
        // fresh KeyPackage per entry), which is private to that module.
        let conv_kps: Vec<moat_core::OfferedKp> = {
            let seqs = self.ring_driver.allocate_kp_seqs(moat_core::KP_POOL_TARGET);
            let mut out = Vec::with_capacity(seqs.len());
            for seq in seqs {
                let Ok(kp_bytes) = self.mls.replenish_key_package(&credential, &key_bundle) else {
                    break;
                };
                let mut rkey = [0u8; 16];
                rand::Rng::fill(&mut rand::thread_rng(), &mut rkey);
                out.push(moat_core::OfferedKp {
                    rkey: rkey.to_vec(),
                    seq,
                    key_package: kp_bytes,
                });
            }
            out
        };
        let _ = self.keys.save_ring_state(&self.ring_driver);

        let Some(session) = self.pairing_session.as_mut() else { return };
        let cmds = match session.start_enroll(
            &self.mls,
            &credential,
            &key_bundle,
            stealth_pubkey,
            conv_kps,
        ) {
            Ok(cmds) => cmds,
            Err(e) => {
                // `start_enroll` already recorded `Failed { reason }` on
                // the session — don't null it out; `ui_state()` needs it.
                self.debug_log.log(&format!("pairing: start_enroll failed: {e}"));
                self.pending_pair_rendezvous_token = None;
                self.drawbridge.clear_pair();
                return;
            }
        };
        // start_enroll (the conv_kps loop above, and the ring_kp inside
        // start_enroll itself) consumes init keys via replenish_key_package
        // — persist now rather than relying on some later, unrelated
        // command to happen to save (qr-pairing.md Phase 5a: "the driver
        // calls save_mls_state itself after each mutation").
        let _ = self.save_mls_state();
        self.interpret_pairing_commands(cmds);
    }

    /// Feed a sealed frame received on the pair WS to the active
    /// `PairingSession`. On a protocol/crypto error, the session itself is
    /// already `Failed { reason }` (see `on_frame_received`'s doc) — this
    /// only tears down the *transport* (pair WS, rendezvous token), not the
    /// session, so `ui_state()` keeps reporting why it failed.
    fn handle_pairing_frame(&mut self, data: Vec<u8>) {
        let Some((credential, _key_bundle, _stealth_pubkey)) = self.own_pairing_identity() else {
            self.debug_log.log("pairing: cannot process frame — identity not ready");
            return;
        };
        let Some(session) = self.pairing_session.as_mut() else { return };
        match session.on_frame_received(&self.mls, &credential, &data) {
            Ok(cmds) => {
                // New device: this may have just processed a Welcome
                // (process_welcome) — the heaviest MLS mutation in this
                // flow. Persist immediately rather than relying on
                // PersistRing's follow-on RingTickNow to happen to save.
                let _ = self.save_mls_state();
                self.interpret_pairing_commands(cmds);
            }
            Err(e) => {
                self.debug_log.log(&format!("pairing: frame rejected: {e}"));
                self.pending_pair_rendezvous_token = None;
                self.drawbridge.clear_pair();
            }
        }
    }

    /// Existing device: assemble the roster of already-known ring siblings
    /// for `Admit.roster` — `device_name` comes from ring MLS member
    /// credentials, stealth key from `cached_sibling_stealth`. Empty for a
    /// first pairing (no ring, no siblings yet).
    fn known_pairing_siblings(&self) -> Vec<SiblingInfo> {
        let Some(ring_id) = self.ring_driver.ring_id() else {
            return Vec::new();
        };
        let members = self.mls.get_group_members(ring_id).unwrap_or_default();
        self.cached_sibling_stealth
            .iter()
            .filter_map(|s| {
                let device_name = members
                    .iter()
                    .find(|(_, cred)| cred.as_ref().map(|c| *c.device_id()) == Some(s.device_id))
                    .and_then(|(_, cred)| cred.as_ref())
                    .map(|c| c.device_name().to_string())?;
                Some(SiblingInfo {
                    device_id: s.device_id,
                    device_name,
                    stealth_pubkey: s.scan_pubkey,
                })
            })
            .collect()
    }

    /// Existing device: called once the user taps Approve (interactive UI)
    /// or `POST /pair/approve` is called (headless — no host auto-approves
    /// anymore; see `interpret_pairing_commands`'s `SurfaceApprovalPrompt`
    /// arm). Errors without side effects if identity state isn't ready or
    /// there's no active session; `session.approve()`'s own guard (no
    /// pending `Enroll`) is reported the same way.
    fn approve_pending_pairing(&mut self) -> Result<()> {
        let Some((credential, key_bundle, stealth_pubkey)) = self.own_pairing_identity() else {
            return Err(AppError::Other(
                "pairing: cannot approve — identity not ready".to_string(),
            ));
        };
        let existing_ring_id = self.ring_driver.ring_id().map(<[u8]>::to_vec);
        let is_first_pairing = existing_ring_id.is_none();
        let known_siblings = self.known_pairing_siblings();

        let Some(session) = self.pairing_session.as_mut() else {
            return Err(AppError::Other("no active pairing session".to_string()));
        };
        // `approve()` consumes `pending_enroll` internally and has no
        // command to hand the newcomer's stealth key back to the host —
        // `Admit.roster` only ever carries *already-known* siblings (see
        // its doc). Capture it now, before the call, so `poll_for_new_devices`
        // (triggered below on success) can actually reach the newcomer over
        // the stealth lane instead of silently finding no address for it.
        let newcomer_stealth = session
            .pending_enroll()
            .map(|e| (*e.credential.device_id(), e.stealth_scan_pubkey));
        let result = session.approve(
            &self.mls,
            &credential,
            &key_bundle,
            stealth_pubkey,
            &known_siblings,
            existing_ring_id.as_deref(),
        );
        // `approve()` records the ring id (freshly created or passed in) on
        // success; capture it now while `session` is still borrowed, since
        // — unlike the new device — nothing in `approve()`'s own command
        // list tells the *existing* device host to persist its own
        // membership (it already knew it was joining/creating `ring_id`).
        let new_ring_id = session.ring_id().map(<[u8]>::to_vec);

        match result {
            Ok(cmds) => {
                // approve() just performed create_device_ring/add_member —
                // the heaviest MLS mutations in this flow. Persist
                // immediately rather than relying on PollForNewDevicesNow
                // (enqueued below) to happen to save — it returns early
                // whenever there are no pre-existing conversations yet,
                // the common first-pairing case, which would otherwise
                // leave ring.json claiming InRing with no MLS group behind
                // it for up to 30s (until the next periodic ring tick).
                let _ = self.save_mls_state();
                if let Some(ref ring_id) = new_ring_id {
                    if is_first_pairing {
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        if let Err(e) = self.ring_driver.record_ring_membership(
                            &self.mls,
                            ring_id.clone(),
                            now_ms,
                        ) {
                            self.debug_log.log(&format!(
                                "pairing: record_ring_membership (approver) failed: {e}"
                            ));
                        }
                        let _ = self.keys.save_ring_state(&self.ring_driver);
                    }
                    // Candidate tags + group metadata for the ring,
                    // refreshed on *every* approve() (not just the first)
                    // since the epoch — and therefore the candidate tag
                    // set — advances on every Add. Without this a
                    // bystander sibling's poll could never recognize the
                    // commit `PublishRingCommit` is about to publish
                    // (there was previously no `RegisterGroup`-equivalent
                    // for the ring at all).
                    let ring_id_hex = hex::encode(ring_id);
                    let _ = self.keys.store_group_metadata(
                        &ring_id_hex,
                        &GroupMetadata {
                            participant_dids: vec![credential.did().to_string()],
                            participant_handles: vec![],
                            kind: GroupKind::Ring,
                            pending_ex_members: Vec::new(),
                            member_device_ids: Default::default(),
                        },
                    );
                    self.register_group_tags(&ring_id_hex, ring_id);
                }
                if let Some((device_id, scan_pubkey)) = newcomer_stealth {
                    if let Some(existing) = self
                        .cached_sibling_stealth
                        .iter_mut()
                        .find(|c| c.device_id == device_id)
                    {
                        existing.scan_pubkey = scan_pubkey;
                    } else {
                        self.cached_sibling_stealth
                            .push(SiblingStealth { scan_pubkey, device_id });
                    }
                }
                self.interpret_pairing_commands(cmds);
                // qr-pairing.md §2: "On approve: ring add + conversation
                // fan-out + history sync all run over the established
                // channel. The new device shows conversations within
                // seconds" — fan the newcomer into every pre-existing user
                // conversation right away rather than waiting for the next
                // periodic ring tick (every 30s, which can outlast a
                // bounded test/UX wait entirely).
                let _ = self.bg_tx.send(BgEvent::PollForNewDevicesNow);
                Ok(())
            }
            Err(e) => {
                // `approve()` already recorded `Failed { reason }` on the
                // session — don't null it out; `ui_state()` needs it.
                self.debug_log.log(&format!("pairing: approve failed: {e}"));
                self.pending_pair_rendezvous_token = None;
                self.drawbridge.clear_pair();
                Err(AppError::Mls(e))
            }
        }
    }

    /// Interpret `PairingCommand`s from `PairingSession` — mirrors the
    /// `RingCommand` interpreter in `ring_tick_inner` and
    /// `process_sync_outputs`. Deliberately does not clear
    /// `pairing_session` on `StartSync`: `ui_state()`/`GET /pair/status`
    /// must keep reporting the real terminal outcome after completion, not
    /// just at the instant it happens.
    ///
    /// `StartSync` is deferred to the end of the batch rather than acted on
    /// where it appears in `cmds`: it immediately sends a sync `Hello` at
    /// the *next* pairing-AEAD counter, so any `SendFrame` later in the
    /// same batch (e.g. the new device's `Done`, which follows `StartSync`
    /// in `PairingSession::on_frame_received`'s Admit arm) must reach the
    /// wire first — otherwise the peer receives frames out of counter
    /// order and rejects the earlier one as undecryptable.
    fn interpret_pairing_commands(&mut self, cmds: Vec<PairingCommand>) {
        let mut start_sync = false;
        for cmd in cmds {
            match cmd {
                PairingCommand::SendFrame { ciphertext } => {
                    let _ = self
                        .bg_tx
                        .send(BgEvent::DrawbridgeSendPairBinary { data: ciphertext });
                }
                PairingCommand::SeedKpPool { device_id, kps } => {
                    self.ring_driver.ingest_kp_batch(&device_id, kps);
                    let _ = self.keys.save_ring_state(&self.ring_driver);
                }
                PairingCommand::PublishRingCommit { tag, ciphertext } => {
                    let _ = self
                        .bg_tx
                        .send(BgEvent::PublishRingCommit { tag, ciphertext });
                }
                // Nothing to cache: `ui_state()`'s `AwaitingApproval`
                // already carries device_name/did. Approval is always an
                // explicit step (TUI tap or `POST /pair/approve`), and
                // `sync_pairing_focus` below opens the TUI screen.
                PairingCommand::SurfaceApprovalPrompt { .. } => {}
                PairingCommand::PersistRing { ring_id } => {
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    let ring_id_hex = hex::encode(&ring_id);
                    if let Err(e) = self.ring_driver.record_ring_membership(
                        &self.mls,
                        ring_id.clone(),
                        now_ms,
                    ) {
                        self.debug_log
                            .log(&format!("pairing: record_ring_membership failed: {e}"));
                    }
                    let _ = self.keys.save_ring_state(&self.ring_driver);
                    // Candidate tags + group metadata for the ring — see
                    // the matching note in `approve_pending_pairing`. The
                    // new device needs this too: if a *third* device later
                    // pairs into this same ring, this device becomes the
                    // bystander and must recognize that Add commit on its
                    // own next poll.
                    let my_did = self.client.as_ref().map(|c| c.did().to_string());
                    let _ = self.keys.store_group_metadata(
                        &ring_id_hex,
                        &GroupMetadata {
                            participant_dids: my_did.into_iter().collect(),
                            participant_handles: vec![],
                            kind: GroupKind::Ring,
                            pending_ex_members: Vec::new(),
                            member_device_ids: Default::default(),
                        },
                    );
                    self.register_group_tags(&ring_id_hex, &ring_id);
                    let _ = self.bg_tx.send(BgEvent::RingTickNow);
                }
                PairingCommand::RosterReceived { roster } => {
                    for s in roster {
                        if s.device_id == *self.mls.device_id() {
                            continue;
                        }
                        if let Some(existing) = self
                            .cached_sibling_stealth
                            .iter_mut()
                            .find(|c| c.device_id == s.device_id)
                        {
                            existing.scan_pubkey = s.stealth_pubkey;
                        } else {
                            self.cached_sibling_stealth.push(SiblingStealth {
                                scan_pubkey: s.stealth_pubkey,
                                device_id: s.device_id,
                            });
                        }
                    }
                }
                PairingCommand::StartSync => {
                    start_sync = true;
                }
            }
        }
        if start_sync {
            self.start_pairing_sync_session();
        }
        self.sync_pairing_focus();
    }

    /// Derive `Focus` from `ui_state()` instead of setting it imperatively
    /// per command. Only `AwaitingApproval` needs a transition — an
    /// incoming `Enroll` can arrive while the user is anywhere in the TUI;
    /// the other pairing screens already render and dismiss off
    /// `ui_state()` in their own draw/key handlers.
    fn sync_pairing_focus(&mut self) {
        if matches!(self.pairing_ui_state(), PairingUiState::AwaitingApproval { .. }) {
            self.focus = Focus::PairApprove;
        }
    }
}

#[cfg(test)]
mod tests {
    use moat_atproto::EventRecord;

    fn make_event(rkey: &str, tag: [u8; 16]) -> EventRecord {
        EventRecord {
            uri: String::new(),
            rkey: rkey.to_string(),
            author_did: "did:plc:test".to_string(),
            v: 1,
            tag,
            ciphertext: vec![],
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn watched_events_sorted_by_rkey_ascending() {
        // Simulate PDS returning events in descending rkey order (newest first),
        // which caused events to be processed before the Welcome.
        let welcome_tag = [0xc8, 0xff, 0xc6, 0xc1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let hint_tag = [0x11, 0x57, 0x50, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let msg_tag = [0xda, 0x5f, 0x62, 0x9c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let did = "did:plc:alice".to_string();

        // Events in descending rkey order (as returned by PDS)
        let mut watched_events: Vec<(String, EventRecord)> = vec![
            (did.clone(), make_event("3mfcetibqab2v", hint_tag)),  // highest rkey
            (did.clone(), make_event("3mfcetf53sx23", msg_tag)),
            (did.clone(), make_event("3mfcetex5yg2i", welcome_tag)), // lowest rkey
        ];

        // Apply the same sort used in process_poll_results
        watched_events.sort_by(|a, b| a.1.rkey.cmp(&b.1.rkey));

        // Welcome (lowest rkey) should now be first
        assert_eq!(watched_events[0].1.tag, welcome_tag);
        assert_eq!(watched_events[0].1.rkey, "3mfcetex5yg2i");

        assert_eq!(watched_events[1].1.tag, msg_tag);
        assert_eq!(watched_events[1].1.rkey, "3mfcetf53sx23");

        assert_eq!(watched_events[2].1.tag, hint_tag);
        assert_eq!(watched_events[2].1.rkey, "3mfcetibqab2v");
    }

    #[test]
    fn display_name_returns_explicit_name() {
        let conv = super::Conversation {
            id: "abc".to_string(),
            name: Some("Work Chat".to_string()),
            participant_dids: vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()],
            participant_handles: vec!["alice.bsky.social".to_string(), "bob.bsky.social".to_string()],
            current_epoch: 1,
            unread: 0,
            is_member: true,
        };
        assert_eq!(conv.display_name(), "Work Chat");
    }

    #[test]
    fn display_name_falls_back_to_handles() {
        let conv = super::Conversation {
            id: "abc".to_string(),
            name: None,
            participant_dids: vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()],
            participant_handles: vec!["alice.bsky.social".to_string(), "bob.bsky.social".to_string()],
            current_epoch: 1,
            unread: 0,
            is_member: true,
        };
        assert_eq!(conv.display_name(), "alice.bsky.social, bob.bsky.social");
    }

    #[test]
    fn display_name_falls_back_to_dids_when_no_handles() {
        let conv = super::Conversation {
            id: "abc".to_string(),
            name: None,
            participant_dids: vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()],
            participant_handles: vec![],
            current_epoch: 1,
            unread: 0,
            is_member: true,
        };
        assert_eq!(conv.display_name(), "did:plc:alice, did:plc:bob");
    }

    #[test]
    fn poll_devices_dedup_uses_device_id_not_name() {
        // Two credentials with the same device_name but different device_ids must
        // produce distinct dedup keys so both get added to the group.
        use moat_core::MoatCredential;
        use std::collections::HashSet;

        let id_a = [1u8; 16];
        let id_b = [2u8; 16];
        let cred_a = MoatCredential::new("did:plc:alice", "My Phone", id_a);
        let cred_b = MoatCredential::new("did:plc:alice", "My Phone", id_b);

        let existing: HashSet<(String, [u8; 16])> = vec![
            (cred_a.did().to_string(), *cred_a.device_id()),
        ]
        .into_iter()
        .collect();

        // cred_a is already present
        assert!(existing.contains(&(cred_a.did().to_string(), *cred_a.device_id())));
        // cred_b has the same name but different id — must not be considered present
        assert!(!existing.contains(&(cred_b.did().to_string(), *cred_b.device_id())));
    }

    #[test]
    fn display_name_single_participant() {
        let conv = super::Conversation {
            id: "abc".to_string(),
            name: None,
            participant_dids: vec!["did:plc:alice".to_string()],
            participant_handles: vec!["alice.bsky.social".to_string()],
            current_epoch: 1,
            unread: 0,
            is_member: true,
        };
        assert_eq!(conv.display_name(), "alice.bsky.social");
    }
}
