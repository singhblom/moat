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
use moat_atproto::MoatAtprotoClient;
use moat_core::{
    blob_decrypt, blob_encrypt, encrypt_for_stealth, generate_stealth_keypair,
    try_decrypt_stealth, ControlKind, Event, EventKind, ExternalBlob, LongTextMessage,
    MediaMessage, MessagePayload, MoatCredential, MoatSession, ModifierKind, ParsedMessagePayload,
    CIPHERSUITE,
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
/// If the data doesn't start with the magic, treats the entire blob as a raw
/// Welcome with no hints (backward compat).
fn decode_welcome_envelope(data: &[u8]) -> (Vec<u8>, Vec<HintBundleEntry>) {
    if data.len() >= 8 && data[..4] == WELCOME_ENVELOPE_MAGIC {
        let welcome_len =
            u32::from_be_bytes(data[4..8].try_into().unwrap_or_default()) as usize;
        if data.len() >= 8 + welcome_len {
            let welcome = data[8..8 + welcome_len].to_vec();
            let hints: Vec<HintBundleEntry> = if data.len() > 8 + welcome_len {
                serde_json::from_slice(&data[8 + welcome_len..]).unwrap_or_default()
            } else {
                vec![]
            };
            return (welcome, hints);
        }
    }
    // Legacy: raw Welcome bytes, no hints
    (data.to_vec(), vec![])
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
        Self {
            path: storage_dir.join("debug.log"),
        }
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
    pub name: String,
    pub participant_dids: Vec<String>,
    pub current_epoch: u64,
    pub unread: usize,
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
        did: String,
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
        cid: String,
        key: Vec<u8>,
        ciphertext_hash: Vec<u8>,
        ciphertext_size: u64,
        content_hash: Vec<u8>,
        /// Full original text (kept for future use, e.g. offline retransmit).
        #[allow(dead_code)]
        full_text: String,
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
        cid: String,
        key: Vec<u8>,
        ciphertext_hash: Vec<u8>,
        ciphertext_size: u64,
        content_hash: Vec<u8>,
        width: u32,
        height: u32,
        thumbhash: Vec<u8>,
        mime: String,
        pending_message_id: Vec<u8>,
        conv_id: String,
    },

    /// Image blob fetch succeeded — decode and display the full image.
    ImageBlobFetched {
        message_id: Vec<u8>,
        /// Decrypted image bytes (JPEG or PNG).
        bytes: Vec<u8>,
    },
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
            | BgEvent::DrawbridgeWatchTags { .. } => true,

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
            | BgEvent::ImageBlobFetched { .. } => false,
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

    // Tags published by this device — skip these during polling to avoid
    // self-decryption errors. Using tags rather than rkeys because we know
    // the tag before the network publish completes.
    own_published_tags: HashSet<[u8; 16]>,

    // Polling state
    last_poll: Option<Instant>,
    last_device_poll: Option<Instant>,

    // DIDs to watch for incoming invites
    watched_dids: std::collections::HashSet<String>,
    pub watch_handle_input: String,

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
            own_published_tags: HashSet::new(),
            last_poll: None,
            last_device_poll: None,
            watched_dids: std::collections::HashSet::new(),
            watch_handle_input: String::new(),
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
        let mut stealth_to_publish: Option<([u8; 32], String)> = None;

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
            stealth_to_publish = Some((stealth_pubkey, device_name));
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
                if let Some((stealth_pubkey, device_name)) = stealth_to_publish {
                    if let Err(e) = client
                        .publish_stealth_address(&stealth_pubkey, &device_name)
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
                let idx = self
                    .conversations
                    .iter()
                    .position(|c| c.id == id)
                    .ok_or_else(|| AppError::Other(format!("conversation not found: {id}")))?;
                self.active_conversation = Some(idx);
                self.load_messages()
            }
        }
    }

    /// HTTP: read messages for the active conversation via the same in-memory
    /// state the TUI renders from.  Callers must set the active conversation
    /// first (via `api_set_active_conversation`).
    pub fn api_get_messages(&self) -> &[DisplayMessage] {
        &self.messages
    }

    /// HTTP: send message to active conversation.
    pub fn api_send_message(&mut self, text: String) -> Result<()> {
        self.input_buffer = text;
        self.cursor_position = 0;
        self.send_message_nonblocking()
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
        self.own_published_tags.insert(encrypted.tag);
        self.save_mls_state()?;
        self.keys
            .store_group_state(&conv_id, &encrypted.new_group_state)?;

        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        client
            .publish_event(&encrypted.tag, &encrypted.ciphertext)
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
                match resume_result {
                    Ok(client) => {
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
                    Err(_) => {} // fall through
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
        if !self.conversations.is_empty() {
            let all_conv_indices: Vec<usize> = (0..self.conversations.len()).collect();
            dids_to_poll.entry(my_did).or_insert(all_conv_indices);
        }

        let watched: Vec<(String, Option<String>)> = self
            .watched_dids
            .iter()
            .filter(|did| !dids_to_poll.contains_key(*did))
            .map(|did| {
                let last_rkey = self.keys.get_last_rkey(did).ok().flatten();
                (did.clone(), last_rkey)
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
                match client
                    .fetch_events_from_did(participant_did, last_rkey.as_deref())
                    .await
                {
                    Ok(events) => {
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
                    Err(_) => {}
                }
            }

            let mut watched_events = Vec::new();
            for (did, last_rkey) in &watched {
                match client
                    .fetch_events_from_did(did, last_rkey.as_deref())
                    .await
                {
                    Ok(events) => {
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
                            new_rkeys.push((did.clone(), rkey));
                        }
                    }
                    Err(_) => {}
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

                let rkey = uri.split('/').last().unwrap_or("").to_string();

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

                // Notify Drawbridge about the published event with payload + relay URLs
                if self.drawbridge.has_own_connection() {
                    // Collect relay URLs for all partner DIDs in this conversation
                    let drawbridge_urls = self.drawbridge_urls_for_conversation(&conv_id);
                    let _ = self.bg_tx.send(BgEvent::DrawbridgeNotifyEventPosted {
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
            BgEvent::DrawbridgeNewEvent { tag, rkey, did, payload } => {
                self.debug_log.log(&format!(
                    "drawbridge: new_event tag={} rkey={} did={} payload={}",
                    hex::encode(&tag),
                    &rkey,
                    if did.is_empty() { "(relay)" } else { &did[..20.min(did.len())] },
                    if payload.is_some() { "yes" } else { "no" }
                ));

                // Try to decrypt inline payload first
                if let Some(ref ciphertext) = payload {
                    if let Some(conv_id) = self.tag_map.get(&tag).cloned() {
                        let group_id = hex::decode(&conv_id).unwrap_or_default();
                        if let Ok(decrypted) = self.mls.decrypt_event(&group_id, ciphertext) {
                            self.debug_log.log("drawbridge: inline payload decrypted successfully");
                            // Process the decrypted event inline — skip PDS fetch
                            self.process_inline_decrypted(&conv_id, &rkey, decrypted);
                            self.save_mls_state().ok();
                            return;
                        }
                    }
                }

                // Fallback: trigger PDS fetch
                if !did.is_empty() {
                    self.spawn_targeted_fetch(&did);
                }
                // If no DID (relay-to-relay), next regular poll will pick it up
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
                // Update conversation name and stored metadata
                if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == conv_id) {
                    conv.name = handle.clone();
                }
                let _ = self.keys.store_group_metadata(
                    &conv_id,
                    &GroupMetadata {
                        participant_dids: vec![did],
                        participant_handles: vec![handle],
                    },
                );
            }

            BgEvent::BlobUploaded {
                cid,
                key,
                ciphertext_hash,
                ciphertext_size,
                content_hash,
                full_text: _,
                preview_text,
                conv_id,
            } => {
                self.handle_blob_uploaded(
                    cid,
                    key,
                    ciphertext_hash,
                    ciphertext_size,
                    content_hash,
                    preview_text,
                    conv_id,
                );
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

            BgEvent::ImageUploaded {
                cid,
                key,
                ciphertext_hash,
                ciphertext_size,
                content_hash,
                width,
                height,
                thumbhash,
                mime,
                pending_message_id,
                conv_id,
            } => {
                self.handle_image_uploaded(
                    cid,
                    key,
                    ciphertext_hash,
                    ciphertext_size,
                    content_hash,
                    width,
                    height,
                    thumbhash,
                    mime,
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
        }
    }

    /// MLS-encrypt a long-text event after blob upload succeeded, then publish.
    fn handle_blob_uploaded(
        &mut self,
        cid: String,
        key: Vec<u8>,
        ciphertext_hash: Vec<u8>,
        ciphertext_size: u64,
        content_hash: Vec<u8>,
        preview_text: String,
        conv_id: String,
    ) {
        let Some(client) = self.client.as_ref() else {
            self.set_error("blob uploaded but client is gone".to_string());
            return;
        };

        let uri = format!("at://{}/{}", client.did(), cid);

        let key_arr: [u8; 32] = match key.try_into() {
            Ok(k) => k,
            Err(_) => {
                self.set_error("blob key has wrong length".to_string());
                return;
            }
        };

        let external = match ExternalBlob::new(uri, key_arr.to_vec(), ciphertext_hash, ciphertext_size, content_hash) {
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
        let event = Event::message(group_id.clone(), current_epoch, &payload);

        let encrypted = match self.mls.encrypt_event(&group_id, &key_bundle, &event) {
            Ok(e) => e,
            Err(e) => {
                self.set_error(format!("MLS encrypt failed for long text: {e}"));
                return;
            }
        };

        self.own_published_tags.insert(encrypted.tag);
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
            match client.publish_event(&tag, &ciphertext).await {
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
            BgEvent::DrawbridgeNotifyEventPosted { tag, rkey, payload, drawbridge_urls } => {
                if let Err(e) = self.drawbridge.notify_event_posted(&tag, &rkey, &payload, &drawbridge_urls).await {
                    self.debug_log
                        .log(&format!("drawbridge: event_posted failed: {}", e));
                }
            }
            BgEvent::DrawbridgeWatchTags { tags } => {
                if let Err(e) = self.drawbridge.watch_tags(&tags).await {
                    self.debug_log
                        .log(&format!("drawbridge: watch_tags failed: {}", e));
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
    fn send_image_nonblocking(&mut self, path: &str) -> Result<()> {
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
        };
        if let Err(e) = self.keys.append_message(&conv_id, stored_msg) {
            self.debug_log
                .log(&format!("send_image: failed to store locally: {e}"));
        }

        self.input_buffer.clear();
        self.cursor_position = 0;

        let client = self.client.as_ref().unwrap().clone();
        let tx = self.bg_tx.clone();
        let path = path.to_string();

        tokio::spawn(async move {
            // Image processing runs on the blocking thread pool.
            let result = tokio::task::spawn_blocking(move || {
                image_processing::process_image_for_send(&path)
            })
            .await;

            let (image_bytes, width, height, thumbhash, mime) = match result {
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

            // Encrypt blob (fast, CPU-only).
            let (blob_bytes, key, ciphertext_hash, content_hash) =
                match moat_core::blob_encrypt(&image_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ =
                            tx.send(BgEvent::SendFailed(format!("blob encrypt failed: {e}")));
                        return;
                    }
                };
            let ciphertext_size = blob_bytes.len() as u64;

            // Upload blob to PDS.
            let cid = match client.upload_blob(&blob_bytes).await {
                Ok(cid) => cid,
                Err(e) => {
                    let _ = tx.send(BgEvent::SendFailed(format!("blob upload failed: {e}")));
                    return;
                }
            };

            let _ = tx.send(BgEvent::ImageUploaded {
                cid,
                key: key.to_vec(),
                ciphertext_hash,
                ciphertext_size,
                content_hash,
                width,
                height,
                thumbhash,
                mime,
                pending_message_id,
                conv_id,
            });
        });

        Ok(())
    }

    /// MLS-encrypt an image event after blob upload succeeded, then publish.
    fn handle_image_uploaded(
        &mut self,
        cid: String,
        key: Vec<u8>,
        ciphertext_hash: Vec<u8>,
        ciphertext_size: u64,
        content_hash: Vec<u8>,
        width: u32,
        height: u32,
        thumbhash: Vec<u8>,
        mime: String,
        pending_message_id: Vec<u8>,
        conv_id: String,
    ) {
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
            ciphertext_hash,
            ciphertext_size,
            content_hash,
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
        let event = Event::message(group_id.clone(), current_epoch, &payload);

        let encrypted = match self.mls.encrypt_event(&group_id, &key_bundle, &event) {
            Ok(e) => e,
            Err(e) => {
                self.set_error(format!("MLS encrypt failed for image: {e}"));
                return;
            }
        };

        self.own_published_tags.insert(encrypted.tag);
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
            // Update the locally stored entry with the final display string.
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
                },
            );
            if let Some(thumb_img) = image_processing::decode_thumbhash(&thumbhash) {
                msg.image_proto = Some(ImageProto(self.picker.new_resize_protocol(thumb_img)));
            }
        }

        // Publish the MLS-encrypted event.
        let client = self.client.as_ref().unwrap().clone();
        let tag = encrypted.tag;
        let ciphertext = encrypted.ciphertext;
        let msg_id = encrypted.message_id.clone();
        let tx = self.bg_tx.clone();
        tokio::spawn(async move {
            match client.publish_event(&tag, &ciphertext).await {
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

    fn spawn_targeted_fetch(&mut self, did: &str) {
        let client = match self.client.as_ref() {
            Some(c) => c.clone(),
            None => return,
        };

        let did = did.to_string();
        let last_rkey = self.keys.get_last_rkey(&did).ok().flatten();

        // Find conversation indices for this DID
        let conv_indices: Vec<usize> = self
            .conversations
            .iter()
            .enumerate()
            .filter(|(_, c)| c.participant_dids.contains(&did))
            .map(|(i, _)| i)
            .collect();

        let tx = self.bg_tx.clone();

        tokio::spawn(async move {
            match client
                .fetch_events_from_did(&did, last_rkey.as_deref())
                .await
            {
                Ok(events) => {
                    let mut max_rkey = last_rkey.clone();
                    let mut participant_events = Vec::new();

                    for event in events {
                        if let Some(ref last) = last_rkey {
                            if event.rkey <= *last {
                                continue;
                            }
                        }
                        if max_rkey.as_ref().map_or(true, |m| event.rkey > *m) {
                            max_rkey = Some(event.rkey.clone());
                        }
                        participant_events.push((conv_indices.clone(), event, did.clone()));
                    }

                    let mut new_rkeys = Vec::new();
                    if let Some(rkey) = max_rkey {
                        new_rkeys.push((did, rkey));
                    }

                    let _ = tx.send(BgEvent::PollFetched {
                        participant_events,
                        watched_events: Vec::new(),
                        new_rkeys,
                    });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::PollError(format!(
                        "Targeted fetch for {} failed: {}",
                        did, e
                    )));
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
                    .map(|p| render_message_preview(p))
                    .unwrap_or_else(|| String::from_utf8_lossy(&decrypted.event.payload).to_string());
                let (sender_did, sender_device) = decrypted
                    .sender
                    .map(|s| (Some(s.did), Some(s.device_name)))
                    .unwrap_or((None, None));
                let is_own = sender_did.as_ref().map_or(false, |did| did == &my_did);
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
                    self.populate_candidate_tags(conv_id, &group_id);
                    self.conversations[idx].current_epoch += 1;
                    self.schedule_watch_tags_update();
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
            let (name, participant_dids) = match self.keys.load_group_metadata(&group_id) {
                Ok(meta) => (meta.participant_handles.join(", "), meta.participant_dids),
                Err(_) => {
                    let short_id = &group_id[..8.min(group_id.len())];
                    (format!("Conversation {}", short_id), Vec::new())
                }
            };

            let group_id_bytes = hex::decode(&group_id).unwrap_or_default();
            let current_epoch = if let Ok(Some(epoch)) = self.mls.get_group_epoch(&group_id_bytes) {
                epoch
            } else {
                1
            };

            self.populate_candidate_tags(&group_id, &group_id_bytes);

            self.conversations.push(Conversation {
                id: group_id,
                name,
                participant_dids,
                current_epoch,
                unread: 0,
            });
        }
    }

    /// Populate the tag_map with candidate tags for all members of a conversation.
    ///
    /// Generates tags for each member device using the GAP_LIMIT window.
    /// Tags map back to the hex-encoded group_id for routing.
    fn populate_candidate_tags(&mut self, conv_id: &str, group_id: &[u8]) {
        match self.mls.populate_candidate_tags(group_id) {
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

        if !participant_events.is_empty() {
            self.debug_log.log(&format!(
                "poll: processing {} participant events",
                participant_events.len(),
            ));
        }
        for (conv_indices, event_record, _did) in participant_events {
            // Skip events this device published — MLS cannot decrypt messages
            // from our own sender ratchet, and we already display them
            // optimistically on send. Events from other devices (same DID) are
            // fine to decrypt.
            if self.own_published_tags.contains(&event_record.tag) {
                continue;
            }
            let tag_hex: String = event_record.tag.iter().map(|b| format!("{b:02x}")).collect();
            if self.tag_map.contains_key(&event_record.tag) {
                self.debug_log.log(&format!(
                    "poll: tag matched: {} rkey={}", tag_hex, event_record.rkey
                ));
                if self.process_matched_event(&conv_indices, &event_record, &my_did) {
                    new_messages += 1;
                }
            } else {
                self.debug_log.log(&format!(
                    "poll: unknown tag {} rkey={} from {}, trying as welcome",
                    tag_hex, event_record.rkey, event_record.author_did
                ));
                // Unknown tag — try as welcome (sync crypto, only resolve_handle is async)
                self.try_process_welcome_sync(
                    &event_record.ciphertext,
                    &event_record.author_did,
                    event_record.tag,
                );
            }
        }

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
            if self.own_published_tags.contains(&event_record.tag) {
                continue;
            }
            if self.process_matched_event(&conv_indices, &event_record, &my_did) {
                new_messages += 1;
            }
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

        PollStats {
            new_messages,
            new_conversations: self.conversations.len().saturating_sub(conv_count_before),
        }
    }

    /// Decrypt and handle a single event whose tag matched the tag_map.
    /// Returns `true` if a new message was stored (for poll stats counting).
    fn process_matched_event(
        &mut self,
        conv_indices: &[usize],
        event_record: &moat_atproto::EventRecord,
        my_did: &str,
    ) -> bool {
        let conv_id = match self.tag_map.get(&event_record.tag).cloned() {
            Some(id) => id,
            None => return false,
        };
        self.mls.mark_tag_seen(&event_record.tag);
        let group_id = match hex::decode(&conv_id) {
            Ok(id) => id,
            Err(_) => return false,
        };

        let mut msg_stored = false;
        match self.mls.decrypt_event(&group_id, &event_record.ciphertext) {
            Ok(outcome) => {
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
                            .map(|p| render_message_preview(p))
                            .unwrap_or_else(|| "(invalid message payload)".to_string());
                        let (sender_did, sender_device) = decrypted
                            .sender
                            .map(|s| (Some(s.did), Some(s.device_name)))
                            .unwrap_or((None, None));

                        let is_own =
                            sender_did.as_ref().map_or(false, |did| did == my_did);

                        // Persist received message locally
                        let stored_msg = crate::keystore::StoredMessage {
                            rkey: event_record.rkey.clone(),
                            content: content.clone(),
                            timestamp: event_record.created_at,
                            is_own,
                            message_id: decrypted.event.message_id.clone(),
                            sender_did: sender_did.clone(),
                            sender_device: sender_device.clone(),
                        };
                        match self.keys.append_message(&conv_id, stored_msg) {
                            Err(e) => {
                                self.debug_log
                                    .log(&format!("poll: failed to store message: {}", e));
                            }
                            Ok(false) => {
                                // Duplicate rkey — already stored, skip in-memory insert.
                                return msg_stored;
                            }
                            Ok(true) => {
                                msg_stored = true;
                            }
                        }

                        if self.active_conversation == conv_idx {
                            let dm = DisplayMessage {
                                from: conv_idx
                                    .and_then(|idx| self.conversations.get(idx))
                                    .map(|c| c.name.clone())
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
                                if let Some(conv) =
                                    self.conversations.iter_mut().find(|c| c.id == conv_id)
                                {
                                    conv.participant_dids = member_dids.clone();
                                }
                                // Update stored metadata
                                let _ = self.keys.store_group_metadata(
                                    &conv_id,
                                    &GroupMetadata {
                                        participant_dids: member_dids.clone(),
                                        participant_handles: member_dids,
                                    },
                                );
                                // Fetch relay configs for any new members
                                self.fetch_partner_drawbridge_configs(&conv_id);
                            }
                        }

                        // Regenerate candidate tags for the new epoch
                        self.populate_candidate_tags(&conv_id, &group_id);

                        // Update watched tags on own Drawbridge for the new epoch
                        self.schedule_watch_tags_update();
                    }
                    EventKind::Modifier(ModifierKind::Reaction) => {
                        if let Some(rp) = decrypted.event.reaction_payload() {
                            let sender_did =
                                decrypted.sender.map(|s| s.did).unwrap_or_default();
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
                    _ => {}
                }
            }
            Err(e) => {
                self.debug_log
                    .log(&format!("poll: decryption failed: {}", e));
            }
        }
        msg_stored
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
        let (welcome_bytes, _hint_bundle) = decode_welcome_envelope(&plaintext);

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

        // Use DIDs as placeholder names; will be resolved in background
        let participant_handles: Vec<String> = participant_dids.clone();
        let name = participant_handles.join(", ");

        let _ = self.keys.store_group_metadata(
            &conv_id,
            &GroupMetadata {
                participant_dids: participant_dids.clone(),
                participant_handles: participant_handles.clone(),
            },
        );

        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name,
            participant_dids,
            current_epoch: 1,
            unread: 1,
        });

        self.populate_candidate_tags(&conv_id, &group_id);

        // Resolve DID → handle in background for each participant
        if let Some(conv) = self.conversations.last() {
            self.resolve_conversation_handle(conv);
        }

        // Fetch relay configs for the new conversation's partners
        self.fetch_partner_drawbridge_configs(&conv_id);
        // Register new conversation tags on own Drawbridge relay
        self.schedule_watch_tags_update();

        self.debug_log
            .log("process_welcome: successfully joined group");
        true
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

            // Publish public key to PDS with device name
            self.set_status("Publishing stealth address...".to_string());
            let device_name = self.keys.get_or_create_device_name()?;
            client
                .publish_stealth_address(&stealth_pubkey, &device_name)
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

        // Connect to own Drawbridge if configured
        if let Some(ref url) = self.drawbridge_url.clone() {
            if let Ok(sig_key) = self.keys.load_identity_key() {
                let _ = self.bg_tx.send(BgEvent::DrawbridgeConnectOwn {
                    url: url.clone(),
                    did: did.clone(),
                    signature_key: sig_key,
                });
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
        let stealth_ciphertext =
            encrypt_for_stealth(&recipient_stealth_pubkeys, &welcome_result.welcome)?;

        // 8. Publish with random tag (not group-derived, since recipient doesn't know group yet)
        let random_tag: [u8; 16] = rand::random();
        self.client
            .as_ref()
            .unwrap()
            .publish_event(&random_tag, &stealth_ciphertext)
            .await?;

        // 9. Store conversation metadata
        let conv_id = hex::encode(&group_id);
        self.keys.store_group_metadata(
            &conv_id,
            &GroupMetadata {
                participant_dids: vec![recipient_did.clone()],
                participant_handles: vec![recipient_handle.to_string()],
            },
        )?;

        // 10. Update UI - add conversation to list
        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name: recipient_handle.to_string(),
            participant_dids: vec![recipient_did],
            current_epoch: 1, // Post-add epoch
            unread: 0,
        });

        // 11. Register candidate tags for this conversation
        self.populate_candidate_tags(&conv_id, &group_id);
        self.debug_log.log(&format!(
            "start_conv: registered candidate tags for conv {}",
            &conv_id[..16]
        ));

        // 12. Fetch partner relay configs and update watched tags
        self.fetch_partner_drawbridge_configs(&conv_id);
        self.schedule_watch_tags_update();

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

        // 4. Fetch key package for new member
        let key_packages = client.fetch_key_packages(&new_did).await?;
        let kp_bytes = key_packages
            .first()
            .ok_or_else(|| AppError::Other(format!("No key package found for {handle}")))?
            .key_package
            .clone();

        // 5. Load our key bundle
        let key_bundle = self.keys.load_identity_key()?;

        // 6. Derive commit tag BEFORE add_member (pre-epoch-advance)
        let commit_tag = self.mls.derive_next_tag(&group_id, &key_bundle)?;

        // 7. Add member to MLS group
        let welcome_result = self.mls.add_member(&group_id, &key_bundle, &kp_bytes)?;
        self.save_mls_state()?;

        // 8. Encrypt Welcome envelope for new member's stealth keys, publish with random tag
        let envelope = encode_welcome_envelope(&welcome_result.welcome, &[]);
        let stealth_ciphertext =
            moat_core::encrypt_for_stealth(&stealth_pubkeys, &envelope)?;
        let random_tag: [u8; 16] = rand::random();
        client
            .publish_event(&random_tag, &stealth_ciphertext)
            .await?;

        // 10. Publish the Commit with pre-epoch tag for existing members
        client
            .publish_event(&commit_tag, &welcome_result.commit)
            .await?;

        // 11. Update GroupMetadata — add new DID/handle
        if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == group_id_hex) {
            if !conv.participant_dids.contains(&new_did) {
                conv.participant_dids.push(new_did.clone());
            }
            conv.name = {
                // Rebuild name from all participant handles
                let mut handles: Vec<String> = conv.participant_dids.iter().filter_map(|did| {
                    // For the new member, use the handle we just resolved
                    if did == &new_did {
                        Some(handle.to_string())
                    } else {
                        None
                    }
                }).collect();
                // Keep existing name parts and append new handle
                if !conv.name.is_empty() {
                    handles.insert(0, conv.name.clone());
                }
                handles.join(", ")
            };

            let _ = self.keys.store_group_metadata(
                group_id_hex,
                &GroupMetadata {
                    participant_dids: conv.participant_dids.clone(),
                    participant_handles: conv.name.split(", ").map(|s| s.to_string()).collect(),
                },
            );
        }

        // 12. Re-populate candidate tags for the new epoch
        self.populate_candidate_tags(group_id_hex, &group_id);

        // 13. Update watched tags and fetch new member's relay config
        self.schedule_watch_tags_update();
        self.fetch_partner_drawbridge_configs(group_id_hex);

        self.debug_log.log(&format!(
            "add_member: added {handle} to group {}",
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
        let conv_name = self.conversations[idx].name.clone();

        let local_messages = self.keys.load_messages(&conv_id).unwrap_or_default();
        for stored in &local_messages.messages {
            let from = if stored.is_own {
                "You".to_string()
            } else {
                conv_name.clone()
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
            let (blob_bytes, key, ciphertext_hash, content_hash) = blob_encrypt(full_text.as_bytes())
                .map_err(|e| AppError::Other(format!("blob encrypt failed: {e}")))?;
            let ciphertext_size = blob_bytes.len() as u64;

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
                match client.upload_blob(&blob_bytes).await {
                    Ok(cid) => {
                        let _ = tx.send(BgEvent::BlobUploaded {
                            cid,
                            key: key.to_vec(),
                            ciphertext_hash,
                            ciphertext_size,
                            content_hash,
                            full_text,
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
        self.own_published_tags.insert(encrypted.tag);
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
            match client.publish_event(&tag, &ciphertext).await {
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
        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        let my_did = client.did().to_string();

        // Fetch key packages for our own DID
        let key_packages = match client.fetch_key_packages(&my_did).await {
            Ok(kps) => kps,
            Err(e) => {
                self.debug_log.log(&format!(
                    "poll_devices: failed to fetch own key packages: {}",
                    e
                ));
                return Ok(());
            }
        };

        if key_packages.is_empty() {
            return Ok(());
        }

        // Load key bundle for MLS operations
        let key_bundle = match self.keys.load_identity_key() {
            Ok(kb) => kb,
            Err(e) => {
                self.debug_log
                    .log(&format!("poll_devices: failed to load key bundle: {}", e));
                return Ok(());
            }
        };

        // Collect group info for all conversations
        let mut groups_to_check: Vec<(Vec<u8>, String)> = Vec::new();
        for conv in &self.conversations {
            if let Ok(group_id) = hex::decode(&conv.id) {
                groups_to_check.push((group_id, conv.id.clone()));
            }
        }

        // For each conversation, check if any of our key packages represent new devices
        for (group_id, conv_id) in groups_to_check {
            // Get current members with their device names
            let current_members = match self.mls.get_group_members(&group_id) {
                Ok(m) => m,
                Err(e) => {
                    self.debug_log.log(&format!(
                        "poll_devices: failed to get members for group {}: {}",
                        &conv_id[..16.min(conv_id.len())],
                        e
                    ));
                    continue;
                }
            };

            // Build a set of (DID, device_name) pairs for existing members
            let existing_devices: std::collections::HashSet<(String, String)> = current_members
                .iter()
                .filter_map(|(_, cred)| {
                    cred.as_ref()
                        .map(|c| (c.did().to_string(), c.device_name().to_string()))
                })
                .collect();

            self.debug_log.log(&format!(
                "poll_devices: group {} has {} devices",
                &conv_id[..16.min(conv_id.len())],
                existing_devices.len()
            ));

            // Check each of our key packages to see if it's a new device
            for kp_record in &key_packages {
                let credential = match self
                    .mls
                    .extract_credential_from_key_package(&kp_record.key_package)
                {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        self.debug_log
                            .log("poll_devices: key package has no credential");
                        continue;
                    }
                    Err(e) => {
                        self.debug_log.log(&format!(
                            "poll_devices: failed to extract credential: {}",
                            e
                        ));
                        continue;
                    }
                };

                let device_key = (
                    credential.did().to_string(),
                    credential.device_name().to_string(),
                );

                self.debug_log.log(&format!(
                    "poll_devices: key package device_name='{}' for did={}",
                    credential.device_name(),
                    &credential.did()[..20.min(credential.did().len())]
                ));

                // Skip if this device is already in the group
                if existing_devices.contains(&device_key) {
                    self.debug_log.log(&format!(
                        "poll_devices: device '{}' already in group, skipping",
                        credential.device_name()
                    ));
                    continue;
                }

                self.debug_log.log(&format!(
                    "poll_devices: found new device '{}' for our DID",
                    credential.device_name()
                ));

                // Derive tag for the commit using pre-advance counter
                let commit_tag = match self.mls.derive_next_tag(&group_id, &key_bundle) {
                    Ok(t) => t,
                    Err(e) => {
                        self.debug_log.log(&format!(
                            "poll_devices: failed to derive pre-add tag: {}",
                            e
                        ));
                        continue;
                    }
                };

                // Add the new device
                match self
                    .mls
                    .add_device(&group_id, &key_bundle, &kp_record.key_package)
                {
                    Ok(welcome_result) => {
                        self.debug_log.log(&format!(
                            "poll_devices: successfully added device '{}' to group",
                            credential.device_name()
                        ));

                        // Save MLS state
                        if let Err(e) = self.save_mls_state() {
                            self.debug_log
                                .log(&format!("poll_devices: failed to save MLS state: {}", e));
                        }

                        // Repopulate candidate tags for the new epoch
                        if let Ok(tags) = self.mls.populate_candidate_tags(&group_id) {
                            for t in tags {
                                self.tag_map.insert(t, conv_id.clone());
                            }
                        }

                        // Publish the commit with PRE-advance epoch tag so others can see it
                        if let Err(e) = client
                            .publish_event(&commit_tag, &welcome_result.commit)
                            .await
                        {
                            self.debug_log
                                .log(&format!("poll_devices: failed to publish commit: {}", e));
                        } else {
                            self.debug_log.log("poll_devices: published commit");
                        }

                        // Encrypt and publish welcome for the new device using our stealth addresses
                        match client.fetch_stealth_addresses(&my_did).await {
                            Ok(stealth_records) if !stealth_records.is_empty() => {
                                let stealth_pubkeys: Vec<[u8; 32]> =
                                    stealth_records.iter().map(|r| r.scan_pubkey).collect();
                                match moat_core::encrypt_for_stealth(
                                    &stealth_pubkeys,
                                    &welcome_result.welcome,
                                ) {
                                    Ok(stealth_ciphertext) => {
                                        let random_tag: [u8; 16] = rand::random();
                                        if let Err(e) = client
                                            .publish_event(&random_tag, &stealth_ciphertext)
                                            .await
                                        {
                                            self.debug_log.log(&format!(
                                                "poll_devices: failed to publish welcome: {}",
                                                e
                                            ));
                                        } else {
                                            self.debug_log.log(&format!(
                                                "poll_devices: published welcome for device '{}' (encrypted for {} stealth keys)",
                                                credential.device_name(),
                                                stealth_pubkeys.len()
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        self.debug_log.log(&format!(
                                            "poll_devices: failed to encrypt welcome: {}",
                                            e
                                        ));
                                    }
                                }
                            }
                            Ok(_) => {
                                self.debug_log.log("poll_devices: no stealth addresses for own DID, cannot send welcome");
                            }
                            Err(e) => {
                                self.debug_log.log(&format!(
                                    "poll_devices: failed to fetch stealth addresses: {}",
                                    e
                                ));
                            }
                        }

                        // Update conversation epoch in UI and add device alert
                        let conv_name = self
                            .conversations
                            .iter()
                            .find(|c| c.id == conv_id)
                            .map(|c| c.name.clone())
                            .unwrap_or_else(|| "Unknown".to_string());

                        if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == conv_id)
                        {
                            if let Ok(Some(new_epoch)) = self.mls.get_group_epoch(&group_id) {
                                conv.current_epoch = new_epoch;
                            }
                        }

                        // Add device alert for UI notification
                        self.device_alerts.push(DeviceAlert {
                            conversation_name: conv_name,
                            user_name: my_did.clone(),
                            device_name: credential.device_name().to_string(),
                            timestamp: chrono::Utc::now(),
                        });
                    }
                    Err(e) => {
                        self.debug_log.log(&format!(
                            "poll_devices: failed to add device '{}': {}",
                            credential.device_name(),
                            e
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Dismiss the oldest device alert
    pub fn dismiss_device_alert(&mut self) {
        if !self.device_alerts.is_empty() {
            self.device_alerts.remove(0);
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
}
