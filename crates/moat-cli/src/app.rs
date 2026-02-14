//! Application state and logic

use crate::{
    keystore::{hex, GroupMetadata, KeyStore, StoredSession},
    message_helpers::{build_text_payload, render_message_preview},
};
use crossterm::event::{KeyCode, KeyEvent};
use moat_atproto::MoatAtprotoClient;
use moat_core::{
    encrypt_for_stealth, generate_stealth_keypair, try_decrypt_stealth, ControlKind, Event,
    EventKind, MoatCredential, MoatSession, ModifierKind, ParsedMessagePayload, CIPHERSUITE,
};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::mpsc;

/// Quick-reaction emojis (same as Flutter app)
pub const QUICK_EMOJIS: &[&str] = &["👍", "❤️", "😂", "😮", "😢", "🙏"];

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

/// A conversation with another user
#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: String,
    pub name: String,
    pub participant_did: String,
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
#[derive(Debug, Clone)]
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
    },
    /// Network publish for send_message failed.
    SendFailed(String),
    /// Network fetch for load_messages completed.
    MessagesFetched {
        conv_idx: usize,
        their_events: Vec<moat_atproto::EventRecord>,
        my_did: String,
    },
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
}

/// Main application state
pub struct App {
    pub keys: KeyStore,
    pub client: Option<MoatAtprotoClient>,
    pub mls: MoatSession,
    mls_path: std::path::PathBuf,
    debug_log: DebugLog,

    // UI state
    pub focus: Focus,
    pub login_form: LoginForm,
    pub error_message: Option<String>,
    pub status_message: Option<String>,

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
    poll_in_flight: bool,
}

impl App {
    /// Create a new App instance
    ///
    /// If `storage_dir` is `None`, uses the default `~/.moat` directory.
    pub fn new(storage_dir: Option<std::path::PathBuf>) -> Result<Self> {
        // Determine the base storage directory
        let base_dir = match storage_dir {
            Some(dir) => dir,
            None => dirs::home_dir()
                .ok_or_else(|| AppError::Other("home directory not found".to_string()))?
                .join(".moat"),
        };

        let keys = KeyStore::with_path(base_dir.join("keys"))?;

        // Initialize MoatSession - load from file if it exists, otherwise start fresh
        let mls_path = base_dir.join("mls.bin");

        // Ensure parent directory exists
        if let Some(parent) = mls_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::Other(format!("Failed to create .moat directory: {e}")))?;
        }

        let mls = if mls_path.exists() {
            let bytes = std::fs::read(&mls_path)
                .map_err(|e| AppError::Other(format!("Failed to read MLS state: {e}")))?;
            MoatSession::from_state(&bytes)?
        } else {
            MoatSession::new()
        };

        let debug_log = DebugLog::new(&base_dir);

        let focus = if keys.has_credentials() {
            Focus::Conversations
        } else {
            Focus::Login
        };

        let (bg_tx, bg_rx) = mpsc::unbounded_channel();

        Ok(Self {
            keys,
            client: None,
            mls,
            mls_path,
            debug_log,
            focus,
            login_form: LoginForm::default(),
            error_message: None,
            status_message: None,
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
            last_poll: None,
            last_device_poll: None,
            watched_dids: std::collections::HashSet::new(),
            watch_handle_input: String::new(),
            bg_tx,
            bg_rx,
            poll_in_flight: false,
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

        // Spawn background poll for new messages (every 5 seconds)
        if self.client.is_some() && !self.poll_in_flight {
            let should_poll = self
                .last_poll
                .map(|t| t.elapsed().as_secs() >= 5)
                .unwrap_or(true);

            if should_poll {
                self.last_poll = Some(Instant::now());
                self.spawn_poll_messages();
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

        tokio::spawn(async move {
            // Try session resume first
            if let Some(session) = stored_session {
                match MoatAtprotoClient::resume_session(
                    &session.did,
                    &session.access_jwt,
                    &session.refresh_jwt,
                )
                .await
                {
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
                match MoatAtprotoClient::login(&handle, &password).await {
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
    fn spawn_poll_messages(&mut self) {
        let client = match self.client.as_ref() {
            Some(c) => c.clone(),
            None => return,
        };
        self.poll_in_flight = true;
        let my_did = client.did().to_string();

        // Collect DIDs and their last rkeys
        let mut dids_to_poll: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, conv) in self.conversations.iter().enumerate() {
            dids_to_poll
                .entry(conv.participant_did.clone())
                .or_default()
                .push(idx);
        }
        if !self.conversations.is_empty() {
            let all_conv_indices: Vec<usize> = (0..self.conversations.len()).collect();
            dids_to_poll.entry(my_did).or_insert(all_conv_indices);
        }

        let dids_with_rkeys: Vec<(String, Vec<usize>, Option<String>)> = dids_to_poll
            .into_iter()
            .map(|(did, indices)| {
                let last_rkey = self.keys.get_last_rkey(&did).ok().flatten();
                (did, indices, last_rkey)
            })
            .collect();

        let watched: Vec<(String, Option<String>)> = self
            .watched_dids
            .iter()
            .map(|did| {
                let last_rkey = self.keys.get_last_rkey(did).ok().flatten();
                (did.clone(), last_rkey)
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
                    did,
                    access_jwt,
                    refresh_jwt,
                });
                self.client = Some(client);
                self.status_message = None;
                self.load_conversations_sync();
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
                self.process_poll_results(participant_events, watched_events, new_rkeys);
            }
            BgEvent::PollError(e) => {
                self.poll_in_flight = false;
                self.set_error(format!("Poll error: {e}"));
            }
            BgEvent::SendPublished { uri, conv_id, tag } => {
                self.debug_log
                    .log(&format!("send_message: published to PDS, uri={}", uri));
                self.tag_map.insert(tag, conv_id);
            }
            BgEvent::SendFailed(e) => {
                self.set_error(format!("Send error: {e}"));
            }
            BgEvent::MessagesFetched {
                conv_idx,
                their_events,
                my_did,
            } => {
                self.finish_load_messages(conv_idx, their_events, &my_did);
            }
        }
    }

    /// Synchronous version of load_conversations (no network calls).
    fn load_conversations_sync(&mut self) {
        let group_ids = match self.keys.list_groups() {
            Ok(ids) => ids,
            Err(e) => {
                self.set_error(format!("Failed to load conversations: {e}"));
                return;
            }
        };

        self.conversations.clear();
        for group_id in group_ids {
            let (name, participant_did) = match self.keys.load_group_metadata(&group_id) {
                Ok(meta) => (meta.participant_handle, meta.participant_did),
                Err(_) => {
                    let short_id = &group_id[..8.min(group_id.len())];
                    (format!("Conversation {}", short_id), String::new())
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
                participant_did,
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
        watched_events: Vec<(String, moat_atproto::EventRecord)>,
        new_rkeys: Vec<(String, String)>,
    ) {
        let my_did = self
            .client
            .as_ref()
            .map(|c| c.did().to_string())
            .unwrap_or_default();

        for (conv_indices, event_record, _did) in participant_events {
            if let Some(conv_id) = self.tag_map.get(&event_record.tag).cloned() {
                self.mls.mark_tag_seen(&event_record.tag);
                let group_id = match hex::decode(&conv_id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };

                match self.mls.decrypt_event(&group_id, &event_record.ciphertext) {
                    Ok(outcome) => {
                        // Log any transcript integrity warnings
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
                                let content = decrypted
                                    .event
                                    .parse_message_payload()
                                    .map(|parsed| render_message_preview(&parsed))
                                    .unwrap_or_else(|| "(invalid message payload)".to_string());
                                let from = conv_idx
                                    .and_then(|idx| self.conversations.get(idx))
                                    .map(|c| c.name.clone())
                                    .unwrap_or_else(|| "Unknown".to_string());

                                let (sender_did, sender_device) = decrypted
                                    .sender
                                    .map(|s| (Some(s.did), Some(s.device_name)))
                                    .unwrap_or((None, None));

                                let is_own =
                                    sender_did.as_ref().map_or(false, |did| did == &my_did);

                                if self.active_conversation == conv_idx {
                                    self.messages.push(DisplayMessage {
                                        from,
                                        content,
                                        timestamp: event_record.created_at,
                                        is_own,
                                        sender_did,
                                        sender_device,
                                        message_id: decrypted.event.message_id,
                                        reactions: vec![],
                                    });
                                } else if let Some(idx) = conv_idx {
                                    if let Some(conv) = self.conversations.get_mut(idx) {
                                        conv.unread += 1;
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
                                // Regenerate candidate tags for the new epoch
                                self.populate_candidate_tags(&conv_id, &group_id);
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
            } else {
                // Unknown tag — try as welcome (sync crypto, only resolve_handle is async)
                self.try_process_welcome_sync(
                    &event_record.ciphertext,
                    &event_record.author_did,
                    event_record.tag,
                );
            }
        }

        // Process watched DID events
        for (did, event_record) in watched_events {
            if self.tag_map.contains_key(&event_record.tag) {
                continue;
            }
            if self.try_process_welcome_sync(
                &event_record.ciphertext,
                &event_record.author_did,
                event_record.tag,
            ) {
                self.watched_dids.remove(&did);
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
    }

    /// Synchronous welcome processing (no handle resolution — uses DID as name).
    fn try_process_welcome_sync(
        &mut self,
        ciphertext: &[u8],
        author_did: &str,
        _tag: [u8; 16],
    ) -> bool {
        let stealth_privkey = match self.keys.load_stealth_key() {
            Ok(key) => key,
            Err(_) => return false,
        };

        let welcome_bytes = match try_decrypt_stealth(&stealth_privkey, ciphertext) {
            Some(bytes) => bytes,
            None => return false,
        };

        let group_id = match self.mls.process_welcome(&welcome_bytes) {
            Ok(id) => id,
            Err(_) => return false,
        };

        let conv_id = hex::encode(&group_id);

        // Use DID as name initially; will be resolved later
        let participant_handle = author_did.to_string();

        let _ = self.keys.store_group_metadata(
            &conv_id,
            &GroupMetadata {
                participant_did: author_did.to_string(),
                participant_handle: participant_handle.clone(),
            },
        );

        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name: participant_handle,
            participant_did: author_did.to_string(),
            current_epoch: 1,
            unread: 1,
        });

        self.populate_candidate_tags(&conv_id, &group_id);

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

        let client = MoatAtprotoClient::login(&handle, &password).await?;

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

        self.client = Some(client);
        self.status_message = None;
        self.focus = Focus::Conversations;

        self.load_conversations_sync();

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
                if self.active_conversation.is_some() {
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

        // Add to watched DIDs
        self.watched_dids.insert(did);

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
            .position(|c| c.participant_did == recipient_did)
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
                participant_did: recipient_did.clone(),
                participant_handle: recipient_handle.to_string(),
            },
        )?;

        // 10. Update UI - add conversation to list
        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name: recipient_handle.to_string(),
            participant_did: recipient_did,
            current_epoch: 1, // Post-add epoch
            unread: 0,
        });

        // 11. Register candidate tags for this conversation
        self.populate_candidate_tags(&conv_id, &group_id);
        self.debug_log.log(&format!(
            "start_conv: registered candidate tags for conv {}",
            &conv_id[..16]
        ));

        // 12. Select the new conversation and switch to input mode
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
        });

        Ok(())
    }

    /// Load messages: show local messages immediately, spawn network fetch.
    fn load_messages(&mut self) -> Result<()> {
        self.messages.clear();

        let Some(idx) = self.active_conversation else {
            return Ok(());
        };

        let conv_id = self.conversations[idx].id.clone();
        let participant_did = self.conversations[idx].participant_did.clone();
        let my_did = self
            .client
            .as_ref()
            .map(|c| c.did().to_string())
            .unwrap_or_default();

        // Show locally stored messages immediately (no network wait)
        let local_messages = self.keys.load_messages(&conv_id).unwrap_or_default();
        for stored in &local_messages.messages {
            self.messages.push(DisplayMessage {
                from: "You".to_string(),
                content: stored.content.clone(),
                timestamp: stored.timestamp,
                is_own: true,
                sender_did: Some(my_did.clone()),
                sender_device: self.keys.get_or_create_device_name().ok(),
                message_id: stored.message_id.clone(),
                reactions: vec![],
            });
        }

        // Clear unread count
        if let Some(conv) = self.conversations.get_mut(idx) {
            conv.unread = 0;
        }

        // Spawn network fetch in background
        let client = match self.client.as_ref() {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        let tx = self.bg_tx.clone();

        tokio::spawn(async move {
            match client.fetch_events_from_did(&participant_did, None).await {
                Ok(events) => {
                    let _ = tx.send(BgEvent::MessagesFetched {
                        conv_idx: idx,
                        their_events: events,
                        my_did,
                    });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::PollError(format!("Failed to fetch messages: {e}")));
                }
            }
        });

        Ok(())
    }

    /// Process fetched messages (decrypt and merge with local).
    fn finish_load_messages(
        &mut self,
        conv_idx: usize,
        their_events: Vec<moat_atproto::EventRecord>,
        _my_did: &str,
    ) {
        // Only process if this conversation is still active
        if self.active_conversation != Some(conv_idx) {
            return;
        }

        let conv = match self.conversations.get(conv_idx) {
            Some(c) => c,
            None => return,
        };
        let conv_id = conv.id.clone();
        let participant_did = conv.participant_did.clone();
        let participant_name = conv.name.clone();
        let group_id = match hex::decode(&conv_id) {
            Ok(id) => id,
            Err(_) => return,
        };

        // Collect valid tags from the tag_map (already populated by populate_candidate_tags)
        let valid_tags: std::collections::HashSet<[u8; 16]> = self
            .tag_map
            .iter()
            .filter(|(_, cid)| *cid == &conv_id)
            .map(|(tag, _)| *tag)
            .collect();

        // Get local rkeys to avoid duplicates
        let local_messages = self.keys.load_messages(&conv_id).unwrap_or_default();
        let local_rkeys: std::collections::HashSet<String> = local_messages
            .messages
            .iter()
            .map(|m| m.rkey.clone())
            .collect();

        // Start with existing local messages already in display
        let mut all_messages: Vec<(String, DisplayMessage)> = self
            .messages
            .drain(..)
            .enumerate()
            .map(|(i, msg)| (format!("local_{:06}", i), msg))
            .collect();

        let mut pending_reactions: Vec<(Vec<u8>, String, String)> = Vec::new();
        let mut max_rkey: Option<String> = None;

        // Filter and decrypt
        let their_events: Vec<_> = their_events
            .into_iter()
            .filter(|e| {
                if max_rkey.as_ref().map_or(true, |m| e.rkey > *m) {
                    max_rkey = Some(e.rkey.clone());
                }
                valid_tags.contains(&e.tag)
            })
            .collect();

        for event_record in their_events {
            if local_rkeys.contains(&event_record.rkey) {
                continue;
            }

            match self.mls.decrypt_event(&group_id, &event_record.ciphertext) {
                Ok(outcome) => {
                    for w in outcome.warnings() {
                        self.debug_log
                            .log(&format!("load_messages: transcript warning: {}", w));
                    }
                    let decrypted = outcome.into_result();
                    match decrypted.event.kind {
                        EventKind::Message(_) => {
                            let content = decrypted
                                .event
                                .parse_message_payload()
                                .map(|parsed| render_message_preview(&parsed))
                                .unwrap_or_else(|| "(invalid message payload)".to_string());
                            let (sender_did, sender_device) = decrypted
                                .sender
                                .map(|s| (Some(s.did), Some(s.device_name)))
                                .unwrap_or((Some(participant_did.clone()), None));

                            all_messages.push((
                                event_record.rkey.clone(),
                                DisplayMessage {
                                    from: participant_name.clone(),
                                    content,
                                    timestamp: event_record.created_at,
                                    is_own: false,
                                    sender_did,
                                    sender_device,
                                    message_id: decrypted.event.message_id,
                                    reactions: vec![],
                                },
                            ));
                        }
                        EventKind::Modifier(ModifierKind::Reaction) => {
                            if let Some(rp) = decrypted.event.reaction_payload() {
                                let sender_did = decrypted
                                    .sender
                                    .map(|s| s.did)
                                    .unwrap_or_else(|| participant_did.clone());
                                pending_reactions.push((
                                    rp.target_message_id,
                                    rp.emoji,
                                    sender_did,
                                ));
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    self.debug_log.log(&format!(
                        "load_messages: failed to decrypt event {}: {}",
                        &event_record.rkey, e
                    ));
                }
            }
        }

        if self.mls.has_pending_changes() {
            let _ = self.save_mls_state();
        }

        all_messages.sort_by(|a, b| a.0.cmp(&b.0));

        for (target_id, emoji, sender_did) in pending_reactions {
            if let Some((_, msg)) = all_messages
                .iter_mut()
                .find(|(_, m)| m.message_id.as_ref() == Some(&target_id))
            {
                if let Some(pos) = msg
                    .reactions
                    .iter()
                    .position(|r| r.emoji == emoji && r.sender_did == sender_did)
                {
                    msg.reactions.remove(pos);
                } else {
                    msg.reactions.push(DisplayReaction { emoji, sender_did });
                }
            }
        }

        self.messages = all_messages.into_iter().map(|(_, msg)| msg).collect();

        if let Some(rkey) = max_rkey {
            let _ = self.keys.set_last_rkey(&participant_did, &rkey);
        }
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
                if !self.input_buffer.is_empty() {
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
            sender_did: Some(my_did),
            sender_device: self.keys.get_or_create_device_name().ok(),
            message_id: event.message_id.clone(),
            reactions: vec![],
        });

        // Store locally with placeholder rkey (will be real once publish completes)
        let stored_msg = crate::keystore::StoredMessage {
            rkey: "pending".to_string(),
            content: preview,
            timestamp,
            is_own: true,
            message_id: encrypted.message_id.clone(),
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
        let conv_id_clone = conv_id;
        let tx = self.bg_tx.clone();

        tokio::spawn(async move {
            match client.publish_event(&tag, &ciphertext).await {
                Ok(uri) => {
                    let _ = tx.send(BgEvent::SendPublished {
                        uri,
                        conv_id: conv_id_clone,
                        tag,
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
        if self.client.is_none() {
            return Err(AppError::NotLoggedIn);
        }
        let conv_idx = self.active_conversation.ok_or(AppError::NoConversation)?;
        let conv_id = self.conversations[conv_idx].id.clone();

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

        self.debug_log.log(&format!(
            "send_reaction: emoji={}, target_id={:02x?}",
            emoji,
            &target_message_id[..4.min(target_message_id.len())]
        ));

        let key_bundle = self.keys.load_identity_key()?;
        let group_id = hex::decode(&conv_id)
            .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

        let current_epoch = self.mls.get_group_epoch(&group_id)?.unwrap_or(1);
        let event = Event::reaction(group_id.clone(), current_epoch, &target_message_id, emoji);

        let encrypted = self.mls.encrypt_event(&group_id, &key_bundle, &event)?;
        self.save_mls_state()?;

        // Update stored group state
        self.keys
            .store_group_state(&conv_id, &encrypted.new_group_state)?;

        // Publish to PDS
        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        client
            .publish_event(&encrypted.tag, &encrypted.ciphertext)
            .await?;

        // Update tag mapping
        self.tag_map.insert(encrypted.tag, conv_id);

        // Apply reaction locally (toggle semantics)
        let my_did = self.client.as_ref().unwrap().did().to_string();
        if let Some(msg) = self.messages.get_mut(msg_index) {
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

        self.debug_log.log("send_reaction: published");
        Ok(())
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
