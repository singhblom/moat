//! Application state and logic

use crate::keystore::{hex, GroupMetadata, KeyStore, StoredSession};
use crossterm::event::{KeyCode, KeyEvent};
use moat_atproto::MoatAtprotoClient;
use moat_core::{
    encrypt_for_stealth, generate_stealth_keypair, try_decrypt_stealth, Event, EventKind,
    MoatCredential, MoatSession, CIPHERSUITE,
};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use thiserror::Error;

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
}

/// A notification about a new device joining a conversation
#[derive(Debug, Clone)]
pub struct DeviceAlert {
    pub conversation_name: String,
    pub user_name: String,
    pub device_name: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
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
    pub selected_message: Option<usize>,  // For message info feature
    pub show_message_info: bool,          // Toggle message info popup

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
            device_alerts: Vec::new(),
            input_buffer: String::new(),
            cursor_position: 0,
            new_conv_handle: String::new(),
            tag_map: HashMap::new(),
            last_poll: None,
            last_device_poll: None,
            watched_dids: std::collections::HashSet::new(),
            watch_handle_input: String::new(),
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
            Focus::Input => self.handle_input_key(key).await,
            Focus::NewConversation => self.handle_new_conversation_key(key).await,
            Focus::WatchHandle => self.handle_watch_handle_key(key).await,
        }
    }

    /// Periodic tick for async operations
    pub async fn tick(&mut self) -> Result<()> {
        // Auto-login if credentials exist but not logged in
        if self.client.is_none() && self.keys.has_credentials() {
            self.auto_login().await?;
        }

        // Poll for new messages if logged in (every 5 seconds)
        if self.client.is_some() {
            let should_poll = self
                .last_poll
                .map(|t| t.elapsed().as_secs() >= 5)
                .unwrap_or(true);

            if should_poll {
                self.last_poll = Some(Instant::now());
                if let Err(e) = self.poll_messages().await {
                    // Log error but don't fail the tick
                    self.set_error(format!("Poll error: {e}"));
                }
            }

            // Poll for new devices from group members (every 30 seconds)
            let should_poll_devices = self
                .last_device_poll
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true);

            if should_poll_devices {
                self.last_device_poll = Some(Instant::now());
                if let Err(e) = self.poll_for_new_devices().await {
                    self.debug_log.log(&format!("Device poll error: {e}"));
                }
            }
        }

        Ok(())
    }

    async fn auto_login(&mut self) -> Result<()> {
        // First, try to resume from stored session tokens (avoids rate limiting)
        if self.keys.has_session() {
            if let Ok(stored_session) = self.keys.load_session() {
                self.set_status("Resuming session...".to_string());

                match MoatAtprotoClient::resume_session(
                    &stored_session.did,
                    &stored_session.access_jwt,
                    &stored_session.refresh_jwt,
                )
                .await
                {
                    Ok(client) => {
                        // Update stored tokens (may have been refreshed)
                        if let Some((access_jwt, refresh_jwt)) = client.get_session_tokens().await {
                            let _ = self.keys.store_session(&StoredSession {
                                did: stored_session.did.clone(),
                                access_jwt,
                                refresh_jwt,
                            });
                        }

                        self.client = Some(client);
                        self.status_message = None;
                        self.load_conversations().await?;
                        return Ok(());
                    }
                    Err(_) => {
                        // Session expired or invalid, clear it and fall through to login
                        let _ = self.keys.clear_session();
                        self.debug_log
                            .log("auto_login: stored session invalid, will try fresh login");
                    }
                }
            }
        }

        // Fall back to fresh login with credentials
        if let Ok((handle, password)) = self.keys.load_credentials() {
            self.set_status("Logging in...".to_string());

            match MoatAtprotoClient::login(&handle, &password).await {
                Ok(client) => {
                    // Store session tokens for future use
                    if let Some((access_jwt, refresh_jwt)) = client.get_session_tokens().await {
                        let _ = self.keys.store_session(&StoredSession {
                            did: client.did().to_string(),
                            access_jwt,
                            refresh_jwt,
                        });
                    }

                    self.client = Some(client);
                    self.status_message = None;
                    self.load_conversations().await?;
                }
                Err(e) => {
                    // Don't retry automatically - show warning and go to login screen
                    self.set_error(format!(
                        "Login failed: {e}\n\nIf you hit rate limits, wait before trying again.\nCheck your app password if credentials are outdated."
                    ));
                    self.focus = Focus::Login;
                }
            }
        }
        Ok(())
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
            let credential = MoatCredential::new(client.did(), &device_name);

            // Use MoatSession for persistent key generation
            let (key_package, key_bundle) = self.mls.generate_key_package(&credential)?;
            self.save_mls_state()?;

            // Store key bundle locally (needed for encryption operations)
            self.keys.store_identity_key(&key_bundle)?;

            // Publish key package to PDS
            self.set_status("Publishing key package...".to_string());
            let ciphersuite_name = format!("{:?}", CIPHERSUITE);
            client.publish_key_package(&key_package, &ciphersuite_name).await?;
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

        self.load_conversations().await?;

        Ok(())
    }

    async fn load_conversations(&mut self) -> Result<()> {
        // Load conversations from stored group metadata
        let group_ids = self.keys.list_groups()?;

        self.conversations.clear();
        for group_id in group_ids {
            // Try to load metadata for this group
            let (mut name, participant_did) = match self.keys.load_group_metadata(&group_id) {
                Ok(meta) => (meta.participant_handle, meta.participant_did),
                Err(_) => {
                    // Fallback for old groups without metadata
                    let short_id = &group_id[..8.min(group_id.len())];
                    (format!("Conversation {}", short_id), String::new())
                }
            };

            // If name looks like a DID, try to resolve it to a handle
            if name.starts_with("did:") {
                if let Some(client) = &self.client {
                    if let Ok(handle) = client.resolve_handle(&name).await {
                        // Update stored metadata with resolved handle
                        let _ = self.keys.store_group_metadata(
                            &group_id,
                            &GroupMetadata {
                                participant_did: participant_did.clone(),
                                participant_handle: handle.clone(),
                            },
                        );
                        name = handle;
                    }
                }
            }

            // Get the current epoch from the MLS group and register the tag
            let group_id_bytes = hex::decode(&group_id)
                .unwrap_or_default();

            let current_epoch = if let Ok(Some(epoch)) = self.mls.get_group_epoch(&group_id_bytes) {
                epoch
            } else {
                1 // Default to epoch 1 if group can't be loaded
            };

            // Register tag for current epoch
            if let Ok(tag) = moat_core::derive_tag_from_group_id(&group_id_bytes, current_epoch) {
                self.debug_log.log(&format!(
                    "load_conversations: registering tag {:02x?} for conv {} epoch {}",
                    &tag[..4],
                    &group_id[..16.min(group_id.len())],
                    current_epoch
                ));
                self.tag_map.insert(tag, group_id.clone());
            }

            self.conversations.push(Conversation {
                id: group_id.clone(),
                name,
                participant_did,
                current_epoch,
                unread: 0,
            });
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
                if self.active_conversation.is_some() {
                    self.load_messages().await?;
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
            self.load_messages().await?;
            self.focus = Focus::Input;
            self.new_conv_handle.clear();
            self.status_message = None;
            self.set_status(format!(
                "Switched to existing conversation with {}",
                recipient_handle
            ));
            return Ok(());
        }

        self.set_status(format!("Fetching stealth addresses for {}...", recipient_handle));

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
        let credential = MoatCredential::new(&did, &device_name);

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

        // 11. Register current epoch's tag for this conversation (for future messages)
        let current_tag = moat_core::derive_tag_from_group_id(&group_id, 1)?;
        self.debug_log.log(&format!(
            "start_conv: registering tag {:02x?} for conv {}",
            &current_tag[..4],
            &conv_id[..16]
        ));
        self.tag_map.insert(current_tag, conv_id.clone());

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
        });

        Ok(())
    }

    async fn load_messages(&mut self) -> Result<()> {
        self.messages.clear();

        let Some(idx) = self.active_conversation else {
            return Ok(());
        };

        let conv = &self.conversations[idx];
        let conv_id = conv.id.clone();
        let participant_did = conv.participant_did.clone();
        let participant_name = conv.name.clone();
        let current_epoch = conv.current_epoch;

        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        let my_did = client.did().to_string();

        self.debug_log.log(&format!(
            "load_messages: conv={}, participant={}, my_did={}, epoch={}",
            &conv_id[..16.min(conv_id.len())],
            &participant_did[..20.min(participant_did.len())],
            &my_did[..20.min(my_did.len())],
            current_epoch
        ));

        // Load locally stored messages (our sent messages that MLS can't decrypt)
        let local_messages = self.keys.load_messages(&conv_id).unwrap_or_default();
        let local_rkeys: std::collections::HashSet<String> = local_messages
            .messages
            .iter()
            .map(|m| m.rkey.clone())
            .collect();

        self.debug_log.log(&format!(
            "load_messages: {} locally stored messages",
            local_messages.messages.len()
        ));

        // Generate all valid tags for this conversation (epochs 0 through current)
        let group_id = hex::decode(&conv_id)
            .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

        let epochs: Vec<u64> = (0..=current_epoch).collect();
        let valid_tags: std::collections::HashSet<[u8; 16]> = epochs
            .iter()
            .filter_map(|&epoch| moat_core::derive_tag_from_group_id(&group_id, epoch).ok())
            .collect();

        self.debug_log.log(&format!(
            "load_messages: generated {} valid tags for epochs 0..={}",
            valid_tags.len(),
            current_epoch
        ));

        // Fetch events from participant only (we have our own messages locally)
        let their_events = client.fetch_events_from_did(&participant_did, None).await.unwrap_or_default();

        self.debug_log.log(&format!(
            "load_messages: fetched {} events from participant",
            their_events.len()
        ));

        // Filter by valid tags for this conversation
        let their_events: Vec<_> = their_events
            .into_iter()
            .filter(|e| valid_tags.contains(&e.tag))
            .collect();

        self.debug_log.log(&format!(
            "load_messages: {} events match conversation tags",
            their_events.len()
        ));

        // Build a combined list of (rkey, DisplayMessage)
        let mut all_messages: Vec<(String, DisplayMessage)> = Vec::new();

        // Add locally stored messages (our sent messages)
        for stored in &local_messages.messages {
            all_messages.push((
                stored.rkey.clone(),
                DisplayMessage {
                    from: "You".to_string(),
                    content: stored.content.clone(),
                    timestamp: stored.timestamp,
                    is_own: true,
                    sender_did: Some(my_did.clone()),
                    sender_device: self.keys.get_or_create_device_name().ok(),
                },
            ));
        }

        // Decrypt and add received messages
        for event_record in their_events {
            // Skip if we somehow have this rkey locally (shouldn't happen for their messages)
            if local_rkeys.contains(&event_record.rkey) {
                continue;
            }

            match self.mls.decrypt_event(&group_id, &event_record.ciphertext) {
                Ok(decrypted) => {
                    if let EventKind::Message = decrypted.event.kind {
                        let content = String::from_utf8_lossy(&decrypted.event.payload).to_string();

                        // Extract sender info for collapsed identity and message info
                        let (sender_did, sender_device) = decrypted.sender
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
                            },
                        ));
                    }
                    // Ignore non-message events (Commit, Checkpoint, Welcome)
                }
                Err(e) => {
                    self.debug_log.log(&format!(
                        "load_messages: failed to decrypt event {}: {}",
                        &event_record.rkey,
                        e
                    ));
                    // Skip events we can't decrypt (might be from before we joined)
                }
            }
        }

        // Save MLS state after decrypting messages
        if self.mls.has_pending_changes() {
            self.save_mls_state()?;
        }

        // Sort by rkey (chronological order since rkeys are TIDs)
        all_messages.sort_by(|a, b| a.0.cmp(&b.0));

        // Extract just the messages
        self.messages = all_messages.into_iter().map(|(_, msg)| msg).collect();

        // Clear unread count since we've now loaded the conversation
        if let Some(conv) = self.conversations.get_mut(idx) {
            conv.unread = 0;
        }

        self.debug_log.log(&format!(
            "load_messages: loaded {} messages total",
            self.messages.len()
        ));

        Ok(())
    }

    async fn handle_messages_key(&mut self, key: KeyEvent) -> Result<bool> {
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

    async fn handle_input_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Enter => {
                if !self.input_buffer.is_empty() {
                    self.send_message().await?;
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

    async fn send_message(&mut self) -> Result<()> {
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

        // Load key bundle for signing
        let key_bundle = self.keys.load_identity_key()?;

        // Parse group_id from hex
        let group_id = hex::decode(&conv_id)
            .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

        // Create message event
        let current_epoch = self.mls.get_group_epoch(&group_id)?.unwrap_or(1);
        let message_bytes = self.input_buffer.as_bytes().to_vec();
        let event = Event::message(
            group_id.clone(),
            current_epoch,
            &message_bytes,
        );

        // Encrypt with MLS (handles padding internally)
        // If encryption fails (e.g., stale epoch), try to refresh state first
        let encrypted = match self.mls.encrypt_event(&group_id, &key_bundle, &event) {
            Ok(enc) => enc,
            Err(e) => {
                self.debug_log.log(&format!(
                    "send_message: encryption failed ({}), attempting refresh",
                    e
                ));
                // Try to poll for updates before failing
                self.poll_messages().await?;

                // Retry encryption with potentially updated state
                let new_epoch = self.mls.get_group_epoch(&group_id)?.unwrap_or(1);
                let new_event = Event::message(
                    group_id.clone(),
                    new_epoch,
                    &message_bytes,
                );
                self.mls.encrypt_event(&group_id, &key_bundle, &new_event)?
            }
        };
        self.save_mls_state()?;

        self.debug_log.log(&format!(
            "send_message: encrypted, tag={:02x?}",
            &encrypted.tag[..4]
        ));

        // Update stored group state (epoch may have advanced)
        self.keys.store_group_state(&conv_id, &encrypted.new_group_state)?;

        // Publish encrypted event to PDS
        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        let uri = client.publish_event(&encrypted.tag, &encrypted.ciphertext).await?;

        // Extract rkey from URI: at://did:plc:xxx/social.moat.event/rkey
        let rkey = uri.split('/').last().unwrap_or("unknown").to_string();
        let timestamp = chrono::Utc::now();

        self.debug_log.log(&format!("send_message: published to PDS, rkey={}", rkey));

        // Update tag mapping with new tag
        self.tag_map.insert(encrypted.tag, conv_id.clone());

        // Store message locally (MLS can't decrypt our own messages)
        let stored_msg = crate::keystore::StoredMessage {
            rkey: rkey.clone(),
            content: self.input_buffer.clone(),
            timestamp,
            is_own: true,
        };
        if let Err(e) = self.keys.append_message(&conv_id, stored_msg) {
            self.debug_log.log(&format!("send_message: failed to store locally: {}", e));
        }

        // Add to messages display
        let my_did = client.did().to_string();
        self.messages.push(DisplayMessage {
            from: "You".to_string(),
            content: self.input_buffer.clone(),
            timestamp,
            is_own: true,
            sender_did: Some(my_did),
            sender_device: self.keys.get_or_create_device_name().ok(),
        });

        // Clear input
        self.input_buffer.clear();
        self.cursor_position = 0;

        Ok(())
    }

    /// Poll for new messages from all conversation participants
    ///
    /// Uses rkey-based pagination to only fetch new events since last poll.
    /// This avoids unbounded memory growth from tracking all seen URIs.
    async fn poll_messages(&mut self) -> Result<()> {
        use moat_atproto::EventRecord;

        // Collect DIDs to poll (deduplicated)
        let mut dids_to_poll: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
        for (idx, conv) in self.conversations.iter().enumerate() {
            dids_to_poll
                .entry(conv.participant_did.clone())
                .or_default()
                .push(idx);
        }

        let watched: Vec<String> = self.watched_dids.iter().cloned().collect();

        self.debug_log.log(&format!(
            "poll: {} unique participant DIDs, {} watched DIDs, {} known tags",
            dids_to_poll.len(),
            watched.len(),
            self.tag_map.len()
        ));

        // Fetch events from participants using rkey-based pagination
        let mut participant_events: Vec<(Vec<usize>, EventRecord, String)> = Vec::new(); // (conv_indices, event, did)
        let mut new_rkeys: Vec<(String, String)> = Vec::new(); // (did, max_rkey)
        {
            let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
            for (participant_did, conv_indices) in &dids_to_poll {
                // Get last seen rkey for this DID
                let last_rkey = self.keys.get_last_rkey(participant_did).ok().flatten();

                self.debug_log.log(&format!(
                    "poll: fetching from DID {} (last_rkey={:?})",
                    &participant_did[..20.min(participant_did.len())],
                    last_rkey.as_ref().map(|r| &r[..10.min(r.len())])
                ));

                match client.fetch_events_from_did(participant_did, last_rkey.as_deref()).await {
                    Ok(events) => {
                        self.debug_log.log(&format!(
                            "poll: got {} events from {}",
                            events.len(),
                            &participant_did[..20.min(participant_did.len())]
                        ));

                        // Track max rkey seen and filter out already-seen events
                        // Note: rkey_start is INCLUSIVE in ATProto, so we must skip events <= last_rkey
                        let mut max_rkey: Option<String> = last_rkey.clone();
                        let mut new_count = 0;
                        for event in events {
                            // Skip events we've already seen (rkey_start is inclusive)
                            if let Some(ref last) = last_rkey {
                                if event.rkey <= *last {
                                    continue;
                                }
                            }
                            new_count += 1;
                            // Update max rkey (rkeys are TIDs that sort lexicographically)
                            if max_rkey.as_ref().map_or(true, |m| event.rkey > *m) {
                                max_rkey = Some(event.rkey.clone());
                            }
                            participant_events.push((conv_indices.clone(), event, participant_did.clone()));
                        }
                        self.debug_log.log(&format!("poll: {} new events after filtering", new_count));

                        // Record the new max rkey for this DID
                        if let Some(rkey) = max_rkey {
                            new_rkeys.push((participant_did.clone(), rkey));
                        }
                    }
                    Err(e) => {
                        self.debug_log.log(&format!(
                            "poll: error fetching from {}: {}",
                            &participant_did[..20.min(participant_did.len())],
                            e
                        ));
                    }
                }
            }
        }

        // Fetch events from watched DIDs
        let mut watched_events: Vec<(String, EventRecord)> = Vec::new();
        {
            let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
            for did in &watched {
                let last_rkey = self.keys.get_last_rkey(did).ok().flatten();

                match client.fetch_events_from_did(did, last_rkey.as_deref()).await {
                    Ok(events) => {
                        let mut max_rkey = last_rkey.clone();
                        for event in events {
                            // Skip events we've already seen (rkey_start is inclusive)
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
                    Err(_) => {
                        // Silently skip DIDs that fail (repo may not exist)
                    }
                }
            }
        }

        self.debug_log.log(&format!(
            "poll: fetched {} participant events, {} watched events",
            participant_events.len(),
            watched_events.len()
        ));

        // Process participant events
        for (conv_indices, event_record, _did) in participant_events {
            self.debug_log.log(&format!(
                "poll: processing event rkey={}, tag={:02x?}",
                &event_record.rkey[..10.min(event_record.rkey.len())],
                &event_record.tag[..4]
            ));

            // Check if tag matches any known conversation
            if let Some(conv_id) = self.tag_map.get(&event_record.tag).cloned() {
                self.debug_log.log(&format!("poll: tag matched conv {}", &conv_id[..16]));

                // Decrypt the event
                let group_id = hex::decode(&conv_id)
                    .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

                match self.mls.decrypt_event(&group_id, &event_record.ciphertext) {
                    Ok(decrypted) => {
                        self.debug_log.log(&format!("poll: decrypted, kind={:?}", decrypted.event.kind));

                        // Update group state
                        if let Err(e) = self.keys.store_group_state(&conv_id, &decrypted.new_group_state) {
                            self.debug_log.log(&format!("poll: failed to store group state: {}", e));
                        }

                        // Handle based on event kind
                        match decrypted.event.kind {
                            EventKind::Message => {
                                let content =
                                    String::from_utf8_lossy(&decrypted.event.payload).to_string();

                                // Find the first matching conversation index
                                let conv_idx = conv_indices.first().copied();

                                // Find conversation name
                                let from = conv_idx
                                    .and_then(|idx| self.conversations.get(idx))
                                    .map(|c| c.name.clone())
                                    .unwrap_or_else(|| "Unknown".to_string());

                                // Extract sender info for collapsed identity and message info
                                let (sender_did, sender_device) = decrypted.sender
                                    .map(|s| (Some(s.did), Some(s.device_name)))
                                    .unwrap_or((None, None));

                                // Only add to display if this is the active conversation
                                if self.active_conversation == conv_idx {
                                    self.messages.push(DisplayMessage {
                                        from,
                                        content,
                                        timestamp: event_record.created_at,
                                        is_own: false,
                                        sender_did,
                                        sender_device,
                                    });
                                } else if let Some(idx) = conv_idx {
                                    // Increment unread count
                                    if let Some(conv) = self.conversations.get_mut(idx) {
                                        conv.unread += 1;
                                    }
                                }
                            }
                            EventKind::Commit => {
                                // MLS commit - state already updated above
                            }
                            EventKind::Checkpoint => {
                                // Checkpoint - could use for faster sync
                            }
                            EventKind::Welcome => {
                                // Welcome inside existing conversation - unusual
                            }
                        }
                    }
                    Err(e) => {
                        // Decryption failed - might be for a different epoch/key
                        self.debug_log.log(&format!("poll: decryption failed: {}", e));
                    }
                }
            } else {
                // Unknown tag - might be a welcome for a new conversation
                self.debug_log.log("poll: tag not matched, trying as welcome");
                self.try_process_welcome(&event_record.ciphertext, &event_record.author_did, event_record.tag).await?;
            }
        }

        // Process watched DID events
        for (did, event_record) in watched_events {
            // Skip if tag matches known conversation (already handled above or will be)
            if self.tag_map.contains_key(&event_record.tag) {
                continue;
            }

            // Try to process as welcome
            if self.try_process_welcome(&event_record.ciphertext, &event_record.author_did, event_record.tag).await? {
                // Remove from watched list - they're now a conversation participant
                self.watched_dids.remove(&did);
            }
        }

        // Save MLS state if any decrypt/welcome operations modified it
        if self.mls.has_pending_changes() {
            self.save_mls_state()?;
        }

        // Persist new rkeys for all DIDs we fetched from
        for (did, rkey) in new_rkeys {
            if let Err(e) = self.keys.set_last_rkey(&did, &rkey) {
                self.debug_log.log(&format!("poll: failed to save rkey for {}: {}", &did[..20.min(did.len())], e));
            }
        }

        Ok(())
    }

    /// Try to process ciphertext as a stealth-encrypted welcome message.
    /// Returns true if successful.
    async fn try_process_welcome(
        &mut self,
        ciphertext: &[u8],
        author_did: &str,
        _tag: [u8; 16],
    ) -> Result<bool> {
        // Load our stealth private key
        let stealth_privkey = match self.keys.load_stealth_key() {
            Ok(key) => key,
            Err(_) => {
                self.debug_log.log("try_process_welcome: no stealth key");
                return Ok(false);
            }
        };

        // Try stealth decryption first
        let welcome_bytes = match try_decrypt_stealth(&stealth_privkey, ciphertext) {
            Some(bytes) => {
                self.debug_log.log(&format!(
                    "try_process_welcome: stealth decrypted {} bytes from {}",
                    bytes.len(),
                    &author_did[..20]
                ));
                bytes
            }
            None => return Ok(false), // Not for us, or not a stealth-encrypted welcome
        };

        // Now try to process the decrypted bytes as an MLS Welcome
        let group_id = match self.mls.process_welcome(&welcome_bytes) {
            Ok(id) => {
                self.debug_log.log(&format!("try_process_welcome: MLS welcome processed, group_id len={}", id.len()));
                id
            }
            Err(e) => {
                self.debug_log.log(&format!("try_process_welcome: MLS welcome failed: {}", e));
                return Ok(false);
            }
        };

        // Successfully joined a new group!
        let conv_id = hex::encode(&group_id);

        // Try to resolve the sender's DID to a handle
        let participant_handle = if let Some(client) = &self.client {
            client.resolve_handle(author_did).await.unwrap_or_else(|_| author_did.to_string())
        } else {
            author_did.to_string()
        };

        // Store metadata with resolved handle
        self.keys.store_group_metadata(
            &conv_id,
            &GroupMetadata {
                participant_did: author_did.to_string(),
                participant_handle: participant_handle.clone(),
            },
        )?;

        // Add to conversations list
        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name: participant_handle,
            participant_did: author_did.to_string(),
            current_epoch: 1,
            unread: 1,
        });

        // Register current epoch's tag for this conversation
        if let Ok(current_tag) = moat_core::derive_tag_from_group_id(&group_id, 1) {
            self.debug_log.log(&format!(
                "process_welcome: registering tag {:02x?} for conv {}",
                &current_tag[..4],
                &conv_id[..16]
            ));
            self.tag_map.insert(current_tag, conv_id);
        }

        self.debug_log.log("process_welcome: successfully joined group");
        Ok(true)
    }

    /// Poll for new devices from existing group members and auto-add them.
    ///
    /// For each conversation:
    /// 1. Get all DIDs currently in the group
    /// 2. Fetch key packages for each DID
    /// 3. Check if any key packages represent new devices (not already in group)
    /// 4. Add new devices with a random delay to reduce race conditions
    async fn poll_for_new_devices(&mut self) -> Result<()> {
        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        let my_did = client.did().to_string();

        // Collect group info for all conversations
        let mut groups_to_check: Vec<(Vec<u8>, String)> = Vec::new(); // (group_id, conv_id)
        for conv in &self.conversations {
            if let Ok(group_id) = hex::decode(&conv.id) {
                groups_to_check.push((group_id, conv.id.clone()));
            }
        }

        for (group_id, conv_id) in groups_to_check {
            // Get all DIDs in this group
            let group_dids = match self.mls.get_group_dids(&group_id) {
                Ok(dids) => dids,
                Err(e) => {
                    self.debug_log.log(&format!(
                        "poll_devices: failed to get DIDs for group {}: {}",
                        &conv_id[..16.min(conv_id.len())],
                        e
                    ));
                    continue;
                }
            };

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
                    cred.as_ref().map(|c| (c.did().to_string(), c.device_name().to_string()))
                })
                .collect();

            self.debug_log.log(&format!(
                "poll_devices: group {} has {} DIDs, {} device entries",
                &conv_id[..16.min(conv_id.len())],
                group_dids.len(),
                existing_devices.len()
            ));

            // For each DID in the group, fetch their key packages
            // This includes our own DID - we want to add our own new devices too
            for did in &group_dids {
                let key_packages = match client.fetch_key_packages(did).await {
                    Ok(kps) => kps,
                    Err(e) => {
                        self.debug_log.log(&format!(
                            "poll_devices: failed to fetch key packages for {}: {}",
                            &did[..20.min(did.len())],
                            e
                        ));
                        continue;
                    }
                };

                self.debug_log.log(&format!(
                    "poll_devices: fetched {} key packages for {}",
                    key_packages.len(),
                    &did[..20.min(did.len())]
                ));

                // Check each key package to see if it's a new device
                for kp_record in key_packages {
                    // Extract credential from the key package
                    let credential = match self.mls.extract_credential_from_key_package(&kp_record.key_package) {
                        Ok(Some(c)) => c,
                        Ok(None) => {
                            self.debug_log.log("poll_devices: key package has no credential");
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

                    let device_key = (credential.did().to_string(), credential.device_name().to_string());

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
                        "poll_devices: found new device '{}' for DID {}",
                        credential.device_name(),
                        &credential.did()[..20.min(credential.did().len())]
                    ));

                    // Add random delay (0-5 seconds) to reduce race conditions
                    // when multiple group members try to add the same device
                    let delay_ms = rand::random::<u64>() % 5000;
                    self.debug_log.log(&format!(
                        "poll_devices: waiting {}ms before adding device",
                        delay_ms
                    ));
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

                    // Re-check if device was added by someone else during our delay
                    let members_after_delay = match self.mls.get_group_members(&group_id) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let devices_after_delay: std::collections::HashSet<(String, String)> = members_after_delay
                        .iter()
                        .filter_map(|(_, cred)| {
                            cred.as_ref().map(|c| (c.did().to_string(), c.device_name().to_string()))
                        })
                        .collect();

                    if devices_after_delay.contains(&device_key) {
                        self.debug_log.log(&format!(
                            "poll_devices: device '{}' was added by someone else",
                            credential.device_name()
                        ));
                        continue;
                    }

                    // Load our key bundle to perform the add
                    let key_bundle = match self.keys.load_identity_key() {
                        Ok(kb) => kb,
                        Err(e) => {
                            self.debug_log.log(&format!(
                                "poll_devices: failed to load key bundle: {}",
                                e
                            ));
                            continue;
                        }
                    };

                    // Add the new device
                    match self.mls.add_device(&group_id, &key_bundle, &kp_record.key_package) {
                        Ok(welcome_result) => {
                            self.debug_log.log(&format!(
                                "poll_devices: successfully added device '{}' to group",
                                credential.device_name()
                            ));

                            // Save MLS state
                            if let Err(e) = self.save_mls_state() {
                                self.debug_log.log(&format!(
                                    "poll_devices: failed to save MLS state: {}",
                                    e
                                ));
                            }

                            // Get current epoch for the tag
                            let epoch = self.mls.get_group_epoch(&group_id)
                                .ok()
                                .flatten()
                                .unwrap_or(1);
                            let tag = match moat_core::derive_tag_from_group_id(&group_id, epoch) {
                                Ok(t) => t,
                                Err(e) => {
                                    self.debug_log.log(&format!(
                                        "poll_devices: failed to derive tag: {}",
                                        e
                                    ));
                                    continue;
                                }
                            };

                            // Update tag map with new epoch
                            self.tag_map.insert(tag, conv_id.clone());

                            // Publish the commit (so other members see the change)
                            if let Err(e) = client.publish_event(&tag, &welcome_result.commit).await {
                                self.debug_log.log(&format!(
                                    "poll_devices: failed to publish commit: {}",
                                    e
                                ));
                            }

                            // Encrypt and publish welcome for the new device using stealth addresses
                            // Fetch all stealth addresses for this DID (one per device)
                            match client.fetch_stealth_addresses(did).await {
                                Ok(stealth_records) if !stealth_records.is_empty() => {
                                    let stealth_pubkeys: Vec<[u8; 32]> =
                                        stealth_records.iter().map(|r| r.scan_pubkey).collect();
                                    match moat_core::encrypt_for_stealth(&stealth_pubkeys, &welcome_result.welcome) {
                                        Ok(stealth_ciphertext) => {
                                            // Publish with random tag (recipient finds it via stealth decryption)
                                            let random_tag: [u8; 16] = rand::random();
                                            if let Err(e) = client.publish_event(&random_tag, &stealth_ciphertext).await {
                                                self.debug_log.log(&format!(
                                                    "poll_devices: failed to publish welcome: {}",
                                                    e
                                                ));
                                            } else {
                                                self.debug_log.log(&format!(
                                                    "poll_devices: published welcome for device '{}' (encrypted for {} devices)",
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
                                    self.debug_log.log(&format!(
                                        "poll_devices: no stealth addresses for {}, cannot send welcome",
                                        &did[..20.min(did.len())]
                                    ));
                                }
                                Err(e) => {
                                    self.debug_log.log(&format!(
                                        "poll_devices: failed to fetch stealth addresses: {}",
                                        e
                                    ));
                                }
                            }

                            // Update conversation epoch in UI and add device alert
                            let conv_name = self.conversations.iter()
                                .find(|c| c.id == conv_id)
                                .map(|c| c.name.clone())
                                .unwrap_or_else(|| "Unknown".to_string());

                            if let Some(conv) = self.conversations.iter_mut().find(|c| c.id == conv_id) {
                                conv.current_epoch = epoch;
                            }

                            // Add device alert for UI notification
                            self.device_alerts.push(DeviceAlert {
                                conversation_name: conv_name,
                                user_name: credential.did().to_string(),
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
