//! Application state and logic

use crate::keystore::{hex, GroupMetadata, KeyStore};
use crossterm::event::{KeyCode, KeyEvent};
use moat_atproto::MoatAtprotoClient;
use moat_core::{Event, EventKind, MoatSession, CIPHERSUITE};
use std::collections::HashMap;
use std::time::Instant;
use thiserror::Error;

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
}

/// Main application state
pub struct App {
    pub keys: KeyStore,
    pub client: Option<MoatAtprotoClient>,
    pub mls: MoatSession,

    // UI state
    pub focus: Focus,
    pub login_form: LoginForm,
    pub error_message: Option<String>,
    pub status_message: Option<String>,

    // Conversations
    pub conversations: Vec<Conversation>,
    pub active_conversation: Option<usize>,
    pub conversation_scroll: usize,

    // Messages for active conversation
    pub messages: Vec<DisplayMessage>,
    pub message_scroll: usize,

    // Input
    pub input_buffer: String,
    pub cursor_position: usize,

    // New conversation input
    pub new_conv_handle: String,

    // Tag -> conversation mapping (tag -> hex-encoded group_id)
    pub tag_map: HashMap<[u8; 16], String>,

    // Polling state
    last_poll: Option<Instant>,
    // TODO: Replace with cursor-based pagination per DID to avoid unbounded growth
    // and to persist across restarts. Currently this grows forever within a session.
    processed_event_uris: std::collections::HashSet<String>,

    // DIDs to watch for incoming invites
    watched_dids: std::collections::HashSet<String>,
    pub watch_handle_input: String,
}

impl App {
    /// Create a new App instance
    pub fn new() -> Result<Self> {
        let keys = KeyStore::new()?;

        // Initialize MoatSession with persistent storage at ~/.moat/mls.bin
        let mls_path = dirs::home_dir()
            .ok_or_else(|| AppError::Other("home directory not found".to_string()))?
            .join(".moat")
            .join("mls.bin");

        // Ensure parent directory exists
        if let Some(parent) = mls_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::Other(format!("Failed to create .moat directory: {e}")))?;
        }

        let mls = MoatSession::new(mls_path)?;

        let focus = if keys.has_credentials() {
            Focus::Conversations
        } else {
            Focus::Login
        };

        Ok(Self {
            keys,
            client: None,
            mls,
            focus,
            login_form: LoginForm::default(),
            error_message: None,
            status_message: None,
            conversations: Vec::new(),
            active_conversation: None,
            conversation_scroll: 0,
            messages: Vec::new(),
            message_scroll: 0,
            input_buffer: String::new(),
            cursor_position: 0,
            new_conv_handle: String::new(),
            tag_map: HashMap::new(),
            last_poll: None,
            processed_event_uris: std::collections::HashSet::new(),
            watched_dids: std::collections::HashSet::new(),
            watch_handle_input: String::new(),
        })
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
        }

        Ok(())
    }

    async fn auto_login(&mut self) -> Result<()> {
        if let Ok((handle, password)) = self.keys.load_credentials() {
            self.set_status("Logging in...".to_string());

            match MoatAtprotoClient::login(&handle, &password).await {
                Ok(client) => {
                    self.client = Some(client);
                    self.status_message = None;
                    self.load_conversations().await?;
                }
                Err(e) => {
                    self.set_error(format!("Auto-login failed: {e}"));
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

        // Generate identity key if needed (using MoatSession for persistence)
        if !self.keys.has_identity_key() {
            self.set_status("Generating identity key...".to_string());
            let identity = client.did().as_bytes();

            // Use MoatSession for persistent key generation
            let (key_package, key_bundle) = self.mls.generate_key_package(identity)?;

            // Store key bundle locally (needed for encryption operations)
            self.keys.store_identity_key(&key_bundle)?;

            // Publish key package to PDS
            self.set_status("Publishing key package...".to_string());
            let ciphersuite_name = format!("{:?}", CIPHERSUITE);
            client.publish_key_package(&key_package, &ciphersuite_name).await?;
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
            let (name, participant_did) = match self.keys.load_group_metadata(&group_id) {
                Ok(meta) => (meta.participant_handle, meta.participant_did),
                Err(_) => {
                    // Fallback for old groups without metadata
                    let short_id = &group_id[..8.min(group_id.len())];
                    (format!("Conversation {}", short_id), String::new())
                }
            };

            self.conversations.push(Conversation {
                id: group_id.clone(),
                name,
                participant_did,
                current_epoch: 0, // Will be updated when loading group
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

        // 1. Resolve handle to DID
        let recipient_did = self
            .client
            .as_ref()
            .unwrap()
            .resolve_did(recipient_handle)
            .await?;

        self.set_status(format!("Fetching key package for {}...", recipient_handle));

        // 2. Fetch recipient's key package
        let key_packages = self
            .client
            .as_ref()
            .unwrap()
            .fetch_key_packages(&recipient_did)
            .await?;
        let recipient_kp_bytes = key_packages
            .first()
            .ok_or_else(|| AppError::Other(format!("No key package found for {}", recipient_handle)))?
            .key_package
            .clone();

        // 3. Load our key bundle and get identity
        let key_bundle = self.keys.load_identity_key()?;
        let identity = self.client.as_ref().unwrap().did().as_bytes().to_vec();

        self.set_status("Creating encrypted group...".to_string());

        // 4. Create MLS group
        let group_id = self.mls.create_group(&identity, &key_bundle)?;

        // 5. Add recipient to group
        let welcome_result = self
            .mls
            .add_member(&group_id, &key_bundle, &recipient_kp_bytes)?;

        self.set_status("Publishing welcome message...".to_string());

        // 6. Publish welcome as encrypted event
        // Note: Welcome messages use a special tag derivation (epoch 0 before recipient joins)
        // The recipient will try to process any incoming events as potential welcomes
        let welcome_event = Event::welcome(group_id.clone(), 0, welcome_result.welcome);
        let encrypted = self
            .mls
            .encrypt_event(&group_id, &key_bundle, &welcome_event)?;
        self.client
            .as_ref()
            .unwrap()
            .publish_event(&encrypted.tag, &encrypted.ciphertext)
            .await?;

        // 7. Store conversation metadata
        let conv_id = hex::encode(&group_id);
        self.keys.store_group_metadata(
            &conv_id,
            &GroupMetadata {
                participant_did: recipient_did.clone(),
                participant_handle: recipient_handle.to_string(),
            },
        )?;

        // 8. Update UI - add conversation to list
        self.conversations.push(Conversation {
            id: conv_id.clone(),
            name: recipient_handle.to_string(),
            participant_did: recipient_did,
            current_epoch: 1, // Post-add epoch
            unread: 0,
        });

        // 9. Register tag for this conversation
        self.tag_map.insert(encrypted.tag, conv_id.clone());

        // 10. Select the new conversation and switch to input mode
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
        });

        Ok(())
    }

    async fn load_messages(&mut self) -> Result<()> {
        self.messages.clear();

        let Some(idx) = self.active_conversation else {
            return Ok(());
        };

        let _conv = &self.conversations[idx];

        // For MVP, messages would be loaded from PDS
        // For now, just show a placeholder
        self.messages.push(DisplayMessage {
            from: "System".to_string(),
            content: "Conversation loaded. Type a message below.".to_string(),
            timestamp: chrono::Utc::now(),
            is_own: false,
        });

        Ok(())
    }

    async fn handle_messages_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Tab => {
                self.focus = Focus::Input;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.message_scroll = self.message_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.message_scroll < self.messages.len().saturating_sub(1) {
                    self.message_scroll += 1;
                }
            }
            KeyCode::Esc => {
                self.focus = Focus::Conversations;
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
        let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
        let conv_idx = self.active_conversation.ok_or(AppError::NoConversation)?;
        let conv = &self.conversations[conv_idx];

        // Load key bundle for signing
        let key_bundle = self.keys.load_identity_key()?;

        // Parse group_id from hex
        let group_id = hex::decode(&conv.id)
            .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

        // Create message event
        let event = Event::message(
            group_id.clone(),
            conv.current_epoch,
            self.input_buffer.as_bytes(),
        );

        // Encrypt with MLS (handles padding internally)
        let encrypted = self.mls.encrypt_event(&group_id, &key_bundle, &event)?;

        // Update stored group state (epoch may have advanced)
        self.keys.store_group_state(&conv.id, &encrypted.new_group_state)?;

        // Publish encrypted event to PDS
        client.publish_event(&encrypted.tag, &encrypted.ciphertext).await?;

        // Update tag mapping with new tag
        self.tag_map.insert(encrypted.tag, conv.id.clone());

        // Add to messages display
        self.messages.push(DisplayMessage {
            from: "You".to_string(),
            content: self.input_buffer.clone(),
            timestamp: chrono::Utc::now(),
            is_own: true,
        });

        // Clear input
        self.input_buffer.clear();
        self.cursor_position = 0;

        Ok(())
    }

    /// Poll for new messages from all conversation participants
    async fn poll_messages(&mut self) -> Result<()> {
        use moat_atproto::EventRecord;

        // Collect DIDs to poll and fetch all events first (to avoid borrow issues)
        let participants: Vec<(usize, String)> = self
            .conversations
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.participant_did.clone()))
            .collect();

        let watched: Vec<String> = self.watched_dids.iter().cloned().collect();

        // Fetch events from participants
        let mut participant_events: Vec<(usize, EventRecord)> = Vec::new();
        {
            let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
            for (conv_idx, participant_did) in participants {
                let (events, _cursor) = client.fetch_events_from_did(&participant_did, None).await?;
                for event in events {
                    participant_events.push((conv_idx, event));
                }
            }
        }

        // Fetch events from watched DIDs
        let mut watched_events: Vec<(String, EventRecord)> = Vec::new();
        {
            let client = self.client.as_ref().ok_or(AppError::NotLoggedIn)?;
            for did in &watched {
                let (events, _cursor) = client.fetch_events_from_did(did, None).await?;
                for event in events {
                    watched_events.push((did.clone(), event));
                }
            }
        }

        // Process participant events
        for (conv_idx, event_record) in participant_events {
            // Skip events we've already processed
            if self.processed_event_uris.contains(&event_record.uri) {
                continue;
            }

            // Check if tag matches any known conversation
            if let Some(conv_id) = self.tag_map.get(&event_record.tag).cloned() {
                // Decrypt the event
                let group_id = hex::decode(&conv_id)
                    .map_err(|e| AppError::Other(format!("Invalid group ID: {}", e)))?;

                match self.mls.decrypt_event(&group_id, &event_record.ciphertext) {
                    Ok(decrypted) => {
                        // Update group state
                        self.keys.store_group_state(&conv_id, &decrypted.new_group_state)?;

                        // Handle based on event kind
                        match decrypted.event.kind {
                            EventKind::Message => {
                                let content =
                                    String::from_utf8_lossy(&decrypted.event.payload).to_string();

                                // Find conversation name
                                let from = self
                                    .conversations
                                    .get(conv_idx)
                                    .map(|c| c.name.clone())
                                    .unwrap_or_else(|| "Unknown".to_string());

                                // Only add to display if this is the active conversation
                                if self.active_conversation == Some(conv_idx) {
                                    self.messages.push(DisplayMessage {
                                        from,
                                        content,
                                        timestamp: event_record.created_at,
                                        is_own: false,
                                    });
                                } else {
                                    // Increment unread count
                                    if let Some(conv) = self.conversations.get_mut(conv_idx) {
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
                    Err(_) => {
                        // Decryption failed - might be for a different epoch/key
                        // Just skip this event
                    }
                }

                self.processed_event_uris.insert(event_record.uri.clone());
            } else {
                // Unknown tag - might be a welcome for a new conversation
                self.try_process_welcome(&event_record.ciphertext, &event_record.author_did, event_record.tag)?;
                self.processed_event_uris.insert(event_record.uri.clone());
            }
        }

        // Process watched DID events
        for (did, event_record) in watched_events {
            // Skip events we've already processed
            if self.processed_event_uris.contains(&event_record.uri) {
                continue;
            }

            // Skip if tag matches known conversation (already handled above or will be)
            if self.tag_map.contains_key(&event_record.tag) {
                self.processed_event_uris.insert(event_record.uri.clone());
                continue;
            }

            // Try to process as welcome
            if self.try_process_welcome(&event_record.ciphertext, &event_record.author_did, event_record.tag)? {
                // Remove from watched list - they're now a conversation participant
                self.watched_dids.remove(&did);
            }

            self.processed_event_uris.insert(event_record.uri.clone());
        }

        Ok(())
    }

    /// Try to process ciphertext as a welcome message. Returns true if successful.
    fn try_process_welcome(&mut self, ciphertext: &[u8], author_did: &str, tag: [u8; 16]) -> Result<bool> {
        if let Ok(group_id) = self.mls.process_welcome(ciphertext) {
            // Successfully joined a new group!
            let conv_id = hex::encode(&group_id);

            // Store metadata
            self.keys.store_group_metadata(
                &conv_id,
                &GroupMetadata {
                    participant_did: author_did.to_string(),
                    participant_handle: author_did.to_string(), // TODO: resolve to handle
                },
            )?;

            // Add to conversations list
            self.conversations.push(Conversation {
                id: conv_id.clone(),
                name: author_did.to_string(), // TODO: resolve to handle
                participant_did: author_did.to_string(),
                current_epoch: 1,
                unread: 1,
            });

            // Register tag
            self.tag_map.insert(tag, conv_id);

            Ok(true)
        } else {
            Ok(false)
        }
    }
}
