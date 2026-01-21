//! Application state and logic

use crate::keystore::KeyStore;
use crossterm::event::{KeyCode, KeyEvent};
use moat_atproto::MoatAtprotoClient;
use moat_core::{derive_tag_from_group_id, pad_to_bucket, MoatCore, CIPHERSUITE};
use std::collections::HashMap;
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

    // Tag -> conversation mapping
    pub tag_map: HashMap<[u8; 16], String>,
}

impl App {
    /// Create a new App instance
    pub fn new() -> Result<Self> {
        let keys = KeyStore::new()?;

        let focus = if keys.has_credentials() {
            Focus::Conversations
        } else {
            Focus::Login
        };

        Ok(Self {
            keys,
            client: None,
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
            tag_map: HashMap::new(),
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
        }
    }

    /// Periodic tick for async operations
    pub async fn tick(&mut self) -> Result<()> {
        // Auto-login if credentials exist but not logged in
        if self.client.is_none() && self.keys.has_credentials() {
            self.auto_login().await?;
        }

        // Poll for new messages if logged in and have active conversation
        // (deferred for now)

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

        // Generate identity key if needed
        if !self.keys.has_identity_key() {
            self.set_status("Generating identity key...".to_string());
            let identity = client.did().as_bytes();
            let (key_package, private_key) = MoatCore::generate_key_package(identity)?;
            self.keys.store_identity_key(&private_key)?;

            // Publish key package
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
        // Load conversations from stored group states
        let group_ids = self.keys.list_groups()?;

        self.conversations.clear();
        for group_id in group_ids {
            // For now, just create a placeholder conversation
            self.conversations.push(Conversation {
                id: group_id.clone(),
                name: format!("Conversation {}", &group_id[..8.min(group_id.len())]),
                participant_did: String::new(),
                current_epoch: 0,
                unread: 0,
            });
        }

        Ok(())
    }

    async fn handle_conversations_key(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('n') => {
                self.start_new_conversation().await?;
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

    async fn start_new_conversation(&mut self) -> Result<()> {
        // For MVP, we'd prompt for a handle here
        // For now, just show a message
        self.set_status("Press 'n' and enter a handle to start a conversation".to_string());
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

        // Load group state
        let group_state = self.keys.load_group_state(&conv.id)?;

        // Pad message
        let plaintext = self.input_buffer.as_bytes();
        let padded = pad_to_bucket(plaintext);

        // Get conversation tag from group ID
        let group_id = MoatCore::get_group_id(&group_state)?;
        let epoch = MoatCore::get_epoch(&group_state)?;
        let tag = derive_tag_from_group_id(&group_id, epoch)?;

        // Publish padded message to PDS
        // Note: In MVP, we're publishing the padded plaintext directly
        // Full implementation would use MLS encryption
        client.publish_event(&tag, &padded).await?;

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
}
