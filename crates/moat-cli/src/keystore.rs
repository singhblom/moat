//! Local key storage for Moat
//!
//! Keys are stored in ~/.moat/keys/ with appropriate file permissions.

use moat_core::GroupKind;
pub use moat_core::DeviceRingState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("key not found: {0}")]
    NotFound(String),

    #[error("invalid key data")]
    InvalidData,

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Metadata about a conversation/group
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupMetadata {
    #[serde(
        alias = "participant_did",
        deserialize_with = "deserialize_string_or_vec",
        default
    )]
    pub participant_dids: Vec<String>,
    #[serde(
        alias = "participant_handle",
        deserialize_with = "deserialize_string_or_vec",
        default
    )]
    pub participant_handles: Vec<String>,
    /// Classification of this group (User/Ring). Defaults to User for
    /// older persisted records that predate this field.
    #[serde(default)]
    pub kind: GroupKind,
    /// DIDs that have left this group but whose PDS this device has not
    /// swept since they left.
    ///
    /// A poll asks the DIDs in `participant_dids`, and processing a commit
    /// overwrites that list from MLS membership. A device that is offline
    /// while someone joins, speaks and leaves therefore processes the Add
    /// and the Remove in one catch-up pass, and never runs a poll while
    /// that person is a member — so their messages, which live on *their*
    /// PDS, are never fetched at all.
    ///
    /// Holding departed DIDs here until they have been swept once closes
    /// that gap. One sweep is enough: after the Remove merges they can
    /// publish nothing further to this group, so a single fetch sees
    /// everything they will ever have written to it.
    ///
    /// Persisted rather than kept in memory because the whole point is to
    /// survive the offline window, which usually includes a restart. See
    /// `MULTI_DEVICE.md`, "Catch-Up Across Membership Changes".
    #[serde(default)]
    pub pending_ex_members: Vec<String>,
}

/// Deserialize a field that may be a single string (old format) or a Vec<String> (new format).
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or a list of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<String>, A::Error> {
            let mut v = Vec::new();
            while let Some(s) = seq.next_element()? {
                v.push(s);
            }
            Ok(v)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

/// Pagination state (per-DID last seen rkey)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaginationState {
    /// Maps DID -> last seen rkey for incremental fetching
    /// rkeys in ATProto are typically TIDs (timestamp-based) which sort chronologically
    pub last_rkeys: std::collections::HashMap<String, String>,
}

/// Stored ATProto session tokens for avoiding repeated logins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub did: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
}

/// A locally stored message (both sent and received)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// The rkey of the published record (for ordering)
    pub rkey: String,
    /// Message content (plaintext)
    pub content: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Whether this is our own message
    pub is_own: bool,
    /// Unique message identifier (16 bytes, for reaction targeting).
    /// Option + serde(default) for backwards compat with existing stored JSON.
    pub message_id: Option<Vec<u8>>,
    /// Sender DID (for received messages)
    pub sender_did: Option<String>,
    /// Sender device name (for received messages)
    pub sender_device: Option<String>,
    /// ExternalBlob metadata for image/long-text messages (backwards compat: None for old messages).
    #[serde(default)]
    pub blob_uri: Option<String>,
    #[serde(default)]
    pub blob_key: Option<Vec<u8>>,
    #[serde(default)]
    pub blob_ciphertext_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub blob_ciphertext_size: Option<u64>,
    #[serde(default)]
    pub blob_content_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub blob_mime: Option<String>,
    #[serde(default)]
    pub blob_width: Option<u32>,
    #[serde(default)]
    pub blob_height: Option<u32>,
    /// The image's blurry placeholder, shown while the blob downloads.
    #[serde(default)]
    pub blob_thumbhash: Option<Vec<u8>>,
    /// Emoji reactions on this message.
    ///
    /// Persisted rather than kept only in the in-memory display list,
    /// because a device that receives this message through history sync
    /// cannot rebuild them: reactions arrive as their own PDS events, and
    /// events predating that device's membership are not decryptable to
    /// it. Unpersisted, they would be lost the moment history moved.
    #[serde(default)]
    pub reactions: Vec<StoredReaction>,
}

/// One emoji reaction as persisted beside its message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredReaction {
    pub emoji: String,
    pub sender_did: String,
}

/// All stored messages for a conversation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversationMessages {
    pub messages: Vec<StoredMessage>,
}

/// An event that was fetched but could not be processed, serialised to disk
/// so it survives a restart. Without this, the cursor advances past the
/// event and a restart loses it permanently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUnprocessedEvent {
    pub rkey: String,
    pub author_did: String,
    pub tag_hex: String,
    pub ciphertext_b64: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub source_did: String,
}

pub type Result<T> = std::result::Result<T, KeyStoreError>;

/// Credentials parsed from a credentials.txt file in the moat directory
pub struct CredentialsTxt {
    pub handle: String,
    pub password: String,
    pub drawbridge: Option<String>,
}

/// Local key storage
pub struct KeyStore {
    base_path: PathBuf,
}

impl KeyStore {
    /// Create a new KeyStore with a custom path
    pub fn with_path(base_path: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        fs::create_dir_all(&base_path)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&base_path)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&base_path, perms)?;
        }

        Ok(Self { base_path })
    }

    /// Store the identity private key
    pub fn store_identity_key(&self, key: &[u8]) -> Result<()> {
        let path = self.base_path.join("identity.key");
        self.write_key_file(&path, key)
    }

    /// Load the identity private key
    pub fn load_identity_key(&self) -> Result<Vec<u8>> {
        let path = self.base_path.join("identity.key");
        self.read_key_file(&path)
    }

    /// Check if identity key exists
    pub fn has_identity_key(&self) -> bool {
        self.base_path.join("identity.key").exists()
    }

    /// Store the stealth address private key (32 bytes)
    pub fn store_stealth_key(&self, key: &[u8; 32]) -> Result<()> {
        let path = self.base_path.join("stealth.key");
        self.write_key_file(&path, key)
    }

    /// Load the stealth address private key
    pub fn load_stealth_key(&self) -> Result<[u8; 32]> {
        let path = self.base_path.join("stealth.key");
        let data = self.read_key_file(&path)?;
        if data.len() != 32 {
            return Err(KeyStoreError::InvalidData);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(key)
    }

    /// Check if stealth key exists
    pub fn has_stealth_key(&self) -> bool {
        self.base_path.join("stealth.key").exists()
    }

    /// Store group state
    pub fn store_group_state(&self, group_id: &str, state: &[u8]) -> Result<()> {
        let safe_id = Self::sanitize_group_id(group_id);
        let path = self.base_path.join(format!("group_{safe_id}.state"));
        fs::write(&path, state)?;
        Ok(())
    }

    /// List all stored group IDs (looks for .meta files now)
    pub fn list_groups(&self) -> Result<Vec<String>> {
        let mut groups = Vec::new();

        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            // Look for metadata files (group_<id>.meta)
            if name.starts_with("group_") && name.ends_with(".meta") {
                let group_id = name
                    .strip_prefix("group_")
                    .and_then(|s| s.strip_suffix(".meta"))
                    .map(|s| s.to_string());

                if let Some(id) = group_id {
                    groups.push(id);
                }
            }
        }

        Ok(groups)
    }

    /// Load the device ring state from `ring.json`.
    /// Returns a default (empty) state if the file does not exist yet.
    pub fn load_ring_state(&self) -> Result<DeviceRingState> {
        let path = self.base_path.join("ring.json");
        if !path.exists() {
            return Ok(DeviceRingState::default());
        }
        let data = fs::read(&path)?;
        let state: DeviceRingState = serde_json::from_slice(&data)?;
        Ok(state)
    }

    /// Persist the device ring state to `ring.json`.
    pub fn save_ring_state(&self, state: &DeviceRingState) -> Result<()> {
        let path = self.base_path.join("ring.json");
        let json = serde_json::to_vec_pretty(state)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Store group metadata (participant info, etc.)
    pub fn store_group_metadata(&self, group_id: &str, metadata: &GroupMetadata) -> Result<()> {
        let path = self.base_path.join(format!("group_{group_id}.meta"));
        let json = serde_json::to_vec_pretty(metadata)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Load group metadata
    pub fn load_group_metadata(&self, group_id: &str) -> Result<GroupMetadata> {
        let path = self.base_path.join(format!("group_{group_id}.meta"));
        if !path.exists() {
            return Err(KeyStoreError::NotFound(format!(
                "group metadata: {group_id}"
            )));
        }
        let data = fs::read(&path)?;
        let metadata: GroupMetadata = serde_json::from_slice(&data)?;
        Ok(metadata)
    }

    /// Delete group metadata (used when leaving a conversation)
    pub fn delete_group_metadata(&self, group_id: &str) -> Result<()> {
        let meta_path = self.base_path.join(format!("group_{group_id}.meta"));
        let state_path = self.base_path.join(format!("group_{group_id}.state"));
        let messages_path = self.base_path.join(format!("group_{group_id}.messages"));

        if meta_path.exists() {
            fs::remove_file(&meta_path)?;
        }
        if state_path.exists() {
            fs::remove_file(&state_path)?;
        }
        if messages_path.exists() {
            fs::remove_file(&messages_path)?;
        }
        Ok(())
    }

    /// Load pagination state
    pub fn load_pagination_state(&self) -> Result<PaginationState> {
        let path = self.base_path.join("pagination.json");
        if !path.exists() {
            return Ok(PaginationState::default());
        }
        let data = fs::read(&path)?;
        let state: PaginationState = serde_json::from_slice(&data)?;
        Ok(state)
    }

    /// Store pagination state
    pub fn store_pagination_state(&self, state: &PaginationState) -> Result<()> {
        let path = self.base_path.join("pagination.json");
        let json = serde_json::to_vec_pretty(state)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Get last seen rkey for a specific DID
    pub fn get_last_rkey(&self, did: &str) -> Result<Option<String>> {
        let state = self.load_pagination_state()?;
        Ok(state.last_rkeys.get(did).cloned())
    }

    /// Set last seen rkey for a specific DID
    pub fn set_last_rkey(&self, did: &str, rkey: &str) -> Result<()> {
        let mut state = self.load_pagination_state()?;
        state.last_rkeys.insert(did.to_string(), rkey.to_string());
        self.store_pagination_state(&state)
    }

    pub fn store_unprocessed_events(
        &self,
        events: &[(Vec<usize>, moat_atproto::EventRecord, String)],
    ) -> Result<()> {
        use base64::Engine;
        let stored: Vec<StoredUnprocessedEvent> = events
            .iter()
            .map(|(_, ev, did)| StoredUnprocessedEvent {
                rkey: ev.rkey.clone(),
                author_did: ev.author_did.clone(),
                tag_hex: hex::encode(ev.tag.as_slice()),
                ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&ev.ciphertext),
                created_at: ev.created_at,
                source_did: did.clone(),
            })
            .collect();
        let path = self.base_path.join("unprocessed_events.json");
        if stored.is_empty() {
            let _ = fs::remove_file(&path);
            return Ok(());
        }
        let json = serde_json::to_vec(&stored)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn load_unprocessed_events(&self) -> Result<Vec<(moat_atproto::EventRecord, String)>> {
        use base64::Engine;
        let path = self.base_path.join("unprocessed_events.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read(&path)?;
        let stored: Vec<StoredUnprocessedEvent> = serde_json::from_slice(&data)?;
        let mut events = Vec::new();
        for s in stored {
            let tag_bytes = hex::decode(&s.tag_hex).unwrap_or_default();
            if tag_bytes.len() != 16 {
                continue;
            }
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_bytes);
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&s.ciphertext_b64)
                .unwrap_or_default();
            let ev = moat_atproto::EventRecord {
                uri: String::new(),
                rkey: s.rkey,
                author_did: s.author_did,
                v: 1,
                tag,
                ciphertext,
                created_at: s.created_at,
            };
            events.push((ev, s.source_did));
        }
        Ok(events)
    }

    /// Load messages for a conversation
    pub fn load_messages(&self, conv_id: &str) -> Result<ConversationMessages> {
        let path = self.base_path.join(format!("messages_{}.json", conv_id));
        if !path.exists() {
            return Ok(ConversationMessages::default());
        }
        let data = fs::read(&path)?;
        let messages: ConversationMessages = serde_json::from_slice(&data)?;
        Ok(messages)
    }

    /// Store messages for a conversation
    pub fn store_messages(&self, conv_id: &str, messages: &ConversationMessages) -> Result<()> {
        let path = self.base_path.join(format!("messages_{}.json", conv_id));
        let json = serde_json::to_vec_pretty(messages)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Append a message to a conversation's local storage, maintaining rkey order.
    /// Returns `Ok(false)` if a message with the same rkey already exists (dedup).
    /// Exception: if the existing message is missing blob metadata and the new one has it,
    /// the blob metadata fields are updated before returning `Ok(false)`.
    /// Toggle one emoji reaction on a stored message, by its message id.
    ///
    /// Reactions arrive as their own PDS events, so a device that was
    /// present can rebuild them by replaying. A device that receives this
    /// message through history sync cannot — those events predate its
    /// membership and are not decryptable to it — so the reaction has to
    /// be persisted here rather than living only in the display list.
    ///
    /// Toggling rather than adding: a reaction event means "this person
    /// pressed this emoji", and pressing it again takes it back. Returns
    /// whether the target message was found.
    pub fn toggle_reaction(
        &self,
        conv_id: &str,
        target_message_id: &[u8],
        emoji: &str,
        sender_did: &str,
    ) -> Result<bool> {
        let mut messages = self.load_messages(conv_id)?;
        let Some(msg) = messages
            .messages
            .iter_mut()
            .find(|m| m.message_id.as_deref() == Some(target_message_id))
        else {
            return Ok(false);
        };
        match msg
            .reactions
            .iter()
            .position(|r| r.emoji == emoji && r.sender_did == sender_did)
        {
            Some(pos) => {
                msg.reactions.remove(pos);
            }
            None => msg.reactions.push(StoredReaction {
                emoji: emoji.to_string(),
                sender_did: sender_did.to_string(),
            }),
        }
        self.store_messages(conv_id, &messages)?;
        Ok(true)
    }

    pub fn append_message(&self, conv_id: &str, message: StoredMessage) -> Result<bool> {
        let mut messages = self.load_messages(conv_id)?;
        // An optimistic row is identified by its `message_id`, not its
        // rkey — "pending" is a placeholder every unsent message shares.
        // The image path writes twice under it: once for the immediate
        // placeholder, then again with the blob metadata once the upload
        // finishes. Without matching on the id, the second write inserts a
        // duplicate instead of completing the row, leaving a permanent
        // "[image — processing…]" beside the real message.
        if message.rkey == "pending" {
            if let Some(mid) = message.message_id.clone() {
                if let Some(existing) = messages.messages.iter_mut().find(|m| {
                    m.rkey == "pending" && m.message_id.as_deref() == Some(mid.as_slice())
                }) {
                    *existing = message;
                    self.store_messages(conv_id, &messages)?;
                    return Ok(false);
                }
            }
        }
        if message.rkey != "pending" {
            if let Some(existing) = messages.messages.iter_mut().find(|m| m.rkey == message.rkey) {
                // Update blob metadata if the existing entry is missing it.
                if existing.blob_uri.is_none() && message.blob_uri.is_some() {
                    existing.blob_uri = message.blob_uri;
                    existing.blob_key = message.blob_key;
                    existing.blob_ciphertext_hash = message.blob_ciphertext_hash;
                    existing.blob_ciphertext_size = message.blob_ciphertext_size;
                    existing.blob_content_hash = message.blob_content_hash;
                    existing.blob_mime = message.blob_mime;
                    self.store_messages(conv_id, &messages)?;
                }
                return Ok(false);
            }
        }
        let pos = messages
            .messages
            .partition_point(|m| m.rkey <= message.rkey);
        messages.messages.insert(pos, message);
        self.store_messages(conv_id, &messages)?;
        Ok(true)
    }

    /// Update a "pending" message's rkey to the real one and re-sort.
    /// Matches by message_id when available, falls back to last "pending" message.
    pub fn fixup_pending_rkey_by_message_id(&self, conv_id: &str, real_rkey: &str, message_id: Option<&[u8]>) -> Result<()> {
        let mut messages = self.load_messages(conv_id)?;
        let found = if let Some(mid) = message_id {
            messages.messages.iter_mut().find(|m| {
                m.rkey == "pending" && m.message_id.as_deref() == Some(mid)
            })
        } else {
            messages.messages.iter_mut().rev().find(|m| m.rkey == "pending")
        };
        if let Some(msg) = found {
            msg.rkey = real_rkey.to_string();
        }
        // Re-sort by rkey
        messages.messages.sort_by(|a, b| a.rkey.cmp(&b.rkey));
        self.store_messages(conv_id, &messages)?;
        Ok(())
    }

    /// Store credentials (handle and app password)
    pub fn store_credentials(&self, handle: &str, password: &str) -> Result<()> {
        let data = format!("{}\n{}", handle, password);
        let path = self.base_path.join("credentials");
        self.write_key_file(&path, data.as_bytes())
    }

    /// Load stored credentials
    pub fn load_credentials(&self) -> Result<(String, String)> {
        let path = self.base_path.join("credentials");
        let data = self.read_key_file(&path)?;
        let text = String::from_utf8(data).map_err(|_| KeyStoreError::InvalidData)?;
        let mut lines = text.lines();

        let handle = lines.next().ok_or(KeyStoreError::InvalidData)?.to_string();
        let password = lines.next().ok_or(KeyStoreError::InvalidData)?.to_string();

        Ok((handle, password))
    }

    /// Check if credentials are stored
    pub fn has_credentials(&self) -> bool {
        self.base_path.join("credentials").exists()
    }

    /// Load credentials from a credentials.txt file in the parent directory (e.g. ~/.moat/credentials.txt).
    ///
    /// Expected format (drawbridge line is optional):
    /// ```text
    /// handle: example.bsky.social
    /// app-password: aaaa-bbbb-cccc-dddd
    /// drawbridge: wss://example.drawbridge.com/ws
    /// ```
    pub fn load_credentials_txt(&self) -> Result<CredentialsTxt> {
        let path = self.base_path.join("../..").join("credentials.txt");
        if !path.exists() {
            return Err(KeyStoreError::NotFound("credentials.txt".to_string()));
        }
        let text = fs::read_to_string(&path)?;

        let mut handle = None;
        let mut password = None;
        let mut drawbridge = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "handle" => handle = Some(value.to_string()),
                    "app-password" => password = Some(value.to_string()),
                    "drawbridge" => drawbridge = Some(value.to_string()),
                    _ => {} // ignore unknown keys
                }
            }
        }

        let handle = handle.ok_or(KeyStoreError::InvalidData)?;
        let password = password.ok_or(KeyStoreError::InvalidData)?;

        Ok(CredentialsTxt {
            handle,
            password,
            drawbridge,
        })
    }

    /// Store device name
    pub fn store_device_name(&self, name: &str) -> Result<()> {
        let path = self.base_path.join("device_name");
        self.write_key_file(&path, name.as_bytes())
    }

    /// Load device name
    pub fn load_device_name(&self) -> Result<String> {
        let path = self.base_path.join("device_name");
        let data = self.read_key_file(&path)?;
        String::from_utf8(data).map_err(|_| KeyStoreError::InvalidData)
    }

    /// Check if device name is stored
    pub fn has_device_name(&self) -> bool {
        self.base_path.join("device_name").exists()
    }

    /// Store session tokens (for reusing sessions without re-login)
    pub fn store_session(&self, session: &StoredSession) -> Result<()> {
        let path = self.base_path.join("session.json");
        let json = serde_json::to_vec_pretty(session)?;
        self.write_key_file(&path, &json)
    }

    /// Load stored session tokens
    pub fn load_session(&self) -> Result<StoredSession> {
        let path = self.base_path.join("session.json");
        let data = self.read_key_file(&path)?;
        let session: StoredSession = serde_json::from_slice(&data)?;
        Ok(session)
    }

    /// Check if session is stored
    pub fn has_session(&self) -> bool {
        self.base_path.join("session.json").exists()
    }

    /// Get or generate a default device name
    pub fn get_or_create_device_name(&self) -> Result<String> {
        if self.has_device_name() {
            return self.load_device_name();
        }

        // Generate a default device name based on hostname or a random identifier
        let device_name = if let Ok(hostname) = std::env::var("HOSTNAME") {
            format!("CLI ({})", hostname)
        } else if let Ok(hostname) = hostname::get() {
            format!("CLI ({})", hostname.to_string_lossy())
        } else {
            // Fall back to a random suffix
            let suffix: u32 = rand::random::<u32>() % 10000;
            format!("CLI Device {}", suffix)
        };

        self.store_device_name(&device_name)?;
        Ok(device_name)
    }

    /// Load watched DIDs (DIDs being monitored for incoming conversation invites)
    pub fn load_watched_dids(&self) -> Result<std::collections::HashSet<String>> {
        let path = self.base_path.join("watched_dids.json");
        if !path.exists() {
            return Ok(Default::default());
        }
        let data = fs::read(&path)?;
        let dids: Vec<String> = serde_json::from_slice(&data)?;
        Ok(dids.into_iter().collect())
    }

    /// Store watched DIDs
    pub fn store_watched_dids(&self, dids: &std::collections::HashSet<String>) -> Result<()> {
        let path = self.base_path.join("watched_dids.json");
        let list: Vec<&String> = dids.iter().collect();
        let json = serde_json::to_vec_pretty(&list)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Load Drawbridge state from drawbridge.json
    pub fn load_drawbridge_state(
        &self,
    ) -> Result<crate::drawbridge::DrawbridgeState> {
        let path = self.base_path.join("drawbridge.json");
        if !path.exists() {
            return Ok(crate::drawbridge::DrawbridgeState::default());
        }
        let data = fs::read(&path)?;
        let state: crate::drawbridge::DrawbridgeState = serde_json::from_slice(&data)?;
        Ok(state)
    }

    /// Store Drawbridge state to drawbridge.json
    pub fn store_drawbridge_state(
        &self,
        state: &crate::drawbridge::DrawbridgeState,
    ) -> Result<()> {
        let path = self.base_path.join("drawbridge.json");
        let json = serde_json::to_vec_pretty(state)?;
        self.write_key_file(&path, &json)
    }

    // Internal helpers

    fn write_key_file(&self, path: &PathBuf, data: &[u8]) -> Result<()> {
        fs::write(path, data)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    fn read_key_file(&self, path: &PathBuf) -> Result<Vec<u8>> {
        if !path.exists() {
            return Err(KeyStoreError::NotFound(
                path.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default(),
            ));
        }
        Ok(fs::read(path)?)
    }

    fn sanitize_group_id(group_id: &str) -> String {
        // Convert to hex to avoid filesystem issues
        hex::encode(group_id.as_bytes())
    }
}

/// Hex encoding utilities
pub mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, DecodeError> {
        if s.len() % 2 != 0 {
            return Err(DecodeError::OddLength);
        }

        let mut result = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();

        for chunk in bytes.chunks(2) {
            let high = hex_char_to_nibble(chunk[0])?;
            let low = hex_char_to_nibble(chunk[1])?;
            result.push((high << 4) | low);
        }

        Ok(result)
    }

    fn hex_char_to_nibble(c: u8) -> Result<u8, DecodeError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(DecodeError::InvalidChar(c as char)),
        }
    }

    #[derive(Debug)]
    pub enum DecodeError {
        OddLength,
        InvalidChar(char),
    }

    impl std::fmt::Display for DecodeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                DecodeError::OddLength => write!(f, "odd length hex string"),
                DecodeError::InvalidChar(c) => write!(f, "invalid hex character: {}", c),
            }
        }
    }

    impl std::error::Error for DecodeError {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn pending_msg(message_id: &[u8], content: &str) -> StoredMessage {
        StoredMessage {
            rkey: "pending".to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now(),
            is_own: true,
            message_id: Some(message_id.to_vec()),
            sender_did: None,
            sender_device: None,
            blob_uri: None,
            blob_key: None,
            blob_ciphertext_hash: None,
            blob_ciphertext_size: None,
            blob_content_hash: None,
            blob_mime: None,
            blob_width: None,
            blob_height: None,
            blob_thumbhash: None,
            reactions: Vec::new(),
        }
    }

    /// A send deferred behind a blob upload writes its optimistic row
    /// twice: once as a placeholder, then again with the real preview and
    /// blob metadata. Both carry rkey "pending", so identity has to come
    /// from the message id — otherwise the second write inserts a
    /// duplicate and the user is left staring at a permanent
    /// "processing…" row beside the real message.
    #[test]
    fn a_second_pending_write_completes_the_row_instead_of_duplicating_it() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();
        let id = [7u8; 16];

        assert!(store
            .append_message("conv", pending_msg(&id, "[image — processing…]"))
            .unwrap());

        let mut finished = pending_msg(&id, "[image image/png 16x16]");
        finished.blob_uri = Some("at://did:plc:alice/cid".to_string());
        assert!(!store.append_message("conv", finished).unwrap());

        let stored = store.load_messages("conv").unwrap().messages;
        assert_eq!(stored.len(), 1, "the row must be completed, not duplicated");
        assert_eq!(stored[0].content, "[image image/png 16x16]");
        assert_eq!(
            stored[0].blob_uri.as_deref(),
            Some("at://did:plc:alice/cid"),
            "the completing write carries the blob metadata"
        );
    }

    /// Two genuinely different unsent messages must still both be kept.
    #[test]
    fn pending_rows_with_different_ids_coexist() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        store.append_message("conv", pending_msg(&[1u8; 16], "first")).unwrap();
        store.append_message("conv", pending_msg(&[2u8; 16], "second")).unwrap();

        assert_eq!(store.load_messages("conv").unwrap().messages.len(), 2);
    }

    #[test]
    fn test_identity_key_roundtrip() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        let key = b"test-private-key-data";
        store.store_identity_key(key).unwrap();

        assert!(store.has_identity_key());

        let loaded = store.load_identity_key().unwrap();
        assert_eq!(loaded, key);
    }

    #[test]
    fn test_list_groups() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        let meta_a = GroupMetadata {
            participant_dids: vec!["did:plc:aaa".to_string()],
            participant_handles: vec!["alice.bsky.social".to_string()],
            ..Default::default()
        };
        let meta_b = GroupMetadata {
            participant_dids: vec!["did:plc:bbb".to_string()],
            participant_handles: vec!["bob.bsky.social".to_string()],
            ..Default::default()
        };

        store.store_group_metadata("group-a", &meta_a).unwrap();
        store.store_group_metadata("group-b", &meta_b).unwrap();

        let groups = store.list_groups().unwrap();
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_credentials_roundtrip() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        store
            .store_credentials("alice.bsky.social", "app-password")
            .unwrap();

        assert!(store.has_credentials());

        let (handle, password) = store.load_credentials().unwrap();
        assert_eq!(handle, "alice.bsky.social");
        assert_eq!(password, "app-password");
    }

    #[test]
    fn test_stealth_key_roundtrip() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        let key: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        assert!(!store.has_stealth_key());
        store.store_stealth_key(&key).unwrap();
        assert!(store.has_stealth_key());

        let loaded = store.load_stealth_key().unwrap();
        assert_eq!(loaded, key);
    }

    #[test]
    fn test_pagination_state_roundtrip() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        // Initially empty
        assert!(store.get_last_rkey("did:plc:abc123").unwrap().is_none());

        // Set rkey for a DID
        store.set_last_rkey("did:plc:abc123", "3lf7abc").unwrap();
        assert_eq!(
            store.get_last_rkey("did:plc:abc123").unwrap(),
            Some("3lf7abc".to_string())
        );

        // Set rkey for another DID
        store.set_last_rkey("did:plc:xyz789", "3lf8def").unwrap();
        assert_eq!(
            store.get_last_rkey("did:plc:xyz789").unwrap(),
            Some("3lf8def".to_string())
        );

        // First DID still has its rkey
        assert_eq!(
            store.get_last_rkey("did:plc:abc123").unwrap(),
            Some("3lf7abc".to_string())
        );

        // Update existing rkey
        store.set_last_rkey("did:plc:abc123", "3lf9ghi").unwrap();
        assert_eq!(
            store.get_last_rkey("did:plc:abc123").unwrap(),
            Some("3lf9ghi".to_string())
        );
    }

    #[test]
    fn test_group_metadata_multi_member() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        let meta = GroupMetadata {
            participant_dids: vec![
                "did:plc:aaa".to_string(),
                "did:plc:bbb".to_string(),
                "did:plc:ccc".to_string(),
            ],
            participant_handles: vec![
                "alice.bsky.social".to_string(),
                "bob.bsky.social".to_string(),
                "carol.bsky.social".to_string(),
            ],
            ..Default::default()
        };

        store.store_group_metadata("group-multi", &meta).unwrap();

        let loaded = store.load_group_metadata("group-multi").unwrap();
        assert_eq!(loaded.participant_dids.len(), 3);
        assert_eq!(loaded.participant_dids[0], "did:plc:aaa");
        assert_eq!(loaded.participant_dids[2], "did:plc:ccc");
        assert_eq!(loaded.participant_handles[1], "bob.bsky.social");
    }

    #[test]
    fn test_group_metadata_backward_compat() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        // Simulate old single-value JSON format written directly as the store would
        let old_json = r#"{"participant_did":"did:plc:old","participant_handle":"old.bsky.social"}"#;
        fs::write(dir.path().join("group_group-old.meta"), old_json).unwrap();

        let loaded = store.load_group_metadata("group-old").unwrap();
        assert_eq!(loaded.participant_dids, vec!["did:plc:old".to_string()]);
        assert_eq!(
            loaded.participant_handles,
            vec!["old.bsky.social".to_string()]
        );
    }

    /// Reactions have to survive in *storage*, not only in the display
    /// list: storage is what history sync serves from, and a device
    /// receiving a message that way cannot rebuild reactions — the events
    /// carrying them predate its membership and are not decryptable to it.
    #[test]
    fn toggling_a_reaction_persists_it() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();
        let id = vec![7u8; 16];
        let mut msg = pending_msg(&id, "hello");
        msg.rkey = "rkey001".to_string();
        store.append_message("conv", msg).unwrap();

        assert!(store
            .toggle_reaction("conv", &id, "👍", "did:plc:bob")
            .unwrap());
        let held = store.load_messages("conv").unwrap();
        assert_eq!(held.messages[0].reactions.len(), 1);
        assert_eq!(held.messages[0].reactions[0].emoji, "👍");

        // Pressing it again takes it back — a reaction event means "this
        // person pressed this emoji", not "add one more".
        store
            .toggle_reaction("conv", &id, "👍", "did:plc:bob")
            .unwrap();
        assert!(store.load_messages("conv").unwrap().messages[0]
            .reactions
            .is_empty());
    }

    /// A reaction for a message this device does not hold is reported
    /// rather than silently dropped, so a caller can tell "toggled" from
    /// "nothing to toggle".
    #[test]
    fn a_reaction_for_an_unknown_message_reports_not_found() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();
        assert!(!store
            .toggle_reaction("conv", &[9u8; 16], "👍", "did:plc:bob")
            .unwrap());
    }
}
