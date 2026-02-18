//! Local key storage for Moat
//!
//! Keys are stored in ~/.moat/keys/ with appropriate file permissions.

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMetadata {
    pub participant_did: String,
    pub participant_handle: String,
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

/// A locally stored message (for sent messages we can't decrypt from PDS)
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
    /// Can be made non-optional (Vec<u8>) once there are no pre-existing users.
    #[serde(default)]
    pub message_id: Option<Vec<u8>>,
}

/// All stored messages for a conversation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversationMessages {
    pub messages: Vec<StoredMessage>,
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

    /// Append a message to a conversation's local storage
    pub fn append_message(&self, conv_id: &str, message: StoredMessage) -> Result<()> {
        let mut messages = self.load_messages(conv_id)?;
        messages.messages.push(message);
        self.store_messages(conv_id, &messages)
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
        let path = self.base_path.join("..").join("credentials.txt");
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
            participant_did: "did:plc:aaa".to_string(),
            participant_handle: "alice.bsky.social".to_string(),
        };
        let meta_b = GroupMetadata {
            participant_did: "did:plc:bbb".to_string(),
            participant_handle: "bob.bsky.social".to_string(),
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
}
