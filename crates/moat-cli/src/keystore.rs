//! Local key storage for Moat
//!
//! Keys are stored in ~/.moat/keys/ with appropriate file permissions.

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
}

pub type Result<T> = std::result::Result<T, KeyStoreError>;

/// Local key storage
pub struct KeyStore {
    base_path: PathBuf,
}

impl KeyStore {
    /// Create a new KeyStore with the default path (~/.moat/keys/)
    pub fn new() -> Result<Self> {
        let base_path = dirs::home_dir()
            .ok_or_else(|| KeyStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "home directory not found",
            )))?
            .join(".moat")
            .join("keys");

        Self::with_path(base_path)
    }

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

    /// Store a group private key
    pub fn store_group_key(&self, group_id: &str, key: &[u8]) -> Result<()> {
        let safe_id = Self::sanitize_group_id(group_id);
        let path = self.base_path.join(format!("group_{safe_id}.key"));
        self.write_key_file(&path, key)
    }

    /// Load a group private key
    pub fn load_group_key(&self, group_id: &str) -> Result<Vec<u8>> {
        let safe_id = Self::sanitize_group_id(group_id);
        let path = self.base_path.join(format!("group_{safe_id}.key"));
        self.read_key_file(&path)
    }

    /// Store group state
    pub fn store_group_state(&self, group_id: &str, state: &[u8]) -> Result<()> {
        let safe_id = Self::sanitize_group_id(group_id);
        let path = self.base_path.join(format!("group_{safe_id}.state"));
        fs::write(&path, state)?;
        Ok(())
    }

    /// Load group state
    pub fn load_group_state(&self, group_id: &str) -> Result<Vec<u8>> {
        let safe_id = Self::sanitize_group_id(group_id);
        let path = self.base_path.join(format!("group_{safe_id}.state"));
        if !path.exists() {
            return Err(KeyStoreError::NotFound(format!("group state: {group_id}")));
        }
        Ok(fs::read(&path)?)
    }

    /// List all stored group IDs
    pub fn list_groups(&self) -> Result<Vec<String>> {
        let mut groups = Vec::new();

        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with("group_") && name.ends_with(".state") {
                let group_id = name
                    .strip_prefix("group_")
                    .and_then(|s| s.strip_suffix(".state"))
                    .map(|s| s.to_string());

                if let Some(id) = group_id {
                    groups.push(id);
                }
            }
        }

        Ok(groups)
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
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for byte in data {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }
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
    fn test_group_key_roundtrip() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        let group_id = "test-group-123";
        let key = b"group-private-key";
        store.store_group_key(group_id, key).unwrap();

        let loaded = store.load_group_key(group_id).unwrap();
        assert_eq!(loaded, key);
    }

    #[test]
    fn test_group_state_roundtrip() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        let group_id = "test-group";
        let state = b"serialized-group-state";
        store.store_group_state(group_id, state).unwrap();

        let loaded = store.load_group_state(group_id).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn test_list_groups() {
        let dir = tempdir().unwrap();
        let store = KeyStore::with_path(dir.path().to_path_buf()).unwrap();

        store.store_group_state("group-a", b"state-a").unwrap();
        store.store_group_state("group-b", b"state-b").unwrap();

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
}
