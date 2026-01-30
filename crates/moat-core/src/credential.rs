//! Moat credential format for MLS
//!
//! MLS credentials carry identity information for group members. Moat uses a
//! structured credential format that includes both the user's DID and their
//! device name, enabling multi-device support where each device is a separate
//! MLS member but can be grouped by DID for display.

use serde::{Deserialize, Serialize};

/// A structured credential for Moat MLS operations.
///
/// Contains the user's decentralized identifier (DID) and a human-readable
/// device name. The DID identifies the user across all their devices, while
/// the device name distinguishes between devices owned by the same user.
///
/// # Wire Format
///
/// Serialized as JSON for embedding in MLS BasicCredential:
/// ```json
/// {"did":"did:plc:abc123","device_name":"My iPhone"}
/// ```
///
/// # Example
///
/// ```
/// use moat_core::MoatCredential;
///
/// let credential = MoatCredential::new("did:plc:abc123", "Work Laptop");
/// assert_eq!(credential.did(), "did:plc:abc123");
/// assert_eq!(credential.device_name(), "Work Laptop");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoatCredential {
    /// The user's decentralized identifier (e.g., "did:plc:abc123")
    did: String,
    /// Human-readable device name (e.g., "My iPhone", "Work Laptop")
    device_name: String,
}

impl MoatCredential {
    /// Create a new credential with the given DID and device name.
    ///
    /// # Arguments
    ///
    /// * `did` - The user's decentralized identifier
    /// * `device_name` - A human-readable name for this device
    pub fn new(did: impl Into<String>, device_name: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            device_name: device_name.into(),
        }
    }

    /// Get the user's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Get the device name.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Serialize this credential to bytes for embedding in MLS BasicCredential.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize a credential from bytes (extracted from MLS BasicCredential).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Try to parse a credential from bytes, returning None if parsing fails.
    ///
    /// This is useful when processing credentials that might be in the old
    /// format (raw identity bytes) or the new structured format.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_creation() {
        let cred = MoatCredential::new("did:plc:abc123", "My Phone");
        assert_eq!(cred.did(), "did:plc:abc123");
        assert_eq!(cred.device_name(), "My Phone");
    }

    #[test]
    fn test_credential_roundtrip() {
        let cred = MoatCredential::new("did:plc:xyz789", "Work Laptop");
        let bytes = cred.to_bytes().unwrap();
        let recovered = MoatCredential::from_bytes(&bytes).unwrap();
        assert_eq!(cred, recovered);
    }

    #[test]
    fn test_credential_json_format() {
        let cred = MoatCredential::new("did:plc:test", "Device");
        let bytes = cred.to_bytes().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["did"], "did:plc:test");
        assert_eq!(json["device_name"], "Device");
    }

    #[test]
    fn test_try_from_bytes_success() {
        let cred = MoatCredential::new("did:plc:foo", "Bar");
        let bytes = cred.to_bytes().unwrap();
        let parsed = MoatCredential::try_from_bytes(&bytes);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap(), cred);
    }

    #[test]
    fn test_try_from_bytes_failure() {
        // Old-style raw identity bytes won't parse
        let raw_identity = b"alice@example.com";
        let parsed = MoatCredential::try_from_bytes(raw_identity);
        assert!(parsed.is_none());
    }
}
