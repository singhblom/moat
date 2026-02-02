//! Unified Event type for Moat messages
//!
//! All communication (messages, commits, welcomes, checkpoints) is represented
//! as a single Event type. This hides the type of communication from observers
//! who only see encrypted blobs with opaque tags.

use crate::credential::MoatCredential;
use serde::{Deserialize, Serialize};

/// The kind of event being sent
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A regular chat message
    Message,
    /// An MLS commit (membership change, key update)
    Commit,
    /// An MLS welcome message for a new member
    Welcome,
    /// A group state checkpoint for faster sync
    Checkpoint,
}

/// Information about the sender of a message.
///
/// Extracted from the MLS credential of the message sender during decryption.
/// This provides both user identity (DID) and device information for multi-device support.
///
/// Note: This is receiver-side metadata extracted from MLS, not part of the encrypted Event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderInfo {
    /// The sender's decentralized identifier
    pub did: String,
    /// The name of the device that sent the message (format: "did:plc:xxx/Device Name")
    pub device_name: String,
    /// The MLS leaf index of the sender (for internal use)
    #[serde(default)]
    pub leaf_index: Option<u32>,
}

impl SenderInfo {
    /// Create sender info from a MoatCredential
    pub fn from_credential(credential: &MoatCredential) -> Self {
        Self {
            did: credential.did().to_string(),
            device_name: credential.device_name().to_string(),
            leaf_index: None,
        }
    }

    /// Create sender info with a leaf index
    pub fn with_leaf_index(mut self, index: u32) -> Self {
        self.leaf_index = Some(index);
        self
    }
}

/// An event to be encrypted and published
///
/// This is the plaintext structure that gets encrypted before publishing.
/// The encrypted form only exposes a rotating tag and ciphertext.
///
/// Note: Sender identity is NOT stored here. It's extracted from MLS credentials
/// during decryption and returned separately in DecryptResult.sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// The type of event
    pub kind: EventKind,

    /// Internal stable group identifier (not exposed in plaintext)
    pub group_id: Vec<u8>,

    /// The MLS epoch this event was created in
    pub epoch: u64,

    /// The actual payload (message text, commit bytes, welcome bytes, etc.)
    pub payload: Vec<u8>,
}

impl Event {
    /// Create a new message event
    pub fn message(group_id: Vec<u8>, epoch: u64, content: &[u8]) -> Self {
        Self {
            kind: EventKind::Message,
            group_id,
            epoch,
            payload: content.to_vec(),
        }
    }

    /// Create a new commit event
    pub fn commit(group_id: Vec<u8>, epoch: u64, commit_bytes: Vec<u8>) -> Self {
        Self {
            kind: EventKind::Commit,
            group_id,
            epoch,
            payload: commit_bytes,
        }
    }

    /// Create a new welcome event
    pub fn welcome(group_id: Vec<u8>, epoch: u64, welcome_bytes: Vec<u8>) -> Self {
        Self {
            kind: EventKind::Welcome,
            group_id,
            epoch,
            payload: welcome_bytes,
        }
    }

    /// Create a new checkpoint event
    pub fn checkpoint(group_id: Vec<u8>, epoch: u64, state_bytes: Vec<u8>) -> Self {
        Self {
            kind: EventKind::Checkpoint,
            group_id,
            epoch,
            payload: state_bytes,
        }
    }

    /// Serialize this event to bytes for encryption
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize an event from bytes after decryption
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_roundtrip() {
        let event = Event::message(b"group-123".to_vec(), 5, b"Hello, world!");

        let bytes = event.to_bytes().unwrap();
        let recovered = Event::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.kind, EventKind::Message);
        assert_eq!(recovered.group_id, b"group-123");
        assert_eq!(recovered.epoch, 5);
        assert_eq!(recovered.payload, b"Hello, world!");
    }

    #[test]
    fn test_event_kinds() {
        let msg = Event::message(vec![], 0, b"text");
        assert_eq!(msg.kind, EventKind::Message);

        let commit = Event::commit(vec![], 0, vec![1, 2, 3]);
        assert_eq!(commit.kind, EventKind::Commit);

        let welcome = Event::welcome(vec![], 0, vec![4, 5, 6]);
        assert_eq!(welcome.kind, EventKind::Welcome);

        let checkpoint = Event::checkpoint(vec![], 0, vec![7, 8, 9]);
        assert_eq!(checkpoint.kind, EventKind::Checkpoint);
    }
}
