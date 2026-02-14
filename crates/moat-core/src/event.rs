//! Unified Event type for Moat messages
//!
//! All communication (messages, commits, welcomes, checkpoints, reactions) is represented
//! as a single Event type. This hides the type of communication from observers
//! who only see encrypted blobs with opaque tags.

use crate::{
    credential::MoatCredential,
    message::{MessagePayload, ParsedMessagePayload},
};
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
    /// An emoji reaction to a message (toggle semantics)
    Reaction,
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

/// Payload for a reaction event, serialized as JSON inside Event.payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionPayload {
    /// The emoji string (UTF-8, supports multi-codepoint sequences and custom names like ":duck:")
    pub emoji: String,
    /// The message_id of the target message (16 bytes)
    pub target_message_id: Vec<u8>,
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
    /// For Reaction events, this is a JSON-serialized ReactionPayload.
    pub payload: Vec<u8>,

    /// Unique message identifier (16 random bytes, generated at send time).
    /// Used to reference messages for reactions. Absent for legacy events.
    #[serde(default)]
    pub message_id: Option<Vec<u8>>,

    /// SHA-256 hash of the plaintext Event JSON of the previous event
    /// sent by this device in this group. Forms a per-device hash chain.
    /// `None` for the first event from a device.
    #[serde(default)]
    pub prev_event_hash: Option<Vec<u8>>,

    /// 16-byte fingerprint derived from MLS epoch keys via
    /// `export_secret("moat-epoch-fingerprint-v1", 16)`. Recipients
    /// verify it matches their own derived value.
    #[serde(default)]
    pub epoch_fingerprint: Option<Vec<u8>>,

    /// The 16-byte device ID of the sender. Used to key the per-device
    /// hash chain on the recipient side. Set by encrypt_event.
    #[serde(default)]
    pub sender_device_id: Option<Vec<u8>>,
}

impl Event {
    /// Generate a random 16-byte message ID.
    fn random_message_id() -> Vec<u8> {
        use rand::RngCore;
        let mut id = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Create a new message event from raw bytes (legacy plaintext).
    pub fn message(group_id: Vec<u8>, epoch: u64, content: &[u8]) -> Self {
        Self {
            kind: EventKind::Message,
            group_id,
            epoch,
            payload: content.to_vec(),
            message_id: Some(Self::random_message_id()),
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a new structured message event from a [`MessagePayload`].
    pub fn message_with_payload(group_id: Vec<u8>, epoch: u64, payload: &MessagePayload) -> Self {
        let payload_bytes = payload
            .to_bytes()
            .expect("MessagePayload serialization should never fail");
        Self::message(group_id, epoch, &payload_bytes)
    }

    /// Attempt to parse the payload of a message event.
    pub fn parse_message_payload(&self) -> Option<ParsedMessagePayload> {
        if self.kind != EventKind::Message {
            return None;
        }
        Some(ParsedMessagePayload::from_bytes(&self.payload))
    }

    /// Create a new commit event
    pub fn commit(group_id: Vec<u8>, epoch: u64, commit_bytes: Vec<u8>) -> Self {
        Self {
            kind: EventKind::Commit,
            group_id,
            epoch,
            payload: commit_bytes,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a new welcome event
    pub fn welcome(group_id: Vec<u8>, epoch: u64, welcome_bytes: Vec<u8>) -> Self {
        Self {
            kind: EventKind::Welcome,
            group_id,
            epoch,
            payload: welcome_bytes,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a new checkpoint event
    pub fn checkpoint(group_id: Vec<u8>, epoch: u64, state_bytes: Vec<u8>) -> Self {
        Self {
            kind: EventKind::Checkpoint,
            group_id,
            epoch,
            payload: state_bytes,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a new reaction event (toggle semantics: same sender + emoji + target = remove)
    pub fn reaction(group_id: Vec<u8>, epoch: u64, target_message_id: &[u8], emoji: &str) -> Self {
        let reaction_payload = ReactionPayload {
            emoji: emoji.to_string(),
            target_message_id: target_message_id.to_vec(),
        };
        let payload = serde_json::to_vec(&reaction_payload)
            .expect("ReactionPayload serialization should never fail");
        Self {
            kind: EventKind::Reaction,
            group_id,
            epoch,
            payload,
            message_id: Some(Self::random_message_id()),
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Parse the payload as a ReactionPayload (only valid for Reaction events).
    pub fn reaction_payload(&self) -> Option<ReactionPayload> {
        if self.kind != EventKind::Reaction {
            return None;
        }
        serde_json::from_slice(&self.payload).ok()
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

/// Warnings detected during transcript integrity validation.
#[derive(Debug, Clone)]
pub enum TranscriptWarning {
    /// prev_event_hash didn't match expected value (gap or reorder).
    HashChainMismatch {
        group_id: Vec<u8>,
        sender_device_id: Vec<u8>,
        expected: Option<[u8; 32]>,
        received: Option<Vec<u8>>,
    },
    /// epoch_fingerprint didn't match locally derived value (fork).
    EpochFingerprintMismatch {
        group_id: Vec<u8>,
        epoch: u64,
        local: Vec<u8>,
        received: Vec<u8>,
    },
    /// Duplicate event detected (replay).
    ReplayDetected {
        group_id: Vec<u8>,
        sender_device_id: Vec<u8>,
    },
    /// A commit conflict was automatically recovered.
    ConflictRecovered { group_id: Vec<u8> },
}

impl std::fmt::Display for TranscriptWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranscriptWarning::HashChainMismatch {
                sender_device_id, ..
            } => {
                write!(
                    f,
                    "hash chain mismatch from device {:02x?}",
                    &sender_device_id[..4.min(sender_device_id.len())]
                )
            }
            TranscriptWarning::EpochFingerprintMismatch { epoch, .. } => {
                write!(f, "epoch fingerprint mismatch at epoch {}", epoch)
            }
            TranscriptWarning::ReplayDetected {
                sender_device_id, ..
            } => {
                write!(
                    f,
                    "replay detected from device {:02x?}",
                    &sender_device_id[..4.min(sender_device_id.len())]
                )
            }
            TranscriptWarning::ConflictRecovered { .. } => {
                write!(f, "commit conflict automatically recovered")
            }
        }
    }
}

/// Result of decrypting an event, including transcript integrity checks.
#[derive(Debug)]
pub enum DecryptOutcome {
    /// Decryption succeeded with no transcript integrity issues.
    Success(super::DecryptResult),
    /// Decryption succeeded but transcript integrity checks found issues.
    Warning(super::DecryptResult, Vec<TranscriptWarning>),
}

impl DecryptOutcome {
    /// Extract a reference to the DecryptResult regardless of warning state.
    pub fn result(&self) -> &super::DecryptResult {
        match self {
            DecryptOutcome::Success(r) => r,
            DecryptOutcome::Warning(r, _) => r,
        }
    }

    /// Extract the DecryptResult, consuming self.
    pub fn into_result(self) -> super::DecryptResult {
        match self {
            DecryptOutcome::Success(r) => r,
            DecryptOutcome::Warning(r, _) => r,
        }
    }

    /// Get any warnings, or an empty slice if none.
    pub fn warnings(&self) -> &[TranscriptWarning] {
        match self {
            DecryptOutcome::Success(_) => &[],
            DecryptOutcome::Warning(_, w) => w,
        }
    }

    /// Create the appropriate variant based on whether warnings exist.
    pub(crate) fn from_result_and_warnings(
        result: super::DecryptResult,
        warnings: Vec<TranscriptWarning>,
    ) -> Self {
        if warnings.is_empty() {
            DecryptOutcome::Success(result)
        } else {
            DecryptOutcome::Warning(result, warnings)
        }
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
        assert!(recovered.message_id.is_some());
        assert_eq!(recovered.message_id.unwrap().len(), 16);
    }

    #[test]
    fn test_event_kinds() {
        let msg = Event::message(vec![], 0, b"text");
        assert_eq!(msg.kind, EventKind::Message);
        assert!(msg.message_id.is_some());

        let commit = Event::commit(vec![], 0, vec![1, 2, 3]);
        assert_eq!(commit.kind, EventKind::Commit);
        assert!(commit.message_id.is_none());

        let welcome = Event::welcome(vec![], 0, vec![4, 5, 6]);
        assert_eq!(welcome.kind, EventKind::Welcome);
        assert!(welcome.message_id.is_none());

        let checkpoint = Event::checkpoint(vec![], 0, vec![7, 8, 9]);
        assert_eq!(checkpoint.kind, EventKind::Checkpoint);
        assert!(checkpoint.message_id.is_none());

        let reaction = Event::reaction(vec![], 0, &[1; 16], "👍");
        assert_eq!(reaction.kind, EventKind::Reaction);
        assert!(reaction.message_id.is_some());
    }

    #[test]
    fn test_message_ids_are_unique() {
        let msg1 = Event::message(vec![], 0, b"hello");
        let msg2 = Event::message(vec![], 0, b"hello");
        assert_ne!(msg1.message_id, msg2.message_id);
    }

    #[test]
    fn test_reaction_roundtrip() {
        let target_id = vec![0xAB; 16];
        let event = Event::reaction(b"group-1".to_vec(), 3, &target_id, "🎉");

        let bytes = event.to_bytes().unwrap();
        let recovered = Event::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.kind, EventKind::Reaction);
        let rp = recovered.reaction_payload().unwrap();
        assert_eq!(rp.emoji, "🎉");
        assert_eq!(rp.target_message_id, target_id);
    }

    #[test]
    fn test_reaction_payload_on_non_reaction() {
        let msg = Event::message(vec![], 0, b"text");
        assert!(msg.reaction_payload().is_none());
    }

    #[test]
    fn test_structured_message_payload_roundtrip() {
        use crate::message::{MessagePayload, TextMessage};

        let payload = MessagePayload::ShortText(TextMessage {
            text: "Hello preview".to_string(),
        });
        let event = Event::message_with_payload(b"group".to_vec(), 1, &payload);

        let parsed = event.parse_message_payload().unwrap();
        match parsed {
            ParsedMessagePayload::Structured(MessagePayload::ShortText(text)) => {
                assert_eq!(text.text, "Hello preview");
            }
            _ => panic!("expected structured short_text payload"),
        }
    }

    #[test]
    fn test_message_payload_legacy_fallback() {
        let event = Event::message(b"group".to_vec(), 1, b"legacy plaintext");
        let parsed = event.parse_message_payload().unwrap();
        let preview = parsed.preview_text().unwrap();
        match parsed {
            ParsedMessagePayload::LegacyPlaintext(bytes) => {
                assert_eq!(bytes, b"legacy plaintext");
            }
            _ => panic!("expected legacy fallback"),
        }
        assert_eq!(preview, "legacy plaintext");
    }

    #[test]
    fn test_backward_compat_no_message_id() {
        // Simulate a legacy event without message_id or transcript integrity fields
        let json = r#"{"kind":"message","group_id":[1,2,3],"epoch":0,"payload":[104,105]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.kind, EventKind::Message);
        assert!(event.message_id.is_none());
        assert!(event.prev_event_hash.is_none());
        assert!(event.epoch_fingerprint.is_none());
        assert!(event.sender_device_id.is_none());
    }
}
