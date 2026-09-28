//! Unified Event type for Moat messages
//!
//! All communication (messages, commits, welcomes, checkpoints, reactions) is represented
//! as a single Event type. This hides the type of communication from observers
//! who only see encrypted blobs with opaque tags.

use crate::{
    credential::MoatCredential,
    message::{MessageBodyKind, MessagePayload, ParsedMessagePayload},
};
use serde::{de::Deserializer, Deserialize, Serialize, Serializer};
use serde_with::serde_as;

/// Top-level event discriminator (domain + variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    Control(ControlKind),
    Message(MessageKind),
    Modifier(ModifierKind),
    /// Sync protocol message sent over the device ring, transmitted as binary
    /// frames on the pair WebSocket. The payload is a padded JSON `SyncMsg`.
    SyncApp,
    /// Steady-state same-user coordination message addressed to a specific
    /// sibling device. The payload is a JSON-encoded [`crate::CoordMsg`]
    /// (`KpBatch` / `KpRequest` / `UserConvWelcome`); the sender's device id
    /// travels in `Event.sender_device_id`. Delivered as a stealth-encrypted
    /// `social.moat.event` to the sibling's `scan_pubkey` — epoch-free and
    /// order-insensitive. `group_id` and `epoch` are not meaningful
    /// (empty / 0).
    SiblingMsg,
    /// Application message on the device ring, MLS-encrypted and published
    /// to the PDS under a ring tag. The payload is a JSON-encoded
    /// [`crate::RingMsg`]. Unlike [`EventKind::SiblingMsg`] this lane is
    /// authenticated (the sender's identity comes from its MLS leaf
    /// credential) and reaches every sibling from one publish, at the cost
    /// of being epoch-bound like any MLS application message.
    RingMsg,
    /// Legacy or unknown domain.
    Unknown(String),
}

/// Control-plane events (MLS state mutations and coordination).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlKind {
    Commit,
    Welcome,
    Checkpoint,
    Unknown(String),
}

/// User-visible message variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageKind {
    ShortText,
    MediumText,
    LongText,
    Image,
    /// Legacy `kind: "message"` events.
    Legacy,
    Unknown(String),
}

/// Message modifiers (reactions, replies, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModifierKind {
    Reaction,
    Unknown(String),
}

impl EventKind {
    fn as_str(&self) -> String {
        match self {
            EventKind::Control(kind) => kind.as_str_with_domain("control"),
            EventKind::Message(kind) => kind.as_str_with_domain("message"),
            EventKind::Modifier(kind) => kind.as_str_with_domain("modifier"),
            EventKind::SyncApp => "sync.app".to_string(),
            EventKind::SiblingMsg => "sibling.msg".to_string(),
            EventKind::RingMsg => "ring.msg".to_string(),
            EventKind::Unknown(s) => s.clone(),
        }
    }
}

/// Information about the sender of a message.
///
/// Extracted from the MLS credential of the message sender during decryption.
/// This provides both user identity (DID) and device information for multi-device support.
///
/// Note: This is receiver-side metadata extracted from MLS, not part of the encrypted Event.
/// `Event.sender_device_id` carries the *same* device id encoded inside the
/// encrypted payload, used at decrypt time as the per-device hash-chain key;
/// `decrypt_event` cross-checks the two and surfaces a
/// `TranscriptWarning::SenderIdentityMismatch` on divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderInfo {
    /// The sender's decentralized identifier
    pub did: String,
    /// The name of the device that sent the message (format: "did:plc:xxx/Device Name")
    pub device_name: String,
    /// The sender's stable 16-byte device id, taken from the MLS credential.
    /// Matches `Event.sender_device_id` (which is the in-plaintext mirror used
    /// for hash-chain keying); divergence between the two is a transcript
    /// warning.
    pub device_id: [u8; 16],
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
            device_id: *credential.device_id(),
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
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionPayload {
    /// The emoji string (UTF-8, supports multi-codepoint sequences and custom names like ":duck:")
    pub emoji: String,
    /// The message_id of the target message (16 bytes)
    #[serde_as(as = "serde_with::base64::Base64")]
    pub target_message_id: Vec<u8>,
}

/// An event to be encrypted and published
///
/// This is the plaintext structure that gets encrypted before publishing.
/// The encrypted form only exposes a rotating tag and ciphertext.
///
/// Note: Sender identity is NOT stored here. It's extracted from MLS credentials
/// during decryption and returned separately in DecryptResult.sender.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// The type of event
    pub kind: EventKind,

    /// Internal stable group identifier (not exposed in plaintext)
    #[serde_as(as = "serde_with::base64::Base64")]
    pub group_id: Vec<u8>,

    /// The MLS epoch this event was created in
    pub epoch: u64,

    /// The actual payload (message text, commit bytes, welcome bytes, etc.)
    /// For Reaction events, this is a JSON-serialized ReactionPayload.
    #[serde_as(as = "serde_with::base64::Base64")]
    pub payload: Vec<u8>,

    /// Unique message identifier (16 random bytes, generated at send time).
    /// Used to reference messages for reactions. Absent for legacy events.
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
    #[serde(default)]
    pub message_id: Option<Vec<u8>>,

    /// SHA-256 hash of the plaintext Event JSON of the previous event
    /// sent by this device in this group. Forms a per-device hash chain.
    /// `None` for the first event from a device.
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
    #[serde(default)]
    pub prev_event_hash: Option<Vec<u8>>,

    /// 16-byte fingerprint derived from MLS epoch keys via
    /// `export_secret("moat-epoch-fingerprint-v1", 16)`. Recipients
    /// verify it matches their own derived value.
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
    #[serde(default)]
    pub epoch_fingerprint: Option<Vec<u8>>,

    /// The 16-byte device ID of the sender, embedded in the encrypted
    /// payload at encrypt time.  Used at decrypt time as the key into
    /// the per-device hash chain (`prev_event_hash` indexing) — i.e. it
    /// is a wire-level transcript-integrity field, *not* the canonical
    /// receiver-side sender identity.
    ///
    /// The same device id is also extracted from the MLS credential at
    /// decrypt time and exposed on [`crate::DecryptResult::sender`]
    /// (see [`SenderInfo::device_id`]).  `decrypt_event` cross-checks the
    /// two; if they disagree the receiver gets a
    /// [`TranscriptWarning::SenderIdentityMismatch`].  Removing this
    /// field would conflate the wire/transcript concern with the
    /// receiver-facing API and would also change `Event` JSON, breaking
    /// the chain digest.
    #[serde_as(as = "Option<serde_with::base64::Base64>")]
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

    /// Create a new structured message event.
    pub fn message(group_id: Vec<u8>, epoch: u64, payload: &MessagePayload) -> Self {
        let payload_bytes = payload
            .to_bytes()
            .expect("MessagePayload serialization should never fail");
        let message_kind = MessageKind::from(payload.kind());
        Self {
            kind: EventKind::Message(message_kind),
            group_id,
            epoch,
            payload: payload_bytes,
            message_id: Some(Self::random_message_id()),
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a message event from serialized payload bytes (used by FFI/legacy callers).
    pub fn message_from_bytes(group_id: Vec<u8>, epoch: u64, payload: &[u8]) -> Self {
        let message_kind = serde_json::from_slice::<MessagePayload>(payload)
            .map(|p| MessageKind::from(p.kind()))
            .unwrap_or(MessageKind::Legacy);
        Self {
            kind: EventKind::Message(message_kind),
            group_id,
            epoch,
            payload: payload.to_vec(),
            message_id: Some(Self::random_message_id()),
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a legacy message event from raw bytes.
    pub fn legacy_message(group_id: Vec<u8>, epoch: u64, content: &[u8]) -> Self {
        Self {
            kind: EventKind::Message(MessageKind::Legacy),
            group_id,
            epoch,
            payload: content.to_vec(),
            message_id: Some(Self::random_message_id()),
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Attempt to parse the payload of a message event.
    pub fn parse_message_payload(&self) -> Option<ParsedMessagePayload> {
        match &self.kind {
            EventKind::Message(_) => Some(ParsedMessagePayload::from_bytes(&self.payload)),
            _ => None,
        }
    }

    /// Create a new commit event
    pub fn commit(group_id: Vec<u8>, epoch: u64, commit_bytes: Vec<u8>) -> Self {
        Self {
            kind: EventKind::Control(ControlKind::Commit),
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
            kind: EventKind::Control(ControlKind::Welcome),
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
            kind: EventKind::Control(ControlKind::Checkpoint),
            group_id,
            epoch,
            payload: state_bytes,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a sync-app message event for the device ring, transmitted on the pair WS.
    pub fn sync_app(group_id: Vec<u8>, epoch: u64, payload: Vec<u8>) -> Self {
        Self {
            kind: EventKind::SyncApp,
            group_id,
            epoch,
            payload,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a device-ring application event carrying a JSON-encoded
    /// [`crate::RingMsg`]. MLS-framed like any group message, so `group_id`
    /// is the ring and `epoch` the ring's current epoch; the sender is
    /// authenticated by MLS rather than declared in the payload.
    pub fn ring_msg(group_id: Vec<u8>, epoch: u64, ring_msg_json: Vec<u8>) -> Self {
        Self {
            kind: EventKind::RingMsg,
            group_id,
            epoch,
            payload: ring_msg_json,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }

    /// Create a sibling coordination event carrying a JSON-encoded `CoordMsg`
    /// destined for a specific sibling via the stealth lane. `group_id` and
    /// `epoch` are unused (empty / `0`); the sender identifies itself via
    /// `sender_device_id` (unauthenticated at this layer — receivers verify
    /// KP payloads against ring leaf credentials).
    pub fn sibling_msg(sender_device_id: Vec<u8>, coord_msg_json: Vec<u8>) -> Self {
        Self {
            kind: EventKind::SiblingMsg,
            group_id: Vec::new(),
            epoch: 0,
            payload: coord_msg_json,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: Some(sender_device_id),
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
            kind: EventKind::Modifier(ModifierKind::Reaction),
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
        match &self.kind {
            EventKind::Modifier(ModifierKind::Reaction) => {
                serde_json::from_slice(&self.payload).ok()
            }
            _ => None,
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
    /// The `device_id` in the encrypted payload (`Event.sender_device_id`)
    /// disagreed with the MLS credential's `device_id`.  Both should be
    /// the same byte-string; a mismatch means the sender lied in the
    /// plaintext or an MLS-layer key substitution slipped past the
    /// authenticator.  Either case is a security-relevant signal.
    SenderIdentityMismatch {
        group_id: Vec<u8>,
        /// What the encrypted payload claimed.
        payload_device_id: Vec<u8>,
        /// What the MLS credential said.
        credential_device_id: Vec<u8>,
    },
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
            TranscriptWarning::SenderIdentityMismatch {
                payload_device_id,
                credential_device_id,
                ..
            } => {
                write!(
                    f,
                    "sender identity mismatch: payload={:02x?} credential={:02x?}",
                    &payload_device_id[..4.min(payload_device_id.len())],
                    &credential_device_id[..4.min(credential_device_id.len())],
                )
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
impl Serialize for EventKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        if let Some((domain, variant)) = raw.split_once('.') {
            let kind = match domain {
                "control" => EventKind::Control(ControlKind::from_variant(variant)),
                "message" => EventKind::Message(MessageKind::from_variant(variant)),
                "modifier" => EventKind::Modifier(ModifierKind::from_variant(variant)),
                "sync" => EventKind::SyncApp,
                "sibling" if variant == "msg" => EventKind::SiblingMsg,
                "ring" if variant == "msg" => EventKind::RingMsg,
                _ => EventKind::Unknown(raw),
            };
            Ok(kind)
        } else {
            // Legacy single-token kinds.
            let legacy = match raw.as_str() {
                "message" => EventKind::Message(MessageKind::Legacy),
                "commit" => EventKind::Control(ControlKind::Commit),
                "welcome" => EventKind::Control(ControlKind::Welcome),
                "checkpoint" => EventKind::Control(ControlKind::Checkpoint),
                "reaction" => EventKind::Modifier(ModifierKind::Reaction),
                _ => EventKind::Unknown(raw),
            };
            Ok(legacy)
        }
    }
}

impl ControlKind {
    fn as_str_with_domain(&self, domain: &str) -> String {
        match self {
            ControlKind::Commit => format!("{domain}.commit"),
            ControlKind::Welcome => format!("{domain}.welcome"),
            ControlKind::Checkpoint => format!("{domain}.checkpoint"),
            ControlKind::Unknown(v) => format!("{domain}.{}", v),
        }
    }

    fn from_variant(variant: &str) -> Self {
        match variant {
            "commit" => ControlKind::Commit,
            "welcome" => ControlKind::Welcome,
            "checkpoint" => ControlKind::Checkpoint,
            other => ControlKind::Unknown(other.to_string()),
        }
    }
}

impl MessageKind {
    fn as_str_with_domain(&self, domain: &str) -> String {
        match self {
            MessageKind::ShortText => format!("{domain}.short_text"),
            MessageKind::MediumText => format!("{domain}.medium_text"),
            MessageKind::LongText => format!("{domain}.long_text"),
            MessageKind::Image => format!("{domain}.image"),
            MessageKind::Legacy => "message".to_string(),
            MessageKind::Unknown(v) => format!("{domain}.{}", v),
        }
    }

    fn from_variant(variant: &str) -> Self {
        match variant {
            "short_text" => MessageKind::ShortText,
            "medium_text" => MessageKind::MediumText,
            "long_text" => MessageKind::LongText,
            "image" => MessageKind::Image,
            other => MessageKind::Unknown(other.to_string()),
        }
    }
}

impl ModifierKind {
    fn as_str_with_domain(&self, domain: &str) -> String {
        match self {
            ModifierKind::Reaction => format!("{domain}.reaction"),
            ModifierKind::Unknown(v) => format!("{domain}.{}", v),
        }
    }

    fn from_variant(variant: &str) -> Self {
        match variant {
            "reaction" => ModifierKind::Reaction,
            other => ModifierKind::Unknown(other.to_string()),
        }
    }
}

impl From<MessageBodyKind> for MessageKind {
    fn from(kind: MessageBodyKind) -> Self {
        match kind {
            MessageBodyKind::ShortText => MessageKind::ShortText,
            MessageBodyKind::MediumText => MessageKind::MediumText,
            MessageBodyKind::LongText => MessageKind::LongText,
            MessageBodyKind::Image => MessageKind::Image,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{MessagePayload, TextMessage};

    #[test]
    fn test_event_roundtrip() {
        let payload = MessagePayload::ShortText(TextMessage {
            text: "Hello, world!".to_string(),
        });
        let event = Event::message(b"group-123".to_vec(), 5, &payload);

        let bytes = event.to_bytes().unwrap();
        let recovered = Event::from_bytes(&bytes).unwrap();

        assert!(matches!(recovered.kind, EventKind::Message(_)));
        assert_eq!(recovered.group_id, b"group-123");
        assert_eq!(recovered.epoch, 5);
        assert_eq!(
            recovered.parse_message_payload().unwrap().preview_text(),
            Some("Hello, world!".to_string())
        );
        assert!(recovered.message_id.is_some());
        assert_eq!(recovered.message_id.unwrap().len(), 16);
    }

    #[test]
    fn test_event_kinds() {
        let msg = Event::message(
            vec![],
            0,
            &MessagePayload::ShortText(TextMessage {
                text: "text".to_string(),
            }),
        );
        assert!(matches!(msg.kind, EventKind::Message(_)));
        assert!(msg.message_id.is_some());

        let commit = Event::commit(vec![], 0, vec![1, 2, 3]);
        assert!(matches!(
            commit.kind,
            EventKind::Control(ControlKind::Commit)
        ));
        assert!(commit.message_id.is_none());

        let welcome = Event::welcome(vec![], 0, vec![4, 5, 6]);
        assert!(matches!(
            welcome.kind,
            EventKind::Control(ControlKind::Welcome)
        ));
        assert!(welcome.message_id.is_none());

        let checkpoint = Event::checkpoint(vec![], 0, vec![7, 8, 9]);
        assert!(matches!(
            checkpoint.kind,
            EventKind::Control(ControlKind::Checkpoint)
        ));
        assert!(checkpoint.message_id.is_none());

        let reaction = Event::reaction(vec![], 0, &[1; 16], "👍");
        assert!(matches!(
            reaction.kind,
            EventKind::Modifier(ModifierKind::Reaction)
        ));
        assert!(reaction.message_id.is_some());
    }

    #[test]
    fn test_sibling_msg_roundtrip() {
        let sender = vec![7u8; 16];
        let payload = br#"{"type":"kp_request","owner_device_id":"BwcHBwcHBwcHBwcHBwcHBw==","count":4}"#.to_vec();
        let event = Event::sibling_msg(sender.clone(), payload.clone());

        let bytes = event.to_bytes().unwrap();
        let recovered = Event::from_bytes(&bytes).unwrap();

        assert!(matches!(recovered.kind, EventKind::SiblingMsg));
        assert_eq!(recovered.payload, payload);
        assert_eq!(recovered.sender_device_id, Some(sender));
        assert!(recovered.group_id.is_empty());
        assert_eq!(recovered.epoch, 0);

        // Wire tag is `sibling.msg`.
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], serde_json::Value::String("sibling.msg".to_string()));
    }

    #[test]
    fn test_message_ids_are_unique() {
        let payload = MessagePayload::ShortText(TextMessage {
            text: "hello".to_string(),
        });
        let msg1 = Event::message(vec![], 0, &payload);
        let msg2 = Event::message(vec![], 0, &payload);
        assert_ne!(msg1.message_id, msg2.message_id);
    }

    #[test]
    fn test_reaction_roundtrip() {
        let target_id = vec![0xAB; 16];
        let event = Event::reaction(b"group-1".to_vec(), 3, &target_id, "🎉");

        let bytes = event.to_bytes().unwrap();
        let recovered = Event::from_bytes(&bytes).unwrap();

        assert!(matches!(
            recovered.kind,
            EventKind::Modifier(ModifierKind::Reaction)
        ));
        let rp = recovered.reaction_payload().unwrap();
        assert_eq!(rp.emoji, "🎉");
        assert_eq!(rp.target_message_id, target_id);
    }

    #[test]
    fn test_reaction_payload_on_non_reaction() {
        let msg = Event::legacy_message(vec![], 0, b"text");
        assert!(msg.reaction_payload().is_none());
    }

    #[test]
    fn test_structured_message_payload_roundtrip() {
        let payload = MessagePayload::ShortText(TextMessage {
            text: "Hello preview".to_string(),
        });
        let event = Event::message(b"group".to_vec(), 1, &payload);

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
        let event = Event::legacy_message(b"group".to_vec(), 1, b"legacy plaintext");
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
        // group_id=[1,2,3] -> base64 "AQID", payload=[104,105] -> base64 "aGk="
        let json = r#"{"kind":"message","group_id":"AQID","epoch":0,"payload":"aGk="}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(matches!(event.kind, EventKind::Message(_)));
        assert_eq!(event.group_id, vec![1, 2, 3]);
        assert_eq!(event.payload, vec![104, 105]);
        assert!(event.message_id.is_none());
        assert!(event.prev_event_hash.is_none());
        assert!(event.epoch_fingerprint.is_none());
        assert!(event.sender_device_id.is_none());
    }
}
