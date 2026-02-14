use serde::{Deserialize, Serialize};

/// Structured payloads for `event.kind == "message"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessagePayload {
    ShortText(TextMessage),
    MediumText(TextMessage),
    LongText(LongTextMessage),
    Image(MediaMessage),
    Video(VideoMessage),
}

impl MessagePayload {
    /// Serialize the payload to bytes suitable for `Event::message`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Returns a human-friendly inline string that should be rendered immediately.
    pub fn preview_text(&self) -> Option<&str> {
        match self {
            MessagePayload::ShortText(msg) | MessagePayload::MediumText(msg) => Some(&msg.text),
            MessagePayload::LongText(msg) => Some(&msg.preview_text),
            _ => None,
        }
    }

    /// Returns true if the payload references an off-chain blob.
    pub fn uses_external_blob(&self) -> bool {
        matches!(
            self,
            MessagePayload::LongText(_) | MessagePayload::Image(_) | MessagePayload::Video(_)
        )
    }
}

/// Result of attempting to parse a message payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedMessagePayload {
    /// Structured payload parsed via serde.
    Structured(MessagePayload),
    /// Legacy plaintext bytes from pre-structured clients.
    LegacyPlaintext(Vec<u8>),
}

impl ParsedMessagePayload {
    /// Attempt to parse bytes as a structured payload; fall back to legacy bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match serde_json::from_slice::<MessagePayload>(bytes) {
            Ok(payload) => ParsedMessagePayload::Structured(payload),
            Err(_) => ParsedMessagePayload::LegacyPlaintext(bytes.to_vec()),
        }
    }

    /// Returns the structured payload if present.
    pub fn structured(&self) -> Option<&MessagePayload> {
        match self {
            ParsedMessagePayload::Structured(payload) => Some(payload),
            _ => None,
        }
    }

    /// Returns the legacy plaintext bytes if parsing failed.
    pub fn legacy_plaintext(&self) -> Option<&[u8]> {
        match self {
            ParsedMessagePayload::LegacyPlaintext(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Convenience helper for rendering a preview string.
    pub fn preview_text(&self) -> Option<String> {
        match self {
            ParsedMessagePayload::Structured(payload) => {
                payload.preview_text().map(|s| s.to_string())
            }
            ParsedMessagePayload::LegacyPlaintext(bytes) => String::from_utf8(bytes.clone()).ok(),
        }
    }
}

/// Inline text payload shared by `short_text` and `medium_text`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextMessage {
    pub text: String,
}

/// Long-form text payload backed by an external blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTextMessage {
    pub preview_text: String,
    #[serde(default)]
    pub mime: Option<String>,
    pub external: ExternalBlob,
}

/// Image payload previewing an external blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaMessage {
    pub preview_thumbhash: Vec<u8>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub mime: Option<String>,
    pub external: ExternalBlob,
}

/// Video payload previewing an external blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoMessage {
    pub preview_thumbhash: Vec<u8>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub mime: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u32>,
    pub external: ExternalBlob,
}

/// Hash/authentication bundle for an external blob referenced by a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalBlob {
    pub ciphertext_hash: Vec<u8>,
    pub ciphertext_size: u64,
    pub content_hash: Vec<u8>,
    pub uri: String,
    pub key: Vec<u8>,
}
