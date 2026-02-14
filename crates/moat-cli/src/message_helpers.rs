use moat_core::{
    LongTextMessage, MediaMessage, MessagePayload, ParsedMessagePayload, TextMessage,
    MEDIUM_TEXT_MAX_BYTES, SHORT_TEXT_MAX_BYTES,
};

/// Build a structured payload for plain text input.
///
/// Auto-promotes based on byte length:
/// - `<= SHORT_TEXT_MAX_BYTES` → `ShortText`
/// - `<= MEDIUM_TEXT_MAX_BYTES` → `MediumText`
/// - `> MEDIUM_TEXT_MAX_BYTES` → `MediumText` (TODO: promote to `LongText` when blob upload is available)
pub fn build_text_payload(text: &str) -> MessagePayload {
    let bytes = text.as_bytes().len();
    if bytes <= SHORT_TEXT_MAX_BYTES {
        MessagePayload::ShortText(TextMessage { text: text.to_string() })
    } else {
        // TODO: when blob upload is available, promote to LongText
        // for text exceeding MEDIUM_TEXT_MAX_BYTES
        MessagePayload::MediumText(TextMessage { text: text.to_string() })
    }
}

/// Render a parsed payload into a human-readable string for the CLI.
pub fn render_message_preview(parsed: &ParsedMessagePayload) -> String {
    match parsed {
        ParsedMessagePayload::Structured(payload) => render_structured_payload(payload),
        ParsedMessagePayload::LegacyPlaintext(bytes) => String::from_utf8_lossy(bytes).to_string(),
    }
}

fn render_structured_payload(payload: &MessagePayload) -> String {
    match payload {
        MessagePayload::ShortText(msg) | MessagePayload::MediumText(msg) => msg.text.clone(),
        MessagePayload::LongText(msg) => render_long_text(msg),
        MessagePayload::Image(msg) => render_image(msg),
    }
}

fn render_long_text(msg: &LongTextMessage) -> String {
    let mut text = msg.preview_text.clone();
    text.push_str(" [long text");
    if let Some(mime) = &msg.mime {
        text.push(' ');
        text.push_str(mime);
    }
    text.push(']');
    text
}

fn render_image(msg: &MediaMessage) -> String {
    let mut parts = vec!["[image".to_string()];
    if let Some(mime) = &msg.mime {
        parts.push(format!(" {}", mime));
    }
    if let Some(dim) = format_dimensions(msg.width, msg.height) {
        parts.push(format!(" {}", dim));
    }
    parts.push("]".to_string());
    parts.concat()
}

fn format_dimensions(width: Option<u32>, height: Option<u32>) -> Option<String> {
    match (width, height) {
        (Some(w), Some(h)) => Some(format!("{}x{}", w, h)),
        _ => None,
    }
}
