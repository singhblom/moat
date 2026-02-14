use moat_core::{
    LongTextMessage, MediaMessage, MessagePayload, ParsedMessagePayload, TextMessage, VideoMessage,
};

const SHORT_TEXT_MAX_BYTES: usize = 240;

/// Build a structured payload for plain text input.
pub fn build_text_payload(text: &str) -> MessagePayload {
    let owned = text.to_string();
    if owned.as_bytes().len() <= SHORT_TEXT_MAX_BYTES {
        MessagePayload::ShortText(TextMessage { text: owned })
    } else {
        MessagePayload::MediumText(TextMessage { text: owned })
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
        MessagePayload::Video(msg) => render_video(msg),
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

fn render_video(msg: &VideoMessage) -> String {
    let mut parts = vec!["[video".to_string()];
    if let Some(mime) = &msg.mime {
        parts.push(format!(" {}", mime));
    }
    if let Some(dim) = format_dimensions(msg.width, msg.height) {
        parts.push(format!(" {}", dim));
    }
    if let Some(duration_ms) = msg.duration_ms {
        let seconds = (duration_ms as f32) / 1000.0;
        parts.push(format!(" {:.1}s", seconds));
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
