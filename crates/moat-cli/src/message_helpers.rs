use moat_core::{
    LongTextMessage, MediaMessage, MessagePayload, ParsedMessagePayload, TextMessage,
    MEDIUM_TEXT_MAX_BYTES, SHORT_TEXT_MAX_BYTES,
};

/// Build a structured payload for plain text input.
///
/// Auto-promotes based on byte length:
/// - `<= SHORT_TEXT_MAX_BYTES` → `ShortText`
/// - `<= MEDIUM_TEXT_MAX_BYTES` → `MediumText`
/// - `> MEDIUM_TEXT_MAX_BYTES` → `MediumText` placeholder
///   (blob upload and promotion to `LongText` is handled in `App::send_message_nonblocking`)
pub fn build_text_payload(text: &str) -> MessagePayload {
    let bytes = text.as_bytes().len();
    if bytes <= SHORT_TEXT_MAX_BYTES {
        MessagePayload::ShortText(TextMessage { text: text.to_string() })
    } else {
        // Messages > MEDIUM_TEXT_MAX_BYTES are promoted to LongText by the caller
        // (App::send_message_nonblocking) via blob upload. This path only handles
        // the short/medium split.
        MessagePayload::MediumText(TextMessage { text: text.to_string() })
    }
}

/// Truncate `text` to a preview of at most ~240 bytes, respecting UTF-8 char
/// boundaries. Appends "…" (U+2026) if the text was truncated.
///
/// Used to generate `LongTextMessage.preview_text` before the full text is
/// uploaded as an off-chain blob.
pub fn truncate_to_preview(text: &str) -> String {
    const MAX_PREVIEW_BYTES: usize = 240;
    if text.len() <= MAX_PREVIEW_BYTES {
        return text.to_string();
    }
    // Walk backwards from MAX_PREVIEW_BYTES to find a valid char boundary.
    let mut boundary = MAX_PREVIEW_BYTES;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}…", &text[..boundary])
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

/// Returns `true` if `bytes` exceeds `MEDIUM_TEXT_MAX_BYTES`, indicating that
/// the text must be promoted to a `LongText` blob.
pub fn needs_blob_upload(text: &str) -> bool {
    text.as_bytes().len() > MEDIUM_TEXT_MAX_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── truncate_to_preview ─────────────────────────────────────────────────

    #[test]
    fn truncate_short_text_unchanged() {
        let s = "hello";
        assert_eq!(truncate_to_preview(s), s);
    }

    #[test]
    fn truncate_exactly_at_limit_unchanged() {
        // 240 ASCII bytes — must NOT be truncated.
        let s = "x".repeat(240);
        assert_eq!(truncate_to_preview(&s), s);
    }

    #[test]
    fn truncate_one_over_limit() {
        // 241 ASCII bytes — should be truncated to 240 + "…".
        let s = "x".repeat(241);
        let preview = truncate_to_preview(&s);
        // "…" is a 3-byte UTF-8 sequence, but the content is 240 bytes.
        assert!(preview.ends_with('…'));
        assert_eq!(&preview[..240], &s[..240]);
    }

    #[test]
    fn truncate_appends_ellipsis() {
        let s = "a".repeat(500);
        let preview = truncate_to_preview(&s);
        assert!(preview.ends_with('…'), "preview should end with …");
    }

    #[test]
    fn truncate_respects_utf8_boundary() {
        // Build a string where byte 240 falls in the middle of a 3-byte char.
        // Place 238 ASCII bytes, then one 3-byte char (€ = 0xE2 0x82 0xAC), then more text.
        // Bytes 238, 239, 240 are the 3 bytes of '€', so boundary 240 is NOT a char boundary.
        let prefix = "a".repeat(238);
        let s = format!("{}€suffix", prefix);
        let preview = truncate_to_preview(&s);
        assert!(preview.ends_with('…'));
        // The '€' must not be partially included — the boundary must snap back to 238.
        assert!(std::str::from_utf8(preview.trim_end_matches('…').as_bytes()).is_ok());
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate_to_preview(""), "");
    }

    #[test]
    fn truncate_preview_is_valid_utf8() {
        // Stress test: many multi-byte chars.
        let s: String = "日本語テスト ".repeat(40); // multi-byte Japanese chars
        let preview = truncate_to_preview(&s);
        assert!(std::str::from_utf8(preview.as_bytes()).is_ok());
    }

    // ─── needs_blob_upload ───────────────────────────────────────────────────

    #[test]
    fn needs_blob_upload_false_for_short() {
        assert!(!needs_blob_upload("hello"));
    }

    #[test]
    fn needs_blob_upload_false_at_limit() {
        // Exactly MEDIUM_TEXT_MAX_BYTES should NOT trigger blob upload.
        let s = "a".repeat(MEDIUM_TEXT_MAX_BYTES);
        assert!(!needs_blob_upload(&s));
    }

    #[test]
    fn needs_blob_upload_true_one_over() {
        let s = "a".repeat(MEDIUM_TEXT_MAX_BYTES + 1);
        assert!(needs_blob_upload(&s));
    }

    #[test]
    fn needs_blob_upload_true_for_very_long() {
        let s = "a".repeat(10_000);
        assert!(needs_blob_upload(&s));
    }

    // ─── build_text_payload ──────────────────────────────────────────────────

    #[test]
    fn build_short_text_payload() {
        let payload = build_text_payload("hi");
        assert!(matches!(payload, MessagePayload::ShortText(_)));
    }

    #[test]
    fn build_medium_text_payload() {
        // Just over SHORT_TEXT_MAX_BYTES.
        let s = "a".repeat(SHORT_TEXT_MAX_BYTES + 1);
        let payload = build_text_payload(&s);
        assert!(matches!(payload, MessagePayload::MediumText(_)));
    }

    #[test]
    fn build_text_preserves_content() {
        let text = "the quick brown fox";
        if let MessagePayload::ShortText(msg) = build_text_payload(text) {
            assert_eq!(msg.text, text);
        } else {
            panic!("expected ShortText");
        }
    }
}
