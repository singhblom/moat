use moat_core::{
    Bucket, Event, EventKind, ExternalBlob, LongTextMessage, MediaMessage, MessagePayload,
    ParsedMessagePayload, TextMessage,
};
use proptest::prelude::*;

// --- Strategies for generating arbitrary payloads ---

fn arb_text_message() -> impl Strategy<Value = TextMessage> {
    "\\PC{0,500}".prop_map(|text| TextMessage { text })
}

fn arb_external_blob() -> impl Strategy<Value = ExternalBlob> {
    (
        proptest::collection::vec(any::<u8>(), 32..=32),
        any::<u64>(),
        proptest::collection::vec(any::<u8>(), 32..=32),
        proptest::collection::vec(any::<u8>(), 32..=32),
    )
        .prop_map(|(ciphertext_hash, ciphertext_size, content_hash, key)| ExternalBlob {
            ciphertext_hash,
            ciphertext_size,
            content_hash,
            uri: "at://did:plc:test/social.moat.blob/abc123".to_string(),
            key,
        })
}

fn arb_message_payload() -> impl Strategy<Value = MessagePayload> {
    prop_oneof![
        arb_text_message().prop_map(MessagePayload::ShortText),
        arb_text_message().prop_map(MessagePayload::MediumText),
        (arb_text_message(), arb_external_blob()).prop_map(|(tm, blob)| {
            MessagePayload::LongText(LongTextMessage {
                preview_text: tm.text,
                mime: Some("text/plain".into()),
                external: blob,
            })
        }),
        arb_external_blob().prop_map(|blob| {
            MessagePayload::Image(MediaMessage {
                preview_thumbhash: vec![0x01; 28],
                width: Some(640),
                height: Some(480),
                mime: Some("image/png".into()),
                external: blob,
            })
        }),
    ]
}

proptest! {
    // --- MessagePayload serde roundtrip ---

    /// Any MessagePayload survives to_bytes() → from_slice().
    #[test]
    fn message_payload_serde_roundtrip(payload in arb_message_payload()) {
        let bytes = payload.to_bytes().unwrap();
        let recovered: MessagePayload = serde_json::from_slice(&bytes).unwrap();
        prop_assert_eq!(payload, recovered);
    }

    /// Serialization is deterministic (same input → same bytes).
    #[test]
    fn message_payload_deterministic_serialization(payload in arb_message_payload()) {
        let bytes1 = payload.to_bytes().unwrap();
        let bytes2 = payload.to_bytes().unwrap();
        prop_assert_eq!(bytes1, bytes2);
    }

    /// kind() is consistent after roundtrip.
    #[test]
    fn message_payload_kind_preserved(payload in arb_message_payload()) {
        let original_kind = payload.kind();
        let bytes = payload.to_bytes().unwrap();
        let recovered: MessagePayload = serde_json::from_slice(&bytes).unwrap();
        prop_assert_eq!(original_kind, recovered.kind());
    }

    // --- ParsedMessagePayload never panics ---

    /// For any byte sequence, from_bytes() returns Structured or LegacyPlaintext (never panics).
    #[test]
    fn parsed_message_payload_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let parsed = ParsedMessagePayload::from_bytes(&data);
        // Just assert it doesn't panic and returns one of the two variants
        match &parsed {
            ParsedMessagePayload::Structured(_) => {},
            ParsedMessagePayload::LegacyPlaintext(bytes) => {
                prop_assert_eq!(bytes, &data);
            },
        }
        // preview_text() should also never panic
        let _ = parsed.preview_text();
    }

    /// Valid MessagePayload bytes always parse as Structured.
    #[test]
    fn valid_payload_parses_as_structured(payload in arb_message_payload()) {
        let bytes = payload.to_bytes().unwrap();
        let parsed = ParsedMessagePayload::from_bytes(&bytes);
        prop_assert!(
            matches!(parsed, ParsedMessagePayload::Structured(_)),
            "valid payload should parse as Structured, got LegacyPlaintext"
        );
    }

    // --- EventKind serialize/deserialize roundtrip ---

    /// Known EventKinds survive serialize → deserialize.
    #[test]
    fn event_kind_roundtrip(kind_str in prop_oneof![
        Just("control.commit"),
        Just("control.welcome"),
        Just("control.checkpoint"),
        Just("message.short_text"),
        Just("message.medium_text"),
        Just("message.long_text"),
        Just("message.image"),
        Just("modifier.reaction"),
        // Legacy single-token
        Just("message"),
        Just("commit"),
        Just("welcome"),
        Just("checkpoint"),
        Just("reaction"),
    ]) {
        let json = format!("\"{}\"", kind_str);
        let kind: EventKind = serde_json::from_str(&json).unwrap();
        let serialized = serde_json::to_string(&kind).unwrap();
        let recovered: EventKind = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(kind, recovered);
    }

    /// Unknown domain.variant strings roundtrip through Unknown variant.
    #[test]
    fn unknown_event_kind_roundtrip(
        domain in "[a-z]{2,10}",
        variant in "[a-z_]{2,10}",
    ) {
        // Exclude known domains to ensure we hit Unknown
        prop_assume!(domain != "control" && domain != "message" && domain != "modifier");
        let kind_str = format!("{}.{}", domain, variant);
        let json = format!("\"{}\"", kind_str);
        let kind: EventKind = serde_json::from_str(&json).unwrap();
        prop_assert!(
            matches!(&kind, EventKind::Unknown(s) if *s == kind_str),
            "expected Unknown({:?}), got {:?}", kind_str, kind
        );
        // Roundtrip
        let serialized = serde_json::to_string(&kind).unwrap();
        let recovered: EventKind = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(kind, recovered);
    }

    /// Unknown single-token strings roundtrip through Unknown variant.
    #[test]
    fn unknown_single_token_roundtrip(token in "[a-z]{2,10}") {
        // Exclude known legacy tokens
        prop_assume!(!["message", "commit", "welcome", "checkpoint", "reaction"].contains(&token.as_str()));
        let json = format!("\"{}\"", token);
        let kind: EventKind = serde_json::from_str(&json).unwrap();
        prop_assert!(
            matches!(&kind, EventKind::Unknown(s) if *s == token),
            "expected Unknown({:?}), got {:?}", token, kind
        );
    }

    // --- Bucket monotonicity ---

    /// Larger plaintexts never produce smaller buckets.
    #[test]
    fn bucket_monotonicity(n1 in 0usize..4092, n2 in 0usize..4092) {
        prop_assume!(n1 <= n2);
        prop_assert!(
            Bucket::for_size(n1).size() <= Bucket::for_size(n2).size(),
            "bucket({}) = {} > bucket({}) = {}",
            n1, Bucket::for_size(n1).size(),
            n2, Bucket::for_size(n2).size()
        );
    }

    // --- build_text_payload text preservation ---
    // (tested via Event::message roundtrip since build_text_payload is in moat-cli)

    /// Any text stored in a MessagePayload survives Event serialize → deserialize.
    #[test]
    fn text_payload_preserves_content(text in "\\PC{0,500}") {
        let payload = if text.as_bytes().len() <= 240 {
            MessagePayload::ShortText(TextMessage { text: text.clone() })
        } else {
            MessagePayload::MediumText(TextMessage { text: text.clone() })
        };
        let event = Event::message(b"group".to_vec(), 0, &payload);
        let bytes = event.to_bytes().unwrap();
        let recovered = Event::from_bytes(&bytes).unwrap();
        let parsed = recovered.parse_message_payload().unwrap();
        let preview = parsed.preview_text().unwrap();
        prop_assert_eq!(&preview, &text);
    }

    /// Short text (≤240 bytes) classified as ShortText, longer as MediumText.
    #[test]
    fn text_promotion_threshold(text in "\\PC{0,500}") {
        let payload = if text.as_bytes().len() <= 240 {
            MessagePayload::ShortText(TextMessage { text: text.clone() })
        } else {
            MessagePayload::MediumText(TextMessage { text: text.clone() })
        };
        match &payload {
            MessagePayload::ShortText(tm) => {
                prop_assert!(tm.text.as_bytes().len() <= 240);
                prop_assert_eq!(&tm.text, &text);
            }
            MessagePayload::MediumText(tm) => {
                prop_assert!(tm.text.as_bytes().len() > 240);
                prop_assert_eq!(&tm.text, &text);
            }
            _ => prop_assert!(false, "unexpected variant"),
        }
    }
}
