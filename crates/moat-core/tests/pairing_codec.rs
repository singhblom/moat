//! Unit tests for the pairing code codec.

use moat_core::{crockford_decode, crockford_encode, PairingPayload, CROCKFORD_ALPHABET};

fn sample_payload() -> PairingPayload {
    PairingPayload {
        token: [0x11; 16],
        secret: [0x22; 32],
    }
}

#[test]
fn payload_roundtrips_through_raw_bytes() {
    let payload = sample_payload();
    let encoded = payload.encode();
    assert_eq!(encoded.len(), moat_core::PAIRING_PAYLOAD_LEN);
    assert_eq!(encoded[0], moat_core::PAIRING_PAYLOAD_VERSION);

    let decoded = PairingPayload::decode(&encoded).expect("valid payload should decode");
    assert_eq!(decoded, payload);
}

#[test]
fn payload_roundtrips_through_text_form() {
    let payload = sample_payload();
    let text = payload.to_text();

    // Hyphen-grouped in fives: `MZXW6-YTBOI-…`.
    assert!(text.contains('-'), "text form should be hyphen-grouped");

    let decoded = PairingPayload::from_text(&text).expect("valid text should decode");
    assert_eq!(decoded, payload);
}

#[test]
fn payload_roundtrips_through_uri_form() {
    let payload = sample_payload();
    let uri = payload.to_uri();

    assert!(
        uri.starts_with(moat_core::PAIRING_URI_SCHEME),
        "uri form should start with {}, got: {uri}",
        moat_core::PAIRING_URI_SCHEME
    );

    let decoded = PairingPayload::from_uri(&uri).expect("valid uri should decode");
    assert_eq!(decoded, payload);
}

#[test]
fn decode_rejects_bad_version() {
    let mut bytes = sample_payload().encode();
    bytes[0] = 0xFF;

    let err = PairingPayload::decode(&bytes).expect_err("bad version byte must be rejected");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("version"),
        "error should name the missing/bad version, got: {msg}"
    );
}

#[test]
fn decode_rejects_truncated_payload() {
    let bytes = sample_payload().encode();
    let truncated = &bytes[..bytes.len() - 1];

    assert!(
        PairingPayload::decode(truncated).is_err(),
        "a payload short of PAIRING_PAYLOAD_LEN must be rejected"
    );
}

#[test]
fn decode_rejects_oversized_payload() {
    let mut bytes = sample_payload().encode();
    bytes.push(0x00);

    assert!(
        PairingPayload::decode(&bytes).is_err(),
        "a payload longer than PAIRING_PAYLOAD_LEN must be rejected"
    );
}

#[test]
fn from_text_rejects_bad_characters() {
    // 'I', 'L', 'O', 'U' are deliberately excluded from the Crockford
    // alphabet (visual-confusion avoidance), so a code containing them is
    // definitely not a valid pairing code.
    let err = PairingPayload::from_text("IIIII-LLLLL-OOOOO-UUUUU")
        .expect_err("characters outside the Crockford alphabet must be rejected");
    let _ = err;
}

#[test]
fn from_text_is_case_insensitive() {
    let payload = sample_payload();
    let text = payload.to_text();
    let lower = text.to_lowercase();

    let decoded =
        PairingPayload::from_text(&lower).expect("lowercase text form should decode identically");
    assert_eq!(decoded, payload);
}

#[test]
fn from_uri_rejects_foreign_scheme() {
    let payload = sample_payload();
    let text = payload.to_text();
    let foreign = format!("https://evil.example/{text}");

    assert!(
        PairingPayload::from_uri(&foreign).is_err(),
        "a non-`moat-pair:` scheme must be rejected, so foreign QRs are cheap to reject"
    );
}

#[test]
fn crockford_alphabet_excludes_confusable_letters() {
    for c in [b'I', b'L', b'O', b'U'] {
        assert!(
            !CROCKFORD_ALPHABET.contains(&c),
            "alphabet should exclude {} to avoid manual-entry confusion",
            c as char
        );
    }
    assert_eq!(CROCKFORD_ALPHABET.len(), 32);
}

#[test]
fn crockford_roundtrips_arbitrary_bytes() {
    let data = b"the quick brown fox jumps over 13 lazy dogs!!";
    let encoded = crockford_encode(data);
    let decoded = crockford_decode(&encoded).expect("valid crockford text should decode");
    assert_eq!(decoded, data);
}

#[test]
fn crockford_decode_rejects_invalid_characters() {
    // '!' is not in the Crockford alphabet and not a separator.
    assert!(crockford_decode("ABC!DEF").is_err());
}

#[test]
fn crockford_decode_ignores_hyphens_and_whitespace() {
    let data = b"round trip me";
    let encoded = crockford_encode(data);

    // Re-group with different hyphen placement — should still decode the
    // same, since grouping is presentation-only.
    let regrouped: String = encoded
        .chars()
        .collect::<Vec<_>>()
        .chunks(3)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-");

    let decoded =
        crockford_decode(&regrouped).expect("hyphens must be ignored, not treated as data");
    assert_eq!(decoded, data);
}
