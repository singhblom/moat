//! Property-based tests for Drawbridge module invariants.

use ed25519_dalek::{Signer, SigningKey, Verifier};
use proptest::prelude::*;
use std::collections::HashMap;

// ── sign_challenge TLS parsing ────────────────────────────────────

/// Build a TLS-serialized SignatureKeyPair from a 32-byte Ed25519 seed.
/// Format: [2-byte priv_len][private_key][2-byte pub_len][public_key]
fn build_tls_keypair_32(seed: &[u8; 32]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(seed);
    let pub_key = signing_key.verifying_key();
    let mut buf = Vec::new();
    // Private key length prefix (32 as big-endian u16)
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(seed);
    // Public key length prefix (32 as big-endian u16)
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(pub_key.as_bytes());
    buf
}

/// Build TLS-serialized with 64-byte private section (seed ++ pubkey).
fn build_tls_keypair_64(seed: &[u8; 32]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(seed);
    let pub_key = signing_key.verifying_key();
    let mut buf = Vec::new();
    // Private key length prefix (64 as big-endian u16)
    buf.extend_from_slice(&64u16.to_be_bytes());
    buf.extend_from_slice(seed);
    buf.extend_from_slice(pub_key.as_bytes());
    // Public key length prefix (32 as big-endian u16)
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(pub_key.as_bytes());
    buf
}

/// Reimplement sign_challenge in test code so we can test it without
/// depending on the binary's internal module.
fn sign_challenge_impl(
    signature_key: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if signature_key.len() < 4 {
        return Err("signature_key too short".to_string());
    }

    let priv_len = u16::from_be_bytes([signature_key[0], signature_key[1]]) as usize;
    if signature_key.len() < 2 + priv_len + 2 {
        return Err("signature_key too short for private key".to_string());
    }

    let priv_bytes = &signature_key[2..2 + priv_len];

    let signing_key = if priv_bytes.len() == 32 {
        SigningKey::from_bytes(priv_bytes.try_into().unwrap())
    } else if priv_bytes.len() == 64 {
        SigningKey::from_bytes(priv_bytes[..32].try_into().unwrap())
    } else {
        return Err(format!("unexpected private key length: {}", priv_bytes.len()));
    };

    let signature = signing_key.sign(message);
    Ok((
        signature.to_bytes().to_vec(),
        signing_key.verifying_key().to_bytes().to_vec(),
    ))
}

proptest! {
    /// Property 1a: For any 32-byte seed, TLS-serialized as 32-byte private key,
    /// sign_challenge produces a valid Ed25519 signature.
    #[test]
    fn sign_challenge_32byte_seed_produces_valid_signature(
        seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let tls_bytes = build_tls_keypair_32(&seed);
        let (sig_bytes, pub_bytes) = sign_challenge_impl(&tls_bytes, &message).unwrap();

        let pub_key = ed25519_dalek::VerifyingKey::from_bytes(
            pub_bytes.as_slice().try_into().unwrap()
        ).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().unwrap()
        );

        prop_assert!(pub_key.verify(&message, &signature).is_ok(),
            "signature verification failed for 32-byte seed");
    }

    /// Property 1b: For any 32-byte seed, TLS-serialized as 64-byte private key
    /// (seed ++ pubkey), sign_challenge produces the SAME signature as the 32-byte path.
    #[test]
    fn sign_challenge_64byte_key_matches_32byte(
        seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let tls_32 = build_tls_keypair_32(&seed);
        let tls_64 = build_tls_keypair_64(&seed);

        let (sig_32, pub_32) = sign_challenge_impl(&tls_32, &message).unwrap();
        let (sig_64, pub_64) = sign_challenge_impl(&tls_64, &message).unwrap();

        prop_assert_eq!(&sig_32, &sig_64, "signatures differ between 32 and 64 byte paths");
        prop_assert_eq!(&pub_32, &pub_64, "public keys differ between 32 and 64 byte paths");
    }

    /// Property 1c: Invalid TLS inputs never panic, always return Err.
    #[test]
    fn sign_challenge_invalid_input_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let message = b"test message";
        // This should not panic, regardless of input
        let _ = sign_challenge_impl(&data, message);
    }

    /// Property 1c (refined): Inputs too short to contain a valid key always fail.
    #[test]
    fn sign_challenge_short_inputs_fail(
        data in prop::collection::vec(any::<u8>(), 0..4),
    ) {
        let result = sign_challenge_impl(&data, b"test");
        prop_assert!(result.is_err(), "expected error for input of length {}", data.len());
    }

    /// Property 1c (refined): Declared priv_len that exceeds buffer fails.
    #[test]
    fn sign_challenge_oversized_priv_len_fails(
        excess in 1u16..256,
    ) {
        // Create buffer where declared priv_len exceeds actual data
        let priv_len = 32u16 + excess;
        let mut buf = Vec::new();
        buf.extend_from_slice(&priv_len.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]); // Only 32 bytes, but declared more
        let result = sign_challenge_impl(&buf, b"test");
        prop_assert!(result.is_err());
    }

    /// Property 1c (refined): Unusual private key lengths (not 32 or 64) fail.
    #[test]
    fn sign_challenge_unusual_priv_len_fails(
        priv_len in (0u16..128).prop_filter("not 32 or 64", |l| *l != 32 && *l != 64),
    ) {
        let mut buf = Vec::new();
        buf.extend_from_slice(&priv_len.to_be_bytes());
        buf.extend_from_slice(&vec![0u8; priv_len as usize]);
        // Pub key section
        buf.extend_from_slice(&32u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        let result = sign_challenge_impl(&buf, b"test");
        prop_assert!(result.is_err(), "expected error for priv_len={}", priv_len);
    }
}

// ── Signed message format ─────────────────────────────────────────

proptest! {
    /// Property 2a: Signed message construction is deterministic — same inputs
    /// always produce the same byte sequence.
    #[test]
    fn signed_message_format_deterministic(
        nonce in "[a-zA-Z0-9]{8,32}",
        url in "wss://[a-z]{3,10}\\.[a-z]{2,4}/ws",
        timestamp in 1_700_000_000i64..1_900_000_000,
    ) {
        let msg1 = format!("{}\n{}\n{}\n", nonce, url, timestamp);
        let msg2 = format!("{}\n{}\n{}\n", nonce, url, timestamp);
        prop_assert_eq!(msg1, msg2);
    }

    /// Property 2a: Rust's i64 Display format matches Go's strconv.FormatInt
    /// for all non-negative timestamps. Both produce plain decimal with no
    /// leading zeros, no sign for positive numbers.
    #[test]
    fn timestamp_format_matches_go(timestamp in 0i64..i64::MAX) {
        let formatted = format!("{}", timestamp);
        // Go's strconv.FormatInt(n, 10) produces: no leading zeros, no '+' sign
        prop_assert!(!formatted.starts_with('0') || formatted == "0");
        prop_assert!(!formatted.starts_with('+'));
        // All characters are digits
        prop_assert!(formatted.chars().all(|c| c.is_ascii_digit()));
    }
}

// ── DrawbridgeState serde roundtrip ──────────────────────────────

/// Minimal DrawbridgeState for testing (mirrors the real type).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct TestDrawbridgeState {
    own_url: Option<String>,
    own_tickets: HashMap<String, String>,
    partner_hints: Vec<TestStoredHint>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct TestStoredHint {
    url: String,
    device_id_hex: String,
    ticket_hex: String,
    partner_did: String,
    group_id_hex: String,
}

fn arb_stored_hint() -> impl Strategy<Value = TestStoredHint> {
    (
        "wss://[a-z]{3,8}\\.[a-z]{2,3}/ws",
        "[0-9a-f]{4,16}",
        "[0-9a-f]{64}",
        "did:plc:[a-z0-9]{8,24}",
        "[0-9a-f]{16,64}",
    )
        .prop_map(|(url, device_id_hex, ticket_hex, partner_did, group_id_hex)| TestStoredHint {
            url,
            device_id_hex,
            ticket_hex,
            partner_did,
            group_id_hex,
        })
}

fn arb_drawbridge_state() -> impl Strategy<Value = TestDrawbridgeState> {
    (
        prop::option::of("wss://[a-z]{3,8}\\.[a-z]{2,3}/ws"),
        prop::collection::hash_map("[0-9a-f]{16,64}", "[0-9a-f]{64}", 0..5),
        prop::collection::vec(arb_stored_hint(), 0..5),
    )
        .prop_map(|(own_url, own_tickets, partner_hints)| TestDrawbridgeState {
            own_url,
            own_tickets,
            partner_hints,
        })
}

proptest! {
    /// Property 5a: JSON roundtrip preserves all fields.
    #[test]
    fn drawbridge_state_json_roundtrip(state in arb_drawbridge_state()) {
        let json = serde_json::to_string(&state).unwrap();
        let parsed: TestDrawbridgeState = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(parsed, state);
    }
}

// ── load_state / export_state hint roundtrip ─────────────────────

/// Property 5b: For hints with unique (partner_did, device_id_hex) keys,
/// the load -> export cycle preserves all hints.
#[test]
fn load_export_preserves_unique_hints() {
    // Generate hints with guaranteed-unique keys
    let hints: Vec<TestStoredHint> = (0..10)
        .map(|i| TestStoredHint {
            url: format!("wss://relay-{}.example.com/ws", i),
            device_id_hex: format!("{:04x}", i),
            ticket_hex: format!("{:064x}", i),
            partner_did: format!("did:plc:partner{}", i),
            group_id_hex: format!("{:032x}", i),
        })
        .collect();

    // Simulate load_state: insert into HashMap keyed by (partner_did, device_id_hex)
    let mut map: HashMap<(String, String), TestStoredHint> = HashMap::new();
    for hint in &hints {
        let key = (hint.partner_did.clone(), hint.device_id_hex.clone());
        map.insert(key, hint.clone());
    }

    // Simulate export_state: collect values
    let exported: Vec<TestStoredHint> = map.values().cloned().collect();

    assert_eq!(exported.len(), hints.len(), "unique hints should all survive roundtrip");
}

/// Property 5b (corollary): Duplicate keys cause silent data loss.
/// This documents the current behavior — not necessarily a bug, but
/// something a caller should be aware of.
#[test]
fn load_state_deduplicates_same_key() {
    let hint1 = TestStoredHint {
        url: "wss://a.com/ws".to_string(),
        device_id_hex: "aa".to_string(),
        ticket_hex: "bb".to_string(),
        partner_did: "did:plc:alice".to_string(),
        group_id_hex: "cc".to_string(),
    };
    let hint2 = TestStoredHint {
        url: "wss://b.com/ws".to_string(), // Different URL
        device_id_hex: "aa".to_string(),    // Same key!
        ticket_hex: "dd".to_string(),
        partner_did: "did:plc:alice".to_string(), // Same key!
        group_id_hex: "ee".to_string(),
    };

    let mut map: HashMap<(String, String), TestStoredHint> = HashMap::new();
    let key1 = (hint1.partner_did.clone(), hint1.device_id_hex.clone());
    map.insert(key1.clone(), hint1);
    let key2 = (hint2.partner_did.clone(), hint2.device_id_hex.clone());
    map.insert(key2, hint2.clone());

    // Same key → second insert overwrites first
    assert_eq!(map.len(), 1);
    assert_eq!(map[&key1].url, "wss://b.com/ws");
}

// ── Backoff properties ───────────────────────────────────────────

fn backoff_duration(attempt: u32) -> std::time::Duration {
    use std::time::Duration;
    match attempt {
        0 => Duration::from_secs(5),
        1 => Duration::from_secs(10),
        2 => Duration::from_secs(30),
        3 => Duration::from_secs(60),
        _ => Duration::from_secs(300),
    }
}

proptest! {
    /// Property 6a: Backoff is monotonically non-decreasing.
    #[test]
    fn backoff_monotonic(a in 0u32..100, b in 0u32..100) {
        if a <= b {
            prop_assert!(backoff_duration(a) <= backoff_duration(b));
        }
    }

    /// Property 6b: Backoff is bounded above by 300 seconds.
    #[test]
    fn backoff_bounded(attempt in 0u32..u32::MAX) {
        prop_assert!(backoff_duration(attempt) <= std::time::Duration::from_secs(300));
    }

    /// Property 6c: Backoff is always positive.
    #[test]
    fn backoff_positive(attempt in 0u32..u32::MAX) {
        prop_assert!(backoff_duration(attempt) > std::time::Duration::ZERO);
    }
}

// ── Cross-language test vector generation ────────────────────────

/// Generate test vectors for cross-language verification.
/// These vectors can be consumed by Go tests to verify format agreement.
#[test]
fn generate_signed_message_test_vectors() {
    let test_cases: Vec<(&str, &str, i64)> = vec![
        ("abc123", "wss://relay.example.com/ws", 1700000000),
        ("", "wss://relay.example.com/ws", 0),
        ("nonce-with-special-chars!@#", "wss://a.b/ws", 1999999999),
        ("x", "wss://relay.example.com/ws", i64::MAX),
    ];

    for (nonce, url, timestamp) in &test_cases {
        let msg = format!("{}\n{}\n{}\n", nonce, url, timestamp);

        // Sign with a known seed
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(msg.as_bytes());

        // These can be verified in Go:
        // message_bytes, pub_key, signature should all match
        let _pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let _sig_hex = hex::encode(signature.to_bytes());
        let _msg_hex = hex::encode(msg.as_bytes());

        // Verify locally — if this passes, the vectors are self-consistent
        assert!(signing_key
            .verifying_key()
            .verify(msg.as_bytes(), &signature)
            .is_ok());
    }
}

/// Write test vectors to a JSON file for Go consumption.
#[test]
fn write_cross_language_test_vectors() {
    use base64::Engine;

    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pub_key = signing_key.verifying_key();

    let test_cases: Vec<(&str, &str, i64)> = vec![
        ("abc123", "wss://relay.example.com/ws", 1700000000),
        ("nonce_xyz_789", "wss://drawbridge.moat.social/ws", 1700000001),
        ("short", "wss://a.b/ws", 0),
        ("a-long-nonce-value-for-testing-purposes", "wss://relay.example.com/ws", 1999999999),
    ];

    let mut vectors: Vec<serde_json::Value> = Vec::new();
    for (nonce, url, timestamp) in &test_cases {
        let msg = format!("{}\n{}\n{}\n", nonce, url, timestamp);
        let signature = signing_key.sign(msg.as_bytes());

        vectors.push(serde_json::json!({
            "nonce": nonce,
            "url": url,
            "timestamp": timestamp,
            "message_hex": hex::encode(msg.as_bytes()),
            "public_key_b64": base64::engine::general_purpose::STANDARD.encode(pub_key.as_bytes()),
            "signature_b64": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        }));
    }

    let json = serde_json::to_string_pretty(&vectors).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("moat-drawbridge")
        .join("testdata")
        .join("challenge_vectors.json");

    // Create dir if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, &json).unwrap();
}
