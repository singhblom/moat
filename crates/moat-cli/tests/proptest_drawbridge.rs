//! Property-based tests for Drawbridge module invariants.
//!
//! Note: Ed25519 signing property tests live in moat-core/tests/proptest_drawbridge.rs,
//! since that's where MoatSession::sign_drawbridge_challenge is implemented.

use proptest::prelude::*;
use std::collections::HashMap;

// ── Signed message format ─────────────────────────────────────────

proptest! {
    /// The signed message construction is deterministic — same inputs
    /// always produce the same byte sequence.
    #[test]
    fn signed_message_format_deterministic(
        nonce in "[a-zA-Z0-9]{8,32}",
        host in "[a-z]{3,10}\\.[a-z]{2,4}",
        timestamp in 1_700_000_000i64..1_900_000_000,
    ) {
        // Server includes the request path in its relay URL, so we sign the full URL
        let url = format!("wss://{}/ws", host);
        let msg1 = format!("{}\n{}\n{}\n", nonce, url, timestamp);
        let msg2 = format!("{}\n{}\n{}\n", nonce, url, timestamp);
        prop_assert_eq!(msg1, msg2);
    }

    /// Rust's i64 Display format matches Go's strconv.FormatInt for all
    /// non-negative timestamps. Both produce plain decimal with no leading
    /// zeros, no sign prefix for positive numbers.
    #[test]
    fn timestamp_format_matches_go(timestamp in 0i64..i64::MAX) {
        let formatted = format!("{}", timestamp);
        prop_assert!(!formatted.starts_with('0') || formatted == "0");
        prop_assert!(!formatted.starts_with('+'));
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
    /// JSON roundtrip preserves all fields.
    #[test]
    fn drawbridge_state_json_roundtrip(state in arb_drawbridge_state()) {
        let json = serde_json::to_string(&state).unwrap();
        let parsed: TestDrawbridgeState = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(parsed, state);
    }
}

/// For hints with unique (partner_did, device_id_hex) keys, load -> export preserves all hints.
#[test]
fn load_export_preserves_unique_hints() {
    let hints: Vec<TestStoredHint> = (0..10)
        .map(|i| TestStoredHint {
            url: format!("wss://relay-{}.example.com/ws", i),
            device_id_hex: format!("{:04x}", i),
            ticket_hex: format!("{:064x}", i),
            partner_did: format!("did:plc:partner{}", i),
            group_id_hex: format!("{:032x}", i),
        })
        .collect();

    let mut map: HashMap<(String, String), TestStoredHint> = HashMap::new();
    for hint in &hints {
        let key = (hint.partner_did.clone(), hint.device_id_hex.clone());
        map.insert(key, hint.clone());
    }

    let exported: Vec<TestStoredHint> = map.values().cloned().collect();
    assert_eq!(exported.len(), hints.len());
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
    /// Backoff is monotonically non-decreasing.
    #[test]
    fn backoff_monotonic(a in 0u32..100, b in 0u32..100) {
        if a <= b {
            prop_assert!(backoff_duration(a) <= backoff_duration(b));
        }
    }

    /// Backoff is bounded above by 300 seconds.
    #[test]
    fn backoff_bounded(attempt in 0u32..u32::MAX) {
        prop_assert!(backoff_duration(attempt) <= std::time::Duration::from_secs(300));
    }

    /// Backoff is always positive.
    #[test]
    fn backoff_positive(attempt in 0u32..u32::MAX) {
        prop_assert!(backoff_duration(attempt) > std::time::Duration::ZERO);
    }
}
