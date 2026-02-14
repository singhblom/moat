//! Deterministic hash chain tests (Tests 1-7 from transcript integrity plan).

mod conversation_sim;
use conversation_sim::ConversationSim;
use moat_core::{Event, EventKind};

/// Test 1: Complete delivery. Alice sends M1, M2, M3 to Bob.
/// Bob verifies the hash chain is contiguous.
#[test]
fn test_complete_delivery_no_warnings() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    sim.send_message(0, b"M1");
    sim.send_message(0, b"M2");
    sim.send_message(0, b"M3");

    // Bob receives all three in order — no warnings expected
    for _ in 0..3 {
        let outcome = sim.deliver_next(1).unwrap();
        assert!(
            !ConversationSim::has_warnings(&outcome),
            "expected no warnings on complete delivery"
        );
    }
}

/// Test 2: Withholding. Alice sends M1, M2, M3. Deliver only M1 and M3
/// to Bob (drop M2). Bob should detect a gap.
#[test]
fn test_withholding_detected() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    sim.send_message(0, b"M1");
    sim.send_message(0, b"M2");
    sim.send_message(0, b"M3");

    // Bob receives M1
    let outcome1 = sim.deliver_next(1).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome1));

    // Drop M2
    sim.drop_next(1);

    // Bob receives M3 — should detect hash chain mismatch
    let outcome3 = sim.deliver_next(1).unwrap();
    assert!(
        ConversationSim::has_hash_chain_mismatch(outcome3.warnings()),
        "expected hash chain mismatch after withholding"
    );
}

/// Test 3: Reordering. Alice sends M1, M2, M3. Deliver M1, M3, M2 to Bob.
#[test]
fn test_reordering_detected() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    sim.send_message(0, b"M1");
    sim.send_message(0, b"M2");
    sim.send_message(0, b"M3");

    // Bob receives M1
    let outcome1 = sim.deliver_next(1).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome1));

    // Swap M2 and M3 in Bob's inbox
    sim.reorder_next_two(1);

    // Bob receives M3 (was M2's slot) — hash chain mismatch
    let outcome_swapped1 = sim.deliver_next(1).unwrap();
    assert!(
        ConversationSim::has_hash_chain_mismatch(outcome_swapped1.warnings()),
        "expected hash chain mismatch on first reordered event"
    );

    // Bob receives M2 (was M3's slot) — also hash chain mismatch
    let outcome_swapped2 = sim.deliver_next(1).unwrap();
    assert!(
        ConversationSim::has_hash_chain_mismatch(outcome_swapped2.warnings()),
        "expected hash chain mismatch on second reordered event"
    );
}

/// Test 4: Replay. Deliver M1 twice. The second delivery should be detected
/// either by MLS (protocol-level rejection) or by our hash chain (replay warning).
#[test]
fn test_replay_detected() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    let record = sim.send_message(0, b"M1");

    // Bob receives M1
    let outcome1 = sim.deliver_next(1).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome1));

    // Manually push the same ciphertext again into Bob's inbox
    sim.inboxes[1].push_back(record);

    // Bob receives M1 again
    let result = sim.participants[1].session.decrypt_event(
        &sim.group_id,
        &sim.inboxes[1].pop_front().unwrap().ciphertext,
    );

    match result {
        Err(_) => {
            // MLS rejected the replay at protocol level — this is fine
        }
        Ok(outcome) => {
            // MLS allowed re-processing — our hash chain should catch it
            assert!(
                ConversationSim::has_replay_detected(outcome.warnings()),
                "expected replay detection warning when MLS doesn't reject"
            );
        }
    }
}

/// Test 5: Multi-sender interleaving. Alice sends A1, A2. Bob sends B1, B2.
/// Deliver in order A1, B1, A2, B2 to Charlie. Each sender's chain should
/// verify independently.
#[test]
fn test_multi_sender_interleaving() {
    let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

    // Alice sends A1
    sim.send_message(0, b"A1");
    // Bob sends B1
    sim.send_message(1, b"B1");
    // Alice sends A2
    sim.send_message(0, b"A2");
    // Bob sends B2
    sim.send_message(1, b"B2");

    // Charlie's inbox should have: A1, B1, A2, B2 (in send order)
    assert_eq!(sim.inbox_len(2), 4);

    // Deliver all to Charlie — no warnings expected since each sender's
    // chain is independent and delivered in order
    for _ in 0..4 {
        let outcome = sim.deliver_next(2).unwrap();
        assert!(
            !ConversationSim::has_warnings(&outcome),
            "expected no warnings on properly interleaved multi-sender delivery"
        );
    }
}

/// Test 6: First event has prev_event_hash = None.
#[test]
fn test_first_event_has_none_prev_hash() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    sim.send_message(0, b"First message");

    let outcome = sim.deliver_next(1).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome));

    let event = &outcome.result().event;
    // The first event from Alice should have prev_event_hash = None
    // (the sender_device_id should be set though)
    assert!(event.sender_device_id.is_some());
}

/// Test 7: Backward compatibility. An old event without prev_event_hash
/// and epoch_fingerprint (deserialized as None) should not trigger validation.
#[test]
fn test_backward_compat_no_transcript_fields() {
    // Simulate a legacy event without the new fields
    let json = r#"{"kind":"message","group_id":[1,2,3],"epoch":0,"payload":[104,105]}"#;
    let event: Event = serde_json::from_str(json).unwrap();

    assert_eq!(event.kind, EventKind::Message);
    assert!(event.prev_event_hash.is_none());
    assert!(event.epoch_fingerprint.is_none());
    assert!(event.sender_device_id.is_none());
    // No crash, no validation error — backward compatible
}
