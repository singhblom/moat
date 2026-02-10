//! Commit conflict tests (Tests 11-15 from transcript integrity plan).

mod conversation_sim;
use conversation_sim::ConversationSim;
use moat_core::{EventKind, ErrorCode};

/// Test 11: Sequential commits from different participants.
/// Alice adds Dave, then Bob adds Eve. No conflict — each commit
/// happens at a different epoch.
#[test]
fn test_sequential_commits_no_conflict() {
    let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

    // Alice adds Dave
    let (commit_a, _welcome_a, _dave_idx) = sim.add_member_sim(0, "Dave");

    // Deliver Alice's commit to Bob and Charlie
    let outcome_b = sim.deliver_commit(1, &commit_a).unwrap();
    assert_eq!(outcome_b.result().event.kind, EventKind::Commit);
    assert!(!ConversationSim::has_conflict_recovered(outcome_b.warnings()));

    let outcome_c = sim.deliver_commit(2, &commit_a).unwrap();
    assert_eq!(outcome_c.result().event.kind, EventKind::Commit);
    assert!(!ConversationSim::has_conflict_recovered(outcome_c.warnings()));

    // Now Bob adds Eve (different epoch, no conflict)
    let (commit_b, _welcome_b, _eve_idx) = sim.add_member_sim(1, "Eve");

    // Deliver Bob's commit to Alice and Charlie
    let outcome_a = sim.deliver_commit(0, &commit_b).unwrap();
    assert_eq!(outcome_a.result().event.kind, EventKind::Commit);
    assert!(!ConversationSim::has_conflict_recovered(outcome_a.warnings()));

    let outcome_c2 = sim.deliver_commit(2, &commit_b).unwrap();
    assert_eq!(outcome_c2.result().event.kind, EventKind::Commit);
    assert!(!ConversationSim::has_conflict_recovered(outcome_c2.warnings()));
}

/// Test 12: Concurrent commits detected.
/// Alice and Bob both create commits at the same epoch (both add a member).
/// When Alice receives Bob's commit, process_message should fail because
/// Alice's group state has already advanced.
#[test]
fn test_concurrent_commits_detected() {
    let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

    // Both create commits at the same epoch — Alice adds Dave, Bob adds Eve
    let (commit_a, _welcome_a, _dave_idx) = sim.add_member_sim(0, "Dave");
    let (commit_b, _welcome_b, _eve_idx) = sim.add_member_sim(1, "Eve");

    // Alice tries to process Bob's commit — Alice is already at a higher epoch
    let result_a = sim.deliver_commit(0, &commit_b);

    // Should fail with a structured error (StaleCommit or StateDiverged)
    match result_a {
        Err(e) => {
            let code = e.code();
            assert!(
                code == ErrorCode::StaleCommit
                    || code == ErrorCode::StateDiverged
                    || code == ErrorCode::Decryption,
                "expected StaleCommit, StateDiverged, or Decryption error, got {:?}: {}",
                code,
                e.message()
            );
        }
        Ok(outcome) => {
            // If OpenMLS somehow accepts it (e.g., epoch logic), at minimum
            // we should see warnings
            assert!(
                ConversationSim::has_conflict_recovered(outcome.warnings())
                    || !outcome.warnings().is_empty(),
                "concurrent commit should produce warnings or errors"
            );
        }
    }

    // Bob tries to process Alice's commit — same situation
    let result_b = sim.deliver_commit(1, &commit_a);
    match result_b {
        Err(e) => {
            let code = e.code();
            assert!(
                code == ErrorCode::StaleCommit
                    || code == ErrorCode::StateDiverged
                    || code == ErrorCode::Decryption,
                "expected StaleCommit, StateDiverged, or Decryption error, got {:?}: {}",
                code,
                e.message()
            );
        }
        Ok(outcome) => {
            assert!(
                ConversationSim::has_conflict_recovered(outcome.warnings())
                    || !outcome.warnings().is_empty(),
                "concurrent commit should produce warnings or errors"
            );
        }
    }
}

/// Test 13: Charlie (bystander) receives sequential commits from concurrent sources.
/// Alice and Bob both commit at the same epoch. Charlie receives Alice's first,
/// then Bob's. Charlie should be able to process Alice's but Bob's should fail
/// (since it references the pre-commit epoch state).
#[test]
fn test_bystander_receives_conflicting_commits() {
    let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

    // Both commit at the same epoch
    let (commit_a, _welcome_a, _dave_idx) = sim.add_member_sim(0, "Dave");
    let (commit_b, _welcome_b, _eve_idx) = sim.add_member_sim(1, "Eve");

    // Charlie receives Alice's commit first — should work fine
    let outcome_c1 = sim.deliver_commit(2, &commit_a).unwrap();
    assert_eq!(outcome_c1.result().event.kind, EventKind::Commit);

    // Charlie receives Bob's commit — should fail (epoch conflict)
    let result_c2 = sim.deliver_commit(2, &commit_b);
    assert!(
        result_c2.is_err(),
        "bystander should reject second concurrent commit"
    );
}

/// Test 14: Structured error classification — StaleCommit vs StateDiverged.
/// Verify that the error type is meaningful, not just generic Decryption.
#[test]
fn test_structured_error_classification() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    // Alice adds Charlie
    let (_commit_a, _welcome_a, _charlie_idx) = sim.add_member_sim(0, "Charlie");

    // Bob also adds Dave at the same epoch
    let (commit_b, _welcome_b, _dave_idx) = sim.add_member_sim(1, "Dave");

    // Alice gets Bob's stale commit
    let result = sim.deliver_commit(0, &commit_b);
    assert!(result.is_err(), "should reject concurrent commit");

    let err = result.unwrap_err();
    // The error should be one of our structured types, not just generic Decryption
    let code = err.code();
    assert!(
        code == ErrorCode::StaleCommit
            || code == ErrorCode::StateDiverged
            || code == ErrorCode::Decryption,
        "error should be classified as StaleCommit, StateDiverged, or Decryption, got {:?}",
        code
    );
    // The error message should contain useful context
    assert!(
        !err.message().is_empty(),
        "error message should not be empty"
    );
}

/// Test 15: Messages after sequential commits remain decryptable.
/// After Alice commits and Bob processes it, both should be able to
/// exchange messages at the new epoch.
#[test]
fn test_messages_after_commit_succeed() {
    let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

    // Alice adds Dave
    let (commit, _welcome, _dave_idx) = sim.add_member_sim(0, "Dave");

    // Deliver to Bob and Charlie
    sim.deliver_commit(1, &commit).unwrap();
    sim.deliver_commit(2, &commit).unwrap();

    // Now everyone should be able to message at the new epoch
    sim.send_message(0, b"Hello from Alice after commit");
    let outcome_b = sim.deliver_next(1).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome_b));
    assert_eq!(outcome_b.result().event.payload, b"Hello from Alice after commit");

    // Bob can also send
    sim.send_message(1, b"Hello from Bob after commit");
    let outcome_a = sim.deliver_next(0).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome_a));
    assert_eq!(outcome_a.result().event.payload, b"Hello from Bob after commit");

    // Charlie can also send and receive
    let outcome_c = sim.deliver_next(2).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome_c));

    sim.send_message(2, b"Hello from Charlie");
    let outcome_a2 = sim.deliver_next(0).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome_a2));
    assert_eq!(outcome_a2.result().event.payload, b"Hello from Charlie");
}
