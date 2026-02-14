//! Deterministic epoch fingerprint tests (Tests 8-10 from transcript integrity plan).

mod conversation_sim;
use conversation_sim::ConversationSim;
use moat_core::{EventKind, MoatCredential, MoatSession};

/// Test 8: Agreement after message. Alice encrypts at epoch N. Bob decrypts.
/// Both derive the same epoch_fingerprint (no mismatch warning).
#[test]
fn test_epoch_fingerprint_agreement_after_message() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    sim.send_message(0, b"Hello Bob!");

    let outcome = sim.deliver_next(1).unwrap();
    // No epoch fingerprint mismatch expected
    assert!(
        !ConversationSim::has_epoch_fingerprint_mismatch(outcome.warnings()),
        "epoch fingerprints should agree after message"
    );

    // The event should carry an epoch fingerprint
    let event = &outcome.result().event;
    assert!(event.epoch_fingerprint.is_some(), "event should have epoch fingerprint");
    assert_eq!(event.epoch_fingerprint.as_ref().unwrap().len(), 16);
}

/// Test 9: Agreement after commit. Alice adds Charlie. Bob processes the commit.
/// Both derive the same fingerprint for the new epoch.
#[test]
fn test_epoch_fingerprint_agreement_after_commit() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    // After the initial setup, Alice and Bob are in the group.
    // Alice sends a message to verify epoch fingerprint agreement
    sim.send_message(0, b"Pre-commit message");
    let outcome = sim.deliver_next(1).unwrap();
    assert!(!ConversationSim::has_epoch_fingerprint_mismatch(outcome.warnings()));

    // Add Charlie — this creates a commit
    let charlie_session = MoatSession::new();
    let charlie_cred = MoatCredential::new("did:plc:charlie", "Charlie", [0u8; 16]);
    let (charlie_kp, _charlie_kb) = charlie_session.generate_key_package(&charlie_cred).unwrap();

    let welcome_result = sim.participants[0]
        .session
        .add_member(
            &sim.group_id,
            &sim.participants[0].key_bundle,
            &charlie_kp,
        )
        .unwrap();

    // Bob processes the commit
    let commit_outcome = sim.participants[1]
        .session
        .decrypt_event(&sim.group_id, &welcome_result.commit)
        .unwrap();
    assert_eq!(commit_outcome.result().event.kind, EventKind::Commit);

    // After commit, both are at the same epoch — verify by sending another message
    sim.send_message(0, b"Post-commit message");
    let post_outcome = sim.deliver_next(1).unwrap();
    assert!(
        !ConversationSim::has_epoch_fingerprint_mismatch(post_outcome.warnings()),
        "epoch fingerprints should agree after commit"
    );
}

/// Test 10: Divergence detection. Two sessions with different MLS state
/// for the same group_id would produce different epoch fingerprints.
/// We verify this indirectly by checking that the fingerprint is non-trivial
/// and changes across epochs.
#[test]
fn test_epoch_fingerprint_changes_with_epoch() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    // Send a message at epoch N
    sim.send_message(0, b"Epoch N message");
    let outcome1 = sim.deliver_next(1).unwrap();
    let fp1 = outcome1.result().event.epoch_fingerprint.clone().unwrap();

    // Add a third member to advance the epoch
    let charlie_session = MoatSession::new();
    let charlie_cred = MoatCredential::new("did:plc:charlie", "Charlie", [0u8; 16]);
    let (charlie_kp, _charlie_kb) = charlie_session.generate_key_package(&charlie_cred).unwrap();

    let welcome_result = sim.participants[0]
        .session
        .add_member(
            &sim.group_id,
            &sim.participants[0].key_bundle,
            &charlie_kp,
        )
        .unwrap();

    // Bob processes the commit
    sim.participants[1]
        .session
        .decrypt_event(&sim.group_id, &welcome_result.commit)
        .unwrap();

    // Send a message at epoch N+1
    sim.send_message(0, b"Epoch N+1 message");
    let outcome2 = sim.deliver_next(1).unwrap();
    let fp2 = outcome2.result().event.epoch_fingerprint.clone().unwrap();

    // Fingerprints at different epochs should differ
    assert_ne!(fp1, fp2, "epoch fingerprints should differ across epochs");
}
