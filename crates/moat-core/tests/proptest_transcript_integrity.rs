//! Property-based tests for transcript integrity.
//!
//! These tests verify that hash chain and epoch fingerprint mechanisms
//! maintain their invariants across randomized message sequences.

mod conversation_sim;
use conversation_sim::ConversationSim;
use moat_core::MoatSession;
use proptest::prelude::*;

/// Property 1: Hash chain detects withholding.
/// For any sequence of N messages from Alice, if we deliver all except one
/// to Bob, the message after the gap should trigger a HashChainMismatch.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn hash_chain_detects_withholding(
        msg_count in 3u8..8,
        drop_index in 1u8..7,
    ) {
        let drop_index = (drop_index as usize) % ((msg_count as usize) - 1);
        // Ensure drop_index is at least 1 and at most msg_count-2
        // (drop a middle message so there's a message after the gap)
        let drop_index = drop_index.max(1).min((msg_count as usize) - 2);

        let mut sim = ConversationSim::new(&["Alice", "Bob"]);

        // Alice sends N messages
        for i in 0..msg_count {
            sim.send_message(0, format!("msg-{}", i).as_bytes());
        }

        // Bob receives messages, but we drop one at drop_index
        let mut saw_mismatch = false;
        for i in 0..msg_count as usize {
            if i == drop_index {
                sim.drop_next(1);
                continue;
            }
            let outcome = sim.deliver_next(1).unwrap();
            if ConversationSim::has_hash_chain_mismatch(outcome.warnings()) {
                saw_mismatch = true;
            }
        }

        prop_assert!(saw_mismatch, "withholding message {} of {} should trigger mismatch", drop_index, msg_count);
    }
}

/// Property 2: Hash chain detects reordering.
/// For any sequence of messages, swapping two adjacent messages should be detected.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn hash_chain_detects_reordering(
        msg_count in 3u8..8,
        swap_at in 0u8..6,
    ) {
        let swap_at = (swap_at as usize) % ((msg_count as usize) - 1);

        let mut sim = ConversationSim::new(&["Alice", "Bob"]);

        // Alice sends messages
        for i in 0..msg_count {
            sim.send_message(0, format!("msg-{}", i).as_bytes());
        }

        // Deliver messages before the swap normally
        for _ in 0..swap_at {
            sim.deliver_next(1).unwrap();
        }

        // Swap the next two
        sim.reorder_next_two(1);

        // Deliver remaining messages
        let mut saw_mismatch = false;
        let remaining = (msg_count as usize) - swap_at;
        for _ in 0..remaining {
            let outcome = sim.deliver_next(1).unwrap();
            if ConversationSim::has_hash_chain_mismatch(outcome.warnings()) {
                saw_mismatch = true;
            }
        }

        prop_assert!(saw_mismatch, "reordering at position {} of {} should trigger mismatch", swap_at, msg_count);
    }
}

/// Property 3: Epoch fingerprint agreement.
/// For any number of messages at the same epoch, sender and receiver
/// should always agree on the epoch fingerprint (no mismatches on clean delivery).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn epoch_fingerprint_agrees_on_clean_delivery(msg_count in 1u8..6) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);

        for i in 0..msg_count {
            sim.send_message(0, format!("msg-{}", i).as_bytes());
        }

        for _ in 0..msg_count {
            let outcome = sim.deliver_next(1).unwrap();
            prop_assert!(
                !ConversationSim::has_epoch_fingerprint_mismatch(outcome.warnings()),
                "epoch fingerprint should agree on clean delivery"
            );
        }
    }
}

/// Property 4: Multi-sender hash chains are independent.
/// Messages from different senders should not interfere with each other's
/// hash chain validation when delivered in send order.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn multi_sender_chains_independent(
        alice_msgs in 1u8..4,
        bob_msgs in 1u8..4,
    ) {
        let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

        // Interleave messages from Alice and Bob
        let total = alice_msgs.max(bob_msgs);
        for i in 0..total {
            if i < alice_msgs {
                sim.send_message(0, format!("alice-{}", i).as_bytes());
            }
            if i < bob_msgs {
                sim.send_message(1, format!("bob-{}", i).as_bytes());
            }
        }

        // Charlie receives all in order — no warnings
        let total_msgs = (alice_msgs + bob_msgs) as usize;
        for _ in 0..total_msgs {
            let outcome = sim.deliver_next(2).unwrap();
            prop_assert!(
                !ConversationSim::has_warnings(&outcome),
                "interleaved multi-sender delivery should produce no warnings"
            );
        }
    }
}

/// Property 5: Export/import preserves hash chain state.
/// After exporting and re-importing state, the hash chain should still
/// validate correctly (no spurious mismatches).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn export_import_preserves_hash_chains(msg_count in 1u8..4) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);

        // Alice sends some messages, Bob receives them
        for i in 0..msg_count {
            sim.send_message(0, format!("msg-{}", i).as_bytes());
            let outcome = sim.deliver_next(1).unwrap();
            prop_assert!(!ConversationSim::has_warnings(&outcome));
        }

        // Export and re-import Bob's state
        let state = sim.participants[1].session.export_state().unwrap();
        let restored = MoatSession::from_state(&state).unwrap();
        sim.participants[1].session = restored;

        // Alice sends another message
        sim.send_message(0, format!("msg-after-restore").as_bytes());
        let outcome = sim.deliver_next(1).unwrap();

        // Hash chain should still validate (no mismatch)
        prop_assert!(
            !ConversationSim::has_hash_chain_mismatch(outcome.warnings()),
            "hash chain should be preserved across export/import"
        );
    }
}

/// Property 6: Epoch fingerprint changes with epoch advancement.
/// After a commit advances the epoch, messages at the new epoch should
/// still have matching fingerprints between sender and receiver.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn fingerprint_consistent_after_epoch_change(
        pre_commit_msgs in 1u8..3,
        post_commit_msgs in 1u8..3,
    ) {
        let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

        // Send some messages at initial epoch
        for i in 0..pre_commit_msgs {
            sim.send_message(0, format!("pre-{}", i).as_bytes());
            let outcome = sim.deliver_next(1).unwrap();
            prop_assert!(!ConversationSim::has_epoch_fingerprint_mismatch(outcome.warnings()));
            // Also deliver to Charlie
            sim.deliver_next(2).unwrap();
        }

        // Alice adds Dave (advances epoch)
        let (commit, _welcome, _dave_idx) = sim.add_member_sim(0, "Dave");
        sim.deliver_commit(1, &commit).unwrap();
        sim.deliver_commit(2, &commit).unwrap();

        // Send messages at new epoch
        for i in 0..post_commit_msgs {
            sim.send_message(0, format!("post-{}", i).as_bytes());
            let outcome = sim.deliver_next(1).unwrap();
            prop_assert!(
                !ConversationSim::has_epoch_fingerprint_mismatch(outcome.warnings()),
                "fingerprint should agree at new epoch"
            );
            sim.deliver_next(2).unwrap();
        }
    }
}
