//! Stateful property-based tests for tag scanning protocol invariants.
//!
//! These tests exercise the full send→scan→match→advance loop using
//! ConversationSim + a TagScanner helper. They verify properties that
//! pure-function proptests cannot catch, such as scanning window
//! advancement, epoch transition behavior, and state persistence.

mod conversation_sim;
use conversation_sim::ConversationSim;
use proptest::prelude::*;
use std::collections::HashSet;

/// Helper that wraps the populate → match → mark_seen cycle for a participant.
struct TagScanner {
    /// Current candidate tags for each participant, indexed by participant index.
    candidates: Vec<HashSet<[u8; 16]>>,
}

impl TagScanner {
    /// Create a new scanner for a conversation with `n` participants.
    fn new(n: usize) -> Self {
        Self {
            candidates: vec![HashSet::new(); n],
        }
    }

    /// Rebuild candidate tags for a specific participant by calling
    /// populate_candidate_tags on their session.
    fn rebuild(&mut self, sim: &ConversationSim, participant: usize) {
        let tags = sim.participants[participant]
            .session
            .populate_candidate_tags(&sim.group_id)
            .unwrap();
        self.candidates[participant] = tags.into_iter().collect();
    }

    /// Rebuild candidate tags for all participants.
    fn rebuild_all(&mut self, sim: &ConversationSim) {
        for i in 0..sim.participants.len() {
            self.rebuild(sim, i);
        }
    }

    /// Check if a tag is in a participant's candidate set.
    fn is_candidate(&self, participant: usize, tag: &[u8; 16]) -> bool {
        self.candidates[participant].contains(tag)
    }

    /// Mark a tag as seen for a participant and rebuild their candidates.
    fn mark_and_rebuild(&mut self, sim: &ConversationSim, participant: usize, tag: &[u8; 16]) {
        let found = sim.participants[participant].session.mark_tag_seen(tag);
        assert!(found, "tag should be in metadata for mark_tag_seen");
        self.rebuild(sim, participant);
    }

    /// Add a slot for a new participant (after add_member_sim).
    fn grow(&mut self) {
        self.candidates.push(HashSet::new());
    }
}

// Smoke test for the TagScanner harness itself
#[test]
fn test_tag_scanner_basic() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);
    let mut scanner = TagScanner::new(2);
    scanner.rebuild_all(&sim);

    let record = sim.send_message(0, b"Hello");
    assert!(scanner.is_candidate(1, &record.tag));
    scanner.mark_and_rebuild(&sim, 1, &record.tag);
}

// --- Group 1: Tag Scanning Window ---

proptest! {
    /// P1: Every encrypted event is scannable by every recipient.
    /// This is the test that would have caught the original missing
    /// mark_tag_seen bug — it fails at message GAP_LIMIT+1 without
    /// proper window advancement.
    #[test]
    fn every_event_is_scannable(
        senders in prop::collection::vec(0usize..2, 1..30),
    ) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        for (msg_idx, &sender) in senders.iter().enumerate() {
            let record = sim.send_message(sender, b"msg");
            let recipient = 1 - sender;

            prop_assert!(
                scanner.is_candidate(recipient, &record.tag),
                "message {} from sender {} not scannable by recipient {}",
                msg_idx, sender, recipient
            );

            // Deliver (MLS decrypt) and mark tag as seen
            sim.deliver_next(recipient).unwrap();
            scanner.mark_and_rebuild(&sim, recipient, &record.tag);
        }
    }

    /// P2: Scanning window advances correctly. After sending N messages
    /// from the same sender and marking each as seen, previously seen
    /// tags should no longer appear in the candidate set.
    #[test]
    fn scanning_window_advances(n_messages in 1usize..20) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        let mut seen_tags = Vec::new();

        for _ in 0..n_messages {
            let record = sim.send_message(0, b"msg");
            sim.deliver_next(1).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &record.tag);
            seen_tags.push(record.tag);
        }

        // After marking all tags as seen, none of them should still be candidates
        for (i, tag) in seen_tags.iter().enumerate() {
            prop_assert!(
                !scanner.is_candidate(1, tag),
                "seen tag at index {} should no longer be a candidate", i
            );
        }
    }

    /// P3: GAP_LIMIT boundary behavior. Send k+gap_limit+extra messages,
    /// mark only the first k. Tags within the window are matchable,
    /// tags beyond it are not.
    #[test]
    fn gap_limit_boundary(
        k_seen in 0usize..5,
        extra in 0usize..10,
    ) {
        let gap_limit = moat_core::TAG_GAP_LIMIT as usize;
        let total = k_seen + gap_limit + extra;

        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        let mut tags = Vec::new();

        // Send all messages
        for _ in 0..total {
            let record = sim.send_message(0, b"msg");
            tags.push(record.tag);
        }

        // Mark only the first k as seen (delivering them to Bob first)
        for i in 0..k_seen {
            sim.deliver_next(1).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &tags[i]);
        }

        // Rebuild to get the current window
        scanner.rebuild(&sim, 1);

        // Tags k_seen .. k_seen+gap_limit should be matchable (within window)
        for i in k_seen..std::cmp::min(k_seen + gap_limit, total) {
            prop_assert!(
                scanner.is_candidate(1, &tags[i]),
                "tag at index {} should be in scan window", i
            );
        }

        // Tags beyond k_seen+gap_limit should NOT be matchable
        for i in (k_seen + gap_limit)..total {
            prop_assert!(
                !scanner.is_candidate(1, &tags[i]),
                "tag at index {} should be OUTSIDE scan window", i
            );
        }
    }

    /// P4: Multi-sender interleaving preserves independent windows.
    /// Marking tags for sender 0 does not affect sender 1's window.
    #[test]
    fn multi_sender_independent_windows(
        senders in prop::collection::vec(0usize..2, 2..20),
    ) {
        let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);
        let mut scanner = TagScanner::new(3);
        scanner.rebuild_all(&sim);

        let mut seen_from_0 = 0usize;
        let mut seen_from_1 = 0usize;

        for &sender in &senders {
            let record = sim.send_message(sender, b"msg");

            // Charlie (participant 2) should be able to scan this tag
            prop_assert!(
                scanner.is_candidate(2, &record.tag),
                "Charlie can't scan sender {}'s message (seen_0={}, seen_1={})",
                sender, seen_from_0, seen_from_1
            );

            // Charlie delivers and marks
            sim.deliver_next(2).unwrap();
            scanner.mark_and_rebuild(&sim, 2, &record.tag);

            if sender == 0 { seen_from_0 += 1; }
            else { seen_from_1 += 1; }

            // Also deliver to the other non-sender to keep MLS in sync
            let other = if sender == 0 { 1 } else { 0 };
            sim.deliver_next(other).unwrap();
        }
    }
}

// --- Group 3: Tag Uniqueness (stateful) ---

proptest! {
    /// P8: No tag collisions within a conversation.
    /// All tags from random senders should be unique.
    #[test]
    fn no_tag_collisions_within_conversation(
        senders in prop::collection::vec(0usize..2, 2..30),
    ) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut tags = HashSet::new();

        for (i, &sender) in senders.iter().enumerate() {
            let record = sim.send_message(sender, b"msg");
            prop_assert!(
                tags.insert(record.tag),
                "tag collision detected at message {}", i
            );
        }
    }
}

// --- Group 2: Epoch Transitions ---

proptest! {
    /// P5: Tags are matchable after epoch advance.
    /// Send messages before and after adding a member (epoch change).
    /// All should be scannable.
    #[test]
    fn tags_matchable_across_epoch_advance(
        n_before in 1usize..10,
        n_after in 1usize..10,
    ) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        // Send n_before messages from Alice, Bob scans and marks
        for _ in 0..n_before {
            let record = sim.send_message(0, b"pre");
            prop_assert!(scanner.is_candidate(1, &record.tag));
            sim.deliver_next(1).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &record.tag);
        }

        // Add Charlie to advance epoch
        let (commit, _, new_idx) = sim.add_member_sim(0, "Charlie");
        scanner.grow();
        sim.deliver_commit_to_all(&commit, &[0, new_idx]);
        scanner.rebuild_all(&sim);

        // Send n_after messages from Alice, Bob scans and marks
        for _ in 0..n_after {
            let record = sim.send_message(0, b"post");
            prop_assert!(
                scanner.is_candidate(1, &record.tag),
                "post-epoch message not scannable"
            );
            sim.deliver_next(1).unwrap();
            // Also deliver to Charlie to keep MLS in sync
            sim.deliver_next(new_idx).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &record.tag);
        }
    }

    /// P6: Counter resets after epoch advance.
    /// The first message in a new epoch should be scannable (counter=0).
    #[test]
    fn counter_resets_after_epoch(n_before in 1usize..10) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        // Send n_before messages to advance sender counter
        for _ in 0..n_before {
            let record = sim.send_message(0, b"msg");
            sim.deliver_next(1).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &record.tag);
        }

        // Advance epoch
        let (commit, _, new_idx) = sim.add_member_sim(0, "Charlie");
        scanner.grow();
        sim.deliver_commit_to_all(&commit, &[0, new_idx]);
        scanner.rebuild_all(&sim);

        // First message in new epoch: if counter didn't reset, it would
        // use counter=n_before, but scanner expects counter=0.
        let record = sim.send_message(0, b"post-epoch");
        prop_assert!(
            scanner.is_candidate(1, &record.tag),
            "first post-epoch message must be scannable (counter should reset to 0)"
        );
    }

    /// P7: Seen counters are epoch-scoped.
    /// After epoch advance, scanning should start from counter=0
    /// regardless of how many messages were seen in the old epoch.
    #[test]
    fn seen_counters_reset_on_epoch_advance(
        n_old in 1usize..10,
        n_new in 1usize..10,
    ) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        // Bob sees n_old messages from Alice in epoch N
        for _ in 0..n_old {
            let record = sim.send_message(0, b"old");
            sim.deliver_next(1).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &record.tag);
        }

        // Advance epoch
        let (commit, _, new_idx) = sim.add_member_sim(0, "Charlie");
        scanner.grow();
        sim.deliver_commit_to_all(&commit, &[0, new_idx]);

        // After epoch advance, Bob rebuilds candidates.
        scanner.rebuild_all(&sim);

        // Alice sends n_new messages in the new epoch (counter 0, 1, ...)
        for _ in 0..n_new {
            let record = sim.send_message(0, b"new");
            prop_assert!(
                scanner.is_candidate(1, &record.tag),
                "post-epoch message should be scannable (seen_counter must reset)"
            );
            sim.deliver_next(1).unwrap();
            sim.deliver_next(new_idx).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &record.tag);
        }
    }
}

/// P10: Tags differ across sender DIDs at same counter value.
#[test]
fn tags_differ_across_senders_at_same_counter() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    let alice_msg = sim.send_message(0, b"hello");
    let bob_msg = sim.send_message(1, b"hello");

    assert_ne!(
        alice_msg.tag, bob_msg.tag,
        "different senders at counter=0 should produce different tags"
    );
}

// --- Group 4: State Persistence ---

proptest! {
    /// P11: Sender counter survives state roundtrip.
    /// After export→import, the next tag should not collide with pre-export tags.
    #[test]
    fn sender_counter_survives_roundtrip(n_messages in 1usize..10) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut pre_tags = HashSet::new();

        // Alice sends n messages
        for _ in 0..n_messages {
            let record = sim.send_message(0, b"msg");
            pre_tags.insert(record.tag);
        }

        // Export and reimport Alice's state
        let state = sim.participants[0].session.export_state().unwrap();
        let restored = moat_core::MoatSession::from_state(&state).unwrap();
        sim.participants[0].session = restored;

        // Alice sends one more message — counter should continue
        let record = sim.send_message(0, b"post-restore");
        prop_assert!(
            !pre_tags.contains(&record.tag),
            "post-restore tag collided with pre-restore tag"
        );
    }

    /// P12: Seen counter survives state roundtrip.
    /// After export→import, the candidate window should be at the same position.
    #[test]
    fn seen_counter_survives_roundtrip(n_messages in 1usize..10) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        // Bob receives and marks n messages
        for _ in 0..n_messages {
            let record = sim.send_message(0, b"msg");
            sim.deliver_next(1).unwrap();
            scanner.mark_and_rebuild(&sim, 1, &record.tag);
        }

        // Capture Bob's candidate set before export
        let candidates_before: HashSet<[u8; 16]> = scanner.candidates[1].clone();

        // Export and reimport Bob's state
        let state = sim.participants[1].session.export_state().unwrap();
        let restored = moat_core::MoatSession::from_state(&state).unwrap();
        sim.participants[1].session = restored;

        // Rebuild candidates after import
        scanner.rebuild(&sim, 1);
        let candidates_after: HashSet<[u8; 16]> = scanner.candidates[1].clone();

        prop_assert_eq!(
            candidates_before, candidates_after,
            "candidate set should be identical after state roundtrip"
        );
    }
}

// --- Group 5: Crash Safety ---

proptest! {
    /// P13: Skipped counter values are harmless within GAP_LIMIT.
    /// Simulate crash-after-increment by calling derive_next_tag without sending.
    #[test]
    fn skipped_counters_within_gap_limit(n_skips in 1usize..5) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        // Simulate n_skips crashed sends: increment counter but don't publish
        for _ in 0..n_skips {
            sim.participants[0]
                .session
                .derive_next_tag(&sim.group_id, &sim.participants[0].key_bundle)
                .unwrap();
        }

        // Now actually send a message (counter = n_skips)
        let record = sim.send_message(0, b"survived crash");

        prop_assert!(
            scanner.is_candidate(1, &record.tag),
            "message after {} skips should be scannable (within GAP_LIMIT)",
            n_skips
        );
    }

    /// P14: Exceeding GAP_LIMIT skips causes scan failure.
    /// The message's tag falls outside the recipient's scanning window.
    #[test]
    fn skips_beyond_gap_limit_fail(n_skips in 5usize..10) {
        let mut sim = ConversationSim::new(&["Alice", "Bob"]);
        let mut scanner = TagScanner::new(2);
        scanner.rebuild_all(&sim);

        // Burn through >= GAP_LIMIT counter values
        for _ in 0..n_skips {
            sim.participants[0]
                .session
                .derive_next_tag(&sim.group_id, &sim.participants[0].key_bundle)
                .unwrap();
        }

        // Next real message uses counter = n_skips (>= GAP_LIMIT)
        let record = sim.send_message(0, b"too far");

        prop_assert!(
            !scanner.is_candidate(1, &record.tag),
            "message after {} skips should NOT be scannable (exceeds GAP_LIMIT)",
            n_skips
        );
    }
}

// --- Group 6: Cross-Conversation Isolation ---

proptest! {
    /// P9: No tag collisions across conversations.
    /// Two independent conversations should produce non-overlapping tag spaces.
    #[test]
    fn no_tag_collisions_across_conversations(
        n_conv1 in 1usize..10,
        n_conv2 in 1usize..10,
    ) {
        let mut sim1 = ConversationSim::new(&["Alice", "Bob"]);
        let mut sim2 = ConversationSim::new(&["Charlie", "Dave"]);

        let mut tags1 = HashSet::new();
        let mut tags2 = HashSet::new();

        for _ in 0..n_conv1 {
            let record = sim1.send_message(0, b"conv1");
            tags1.insert(record.tag);
        }
        for _ in 0..n_conv2 {
            let record = sim2.send_message(0, b"conv2");
            tags2.insert(record.tag);
        }

        let overlap: HashSet<_> = tags1.intersection(&tags2).collect();
        prop_assert!(
            overlap.is_empty(),
            "tags from different conversations should not collide"
        );
    }
}
