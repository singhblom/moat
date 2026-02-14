//! ConversationSim: test harness for multi-party MLS conversations.
//!
//! Simulates a group conversation without network or PDS. Maintains
//! per-participant inboxes that can be delivered, reordered, or dropped.
//! Supports dynamic membership (add/remove) from the start.

use moat_core::{
    ControlKind, DecryptOutcome, Event, EventKind, MoatCredential, MoatSession, TranscriptWarning,
};
use std::collections::VecDeque;

/// A simulated participant with their own MoatSession.
pub struct Participant {
    pub name: String,
    pub session: MoatSession,
    pub credential: MoatCredential,
    pub key_bundle: Vec<u8>,
}

/// A record of an encrypted event in transit.
#[derive(Clone)]
pub struct EventRecord {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub sender_index: usize,
}

/// A simulated conversation between participants.
pub struct ConversationSim {
    pub participants: Vec<Participant>,
    pub group_id: Vec<u8>,
    /// Per-participant inbound event queue (simulates PDS).
    pub inboxes: Vec<VecDeque<EventRecord>>,
}

impl ConversationSim {
    /// Create a new conversation with `n` participants.
    /// The first participant creates the group and adds the rest.
    pub fn new(names: &[&str]) -> Self {
        assert!(names.len() >= 2, "need at least 2 participants");

        let mut participants = Vec::new();
        let mut inboxes = Vec::new();

        // Create all participants with sessions and key packages
        for name in names {
            let session = MoatSession::new();
            let credential = MoatCredential::new(
                &format!("did:plc:{}", name.to_lowercase()),
                *name,
                *session.device_id(),
            );
            let (_kp, kb) = session.generate_key_package(&credential).unwrap();
            participants.push(Participant {
                name: name.to_string(),
                session,
                credential,
                key_bundle: kb,
            });
            inboxes.push(VecDeque::new());
        }

        // First participant creates the group
        let group_id = participants[0]
            .session
            .create_group(&participants[0].credential, &participants[0].key_bundle)
            .unwrap();

        // Add remaining participants one at a time
        for i in 1..participants.len() {
            // Generate a fresh key package for the new member
            let (new_kp, new_kb) = participants[i]
                .session
                .generate_key_package(&participants[i].credential)
                .unwrap();
            participants[i].key_bundle = new_kb;

            // Creator adds new member
            let welcome_result = participants[0]
                .session
                .add_member(&group_id, &participants[0].key_bundle, &new_kp)
                .unwrap();

            // New member processes welcome
            let joined_group_id = participants[i]
                .session
                .process_welcome(&welcome_result.welcome)
                .unwrap();
            assert_eq!(joined_group_id, group_id);

            // Deliver the commit to all existing members (except creator who already merged)
            for j in 1..i {
                let outcome = participants[j]
                    .session
                    .decrypt_event(&group_id, &welcome_result.commit)
                    .unwrap();
                assert!(matches!(
                    outcome.result().event.kind,
                    EventKind::Control(ControlKind::Commit)
                ));
            }
        }

        ConversationSim {
            participants,
            group_id,
            inboxes,
        }
    }

    /// Have participant `sender` send a message. The encrypted event is
    /// placed in all other participants' inboxes.
    pub fn send_message(&mut self, sender: usize, content: &[u8]) -> EventRecord {
        let epoch = self.participants[sender]
            .session
            .get_group_epoch(&self.group_id)
            .unwrap()
            .unwrap();
        let event = Event::message_from_bytes(self.group_id.clone(), epoch, content);
        let encrypted = self.participants[sender]
            .session
            .encrypt_event(
                &self.group_id,
                &self.participants[sender].key_bundle,
                &event,
            )
            .unwrap();

        let record = EventRecord {
            ciphertext: encrypted.ciphertext.clone(),
            tag: encrypted.tag,
            sender_index: sender,
        };

        // Place in all other participants' inboxes
        for i in 0..self.participants.len() {
            if i != sender {
                self.inboxes[i].push_back(record.clone());
            }
        }

        record
    }

    /// Deliver the next event from participant `target`'s inbox.
    /// Returns the DecryptOutcome.
    pub fn deliver_next(&mut self, target: usize) -> Option<DecryptOutcome> {
        let record = self.inboxes[target].pop_front()?;
        let outcome = self.participants[target]
            .session
            .decrypt_event(&self.group_id, &record.ciphertext)
            .unwrap();
        Some(outcome)
    }

    /// Drop the next event from participant `target`'s inbox (simulate withholding).
    pub fn drop_next(&mut self, target: usize) -> Option<EventRecord> {
        self.inboxes[target].pop_front()
    }

    /// Swap the next two events in participant `target`'s inbox (simulate reordering).
    pub fn reorder_next_two(&mut self, target: usize) -> bool {
        if self.inboxes[target].len() < 2 {
            return false;
        }
        self.inboxes[target].swap(0, 1);
        true
    }

    /// Deliver all remaining events for a participant.
    pub fn deliver_all(&mut self, target: usize) -> Vec<DecryptOutcome> {
        let mut results = Vec::new();
        while let Some(outcome) = self.deliver_next(target) {
            results.push(outcome);
        }
        results
    }

    /// Get the inbox length for a participant.
    pub fn inbox_len(&self, target: usize) -> usize {
        self.inboxes[target].len()
    }

    /// Check if a DecryptOutcome has any warnings.
    pub fn has_warnings(outcome: &DecryptOutcome) -> bool {
        !outcome.warnings().is_empty()
    }

    /// Check if warnings contain a HashChainMismatch.
    pub fn has_hash_chain_mismatch(warnings: &[TranscriptWarning]) -> bool {
        warnings
            .iter()
            .any(|w| matches!(w, TranscriptWarning::HashChainMismatch { .. }))
    }

    /// Check if warnings contain a ReplayDetected.
    pub fn has_replay_detected(warnings: &[TranscriptWarning]) -> bool {
        warnings
            .iter()
            .any(|w| matches!(w, TranscriptWarning::ReplayDetected { .. }))
    }

    /// Check if warnings contain an EpochFingerprintMismatch.
    pub fn has_epoch_fingerprint_mismatch(warnings: &[TranscriptWarning]) -> bool {
        warnings
            .iter()
            .any(|w| matches!(w, TranscriptWarning::EpochFingerprintMismatch { .. }))
    }

    /// Check if warnings contain a ConflictRecovered.
    pub fn has_conflict_recovered(warnings: &[TranscriptWarning]) -> bool {
        warnings
            .iter()
            .any(|w| matches!(w, TranscriptWarning::ConflictRecovered { .. }))
    }

    /// Have a participant add a new member to the group.
    /// Returns the commit ciphertext (for delivery to others) and welcome bytes.
    /// The commit is already merged locally for the adder.
    pub fn add_member_sim(&mut self, adder: usize, new_name: &str) -> (Vec<u8>, Vec<u8>, usize) {
        // Create the new participant
        let session = MoatSession::new();
        let credential = MoatCredential::new(
            &format!("did:plc:{}", new_name.to_lowercase()),
            new_name,
            *session.device_id(),
        );
        let (new_kp, new_kb) = session.generate_key_package(&credential).unwrap();
        let new_index = self.participants.len();

        self.participants.push(Participant {
            name: new_name.to_string(),
            session,
            credential,
            key_bundle: new_kb,
        });
        self.inboxes.push(VecDeque::new());

        // Adder adds the new member
        let welcome_result = self.participants[adder]
            .session
            .add_member(
                &self.group_id,
                &self.participants[adder].key_bundle,
                &new_kp,
            )
            .unwrap();

        // New member processes welcome
        let joined = self.participants[new_index]
            .session
            .process_welcome(&welcome_result.welcome)
            .unwrap();
        assert_eq!(joined, self.group_id);

        // Return commit bytes for delivery to others
        (welcome_result.commit, welcome_result.welcome, new_index)
    }

    /// Remove a member by leaf index. Returns commit bytes for delivery.
    pub fn remove_member_sim(&mut self, remover: usize, leaf_index: u32) -> Vec<u8> {
        let result = self.participants[remover]
            .session
            .remove_member(
                &self.group_id,
                &self.participants[remover].key_bundle,
                leaf_index,
            )
            .unwrap();
        result.commit
    }

    /// Deliver a commit to all participants except those in the exclude list.
    /// Typically exclude the adder (who already merged) and the new member
    /// (who processed the welcome).
    pub fn deliver_commit_to_all(&mut self, commit: &[u8], exclude: &[usize]) {
        for i in 0..self.participants.len() {
            if exclude.contains(&i) {
                continue;
            }
            let outcome = self.participants[i]
                .session
                .decrypt_event(&self.group_id, commit)
                .unwrap();
            assert!(matches!(
                outcome.result().event.kind,
                EventKind::Control(ControlKind::Commit)
            ));
        }
    }

    /// Deliver a raw commit to a participant (not from inbox).
    pub fn deliver_commit(
        &mut self,
        target: usize,
        commit: &[u8],
    ) -> moat_core::Result<DecryptOutcome> {
        self.participants[target]
            .session
            .decrypt_event(&self.group_id, commit)
    }
}

// Basic smoke test for the harness itself
#[test]
fn test_conversation_sim_basic() {
    let mut sim = ConversationSim::new(&["Alice", "Bob"]);

    // Alice sends a message
    sim.send_message(0, b"Hello Bob!");

    // Bob receives it
    let outcome = sim.deliver_next(1).unwrap();
    assert!(!ConversationSim::has_warnings(&outcome));
    let result = outcome.into_result();
    assert!(matches!(result.event.kind, EventKind::Message(_)));
    assert_eq!(
        result.event.parse_message_payload().unwrap().preview_text(),
        Some("Hello Bob!".to_string())
    );
}

#[test]
fn test_conversation_sim_three_party() {
    let mut sim = ConversationSim::new(&["Alice", "Bob", "Charlie"]);

    // Alice sends a message
    sim.send_message(0, b"Hello everyone!");

    // Both Bob and Charlie receive it
    let bob_outcome = sim.deliver_next(1).unwrap();
    assert_eq!(
        bob_outcome
            .result()
            .event
            .parse_message_payload()
            .unwrap()
            .preview_text(),
        Some("Hello everyone!".to_string())
    );

    let charlie_outcome = sim.deliver_next(2).unwrap();
    assert_eq!(
        charlie_outcome
            .result()
            .event
            .parse_message_payload()
            .unwrap()
            .preview_text(),
        Some("Hello everyone!".to_string())
    );
}
