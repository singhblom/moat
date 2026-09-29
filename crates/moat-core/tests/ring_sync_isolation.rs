//! A history transfer between two ring devices must not disturb what the
//! other ring members expect from either of them next. Sync frames travel on
//! the pair WebSocket and never reach the PDS, so any per-sender state they
//! advance (tag counter, hash chain, MLS ratchet) desynchronises bystanders.

mod conversation_sim;
use conversation_sim::ConversationSim;
use moat_core::{Event, PairingFrameChannel, SyncRequestSession};

const A: usize = 0;
const C: usize = 2;

/// A's end of a requested-sync transfer with B.
fn sync_channel() -> PairingFrameChannel {
    let mut session = SyncRequestSession::request([1; 16], [2; 16], 0);
    session.on_channel_up().unwrap();
    session.transfer_channel().unwrap()
}

/// Seal one sync frame the way a requested-sync transfer does, without
/// publishing it.
fn seal_sync_frame(channel: &mut PairingFrameChannel) {
    channel.seal(b"{}");
}

fn publish_ring_msg(sim: &ConversationSim, sender: usize) -> moat_core::EncryptResult {
    let p = &sim.participants[sender];
    let epoch = p.session.get_group_epoch(&sim.group_id).unwrap().unwrap();
    let ev = Event::ring_msg(sim.group_id.clone(), epoch, b"{}".to_vec());
    p.session
        .encrypt_event(&sim.group_id, &p.key_bundle, &ev)
        .unwrap()
}

#[test]
fn sync_frames_leave_the_next_ring_tag_in_the_siblings_window() {
    let sim = ConversationSim::new(&["A", "B", "C"]);
    let mut channel = sync_channel();
    let c_tags = sim.participants[C]
        .session
        .populate_candidate_tags(&sim.group_id, &[])
        .unwrap();

    for _ in 0..12 {
        seal_sync_frame(&mut channel);
    }
    let published = publish_ring_msg(&sim, A);

    assert!(c_tags.contains(&published.tag));
}

#[test]
fn sync_frames_leave_the_hash_chain_intact() {
    let sim = ConversationSim::new(&["A", "B", "C"]);
    let mut channel = sync_channel();
    // C needs a link from A to check the next one against.
    let first = publish_ring_msg(&sim, A);
    sim.participants[C]
        .session
        .decrypt_event(&sim.group_id, &first.ciphertext)
        .unwrap();

    for _ in 0..12 {
        seal_sync_frame(&mut channel);
    }
    let published = publish_ring_msg(&sim, A);
    let outcome = sim.participants[C]
        .session
        .decrypt_event(&sim.group_id, &published.ciphertext)
        .unwrap();

    assert!(
        !ConversationSim::has_hash_chain_mismatch(outcome.warnings()),
        "{:?}",
        outcome.warnings()
    );
}

/// OpenMLS refuses a message more than 1000 generations ahead of the last
/// one the receiver saw from that sender.
#[test]
fn a_long_sync_leaves_the_next_ring_msg_decryptable() {
    let sim = ConversationSim::new(&["A", "B", "C"]);
    let mut channel = sync_channel();

    for _ in 0..1100 {
        seal_sync_frame(&mut channel);
    }
    let published = publish_ring_msg(&sim, A);

    sim.participants[C]
        .session
        .decrypt_event(&sim.group_id, &published.ciphertext)
        .unwrap();
}
