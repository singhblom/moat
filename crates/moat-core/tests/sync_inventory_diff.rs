//! Inventory-based delta planning for history sync.
//!
//! Before this, a sync session transferred a peer's entire history for
//! every conversation and relied on rkey dedupe at the storage layer to
//! absorb the overlap. That is correct but wasteful, and it is wrong in
//! one direction that matters: `oldest_rkey`/`newest_rkey` alone cannot
//! describe a hole in the *middle* of a device's history, which is
//! exactly what a device that was offline past the ring's usable epoch
//! window ends up with.
//!
//! So each side declares the rkeys it holds per conversation and the peer
//! sends the complement. No digests, no anchors, no bisection: an
//! inventory is ~13 bytes per message, against the messages themselves.

use moat_core::{ConvState, MoatSession, SyncMessage, SyncMsg, SyncOutput, SyncSession};

fn msg(rkey: &str) -> SyncMessage {
    SyncMessage {
        rkey: rkey.to_string(),
        message_id: None,
        sender_did: "did:plc:alice".to_string(),
        sender_device_name: "laptop".to_string(),
        timestamp_ms: 0,
        content: format!("content of {rkey}"),
        is_own: true,
        blob_uri: None,
        blob_key: None,
        blob_ciphertext_hash: None,
        blob_ciphertext_size: None,
        blob_content_hash: None,
        blob_mime: None,
        blob_width: None,
        blob_height: None,
    }
}

/// A `ConvState` declaring an explicit inventory.
fn state_with(group_id: &[u8], rkeys: &[&str]) -> ConvState {
    let rkeys: Vec<String> = rkeys.iter().map(|r| r.to_string()).collect();
    ConvState {
        group_id: group_id.to_vec(),
        oldest_rkey: rkeys.iter().min().cloned(),
        newest_rkey: rkeys.iter().max().cloned(),
        tip_digest: vec![0u8; 32],
        anchors: vec![],
        rkeys: Some(rkeys),
    }
}

/// A `ConvState` from a peer that declined to send an inventory (over the
/// cap, or an older build).
fn state_without_inventory(group_id: &[u8], oldest: &str, newest: &str) -> ConvState {
    ConvState {
        group_id: group_id.to_vec(),
        oldest_rkey: Some(oldest.to_string()),
        newest_rkey: Some(newest.to_string()),
        tip_digest: vec![0u8; 32],
        anchors: vec![],
        rkeys: None,
    }
}

fn sent_batches(outs: &[SyncOutput]) -> Vec<&SyncMsg> {
    outs.iter()
        .filter_map(|o| match o {
            SyncOutput::Send(m @ SyncMsg::Batch { .. }) => Some(m),
            _ => None,
        })
        .collect()
}

fn batch_rkeys(msg: &SyncMsg) -> Vec<String> {
    match msg {
        SyncMsg::Batch { messages, .. } => messages.iter().map(|m| m.rkey.clone()).collect(),
        _ => panic!("not a batch"),
    }
}

fn batch_req_count(outs: &[SyncOutput]) -> usize {
    outs.iter()
        .filter(|o| matches!(o, SyncOutput::Send(SyncMsg::BatchReq { .. })))
        .count()
}

// ── Donor side: send only what the peer lacks ─────────────────────────────────

#[test]
fn a_donor_withholds_messages_the_peer_already_holds() {
    let mls = MoatSession::new();
    let g = vec![1u8; 32];

    let mut donor = SyncSession::new();
    donor.add_conv_plan(
        g.clone(),
        hex::encode(&g),
        vec![msg("r1"), msg("r2"), msg("r3"), msg("r4")],
        false,
    );
    let _ = donor.on_paired(vec![state_with(&g, &["r1", "r2", "r3", "r4"])], 0);

    // Peer holds r1 and r2 already.
    let _ = donor.on_message(
        &mls,
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1", "r2"])], ring_epoch: 0 },
        "did:plc:alice",
    );
    let outs = donor.on_message(
        &mls,
        SyncMsg::BatchReq { group_id: g.clone(), from_rkey: None, to_rkey: None, cursor: None },
        "did:plc:alice",
    );

    let batches = sent_batches(&outs);
    assert_eq!(batches.len(), 1, "expected one batch, got {}", batches.len());
    assert_eq!(
        batch_rkeys(batches[0]),
        vec!["r3".to_string(), "r4".to_string()],
        "only the messages the peer lacks should be sent"
    );
}

#[test]
fn a_donor_fills_a_hole_in_the_middle_of_the_peers_history() {
    // The case `oldest_rkey`/`newest_rkey` cannot express: the peer's range
    // spans r1..r5 and yet r3 is missing from it.
    let mls = MoatSession::new();
    let g = vec![2u8; 32];

    let mut donor = SyncSession::new();
    donor.add_conv_plan(
        g.clone(),
        hex::encode(&g),
        vec![msg("r1"), msg("r2"), msg("r3"), msg("r4"), msg("r5")],
        false,
    );
    let _ = donor.on_paired(vec![state_with(&g, &["r1", "r2", "r3", "r4", "r5"])], 0);
    let _ = donor.on_message(
        &mls,
        SyncMsg::Hello {
            convs: vec![state_with(&g, &["r1", "r2", "r4", "r5"])],
            ring_epoch: 0,
        },
        "did:plc:alice",
    );
    let outs = donor.on_message(
        &mls,
        SyncMsg::BatchReq { group_id: g.clone(), from_rkey: None, to_rkey: None, cursor: None },
        "did:plc:alice",
    );

    let batches = sent_batches(&outs);
    assert_eq!(batch_rkeys(batches[0]), vec!["r3".to_string()]);
}

#[test]
fn a_donor_without_a_peer_inventory_sends_everything() {
    // Fallback path: no inventory declared, so the donor cannot compute a
    // complement and must not guess from the range.
    let mls = MoatSession::new();
    let g = vec![3u8; 32];

    let mut donor = SyncSession::new();
    donor.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1"), msg("r2")], false);
    let _ = donor.on_paired(vec![state_with(&g, &["r1", "r2"])], 0);
    let _ = donor.on_message(
        &mls,
        SyncMsg::Hello { convs: vec![state_without_inventory(&g, "r1", "r1")], ring_epoch: 0 },
        "did:plc:alice",
    );
    let outs = donor.on_message(
        &mls,
        SyncMsg::BatchReq { group_id: g.clone(), from_rkey: None, to_rkey: None, cursor: None },
        "did:plc:alice",
    );

    assert_eq!(
        batch_rkeys(sent_batches(&outs)[0]),
        vec!["r1".to_string(), "r2".to_string()],
        "with no inventory to diff against, the whole history is served"
    );
}

// ── Requester side: ask only when there is something to ask for ───────────────

#[test]
fn no_request_is_sent_when_the_peer_holds_nothing_new() {
    let mls = MoatSession::new();
    let g = vec![4u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1"), msg("r2")], false);
    let _ = s.on_paired(vec![state_with(&g, &["r1", "r2"])], 0);

    let outs = s.on_message(
        &mls,
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1", "r2"])], ring_epoch: 0 },
        "did:plc:alice",
    );
    assert_eq!(
        batch_req_count(&outs),
        0,
        "identical inventories mean there is nothing to transfer"
    );
}

#[test]
fn two_identical_devices_complete_without_transferring_anything() {
    let mls = MoatSession::new();
    let g = vec![5u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1")], false);
    let _ = s.on_paired(vec![state_with(&g, &["r1"])], 0);
    let outs = s.on_message(
        &mls,
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1"])], ring_epoch: 0 },
        "did:plc:alice",
    );

    assert!(
        outs.iter().any(|o| matches!(o, SyncOutput::Complete)),
        "a session with no delta in either direction is finished on the spot"
    );
    assert!(s.is_done());
}

#[test]
fn a_request_is_sent_when_the_peer_holds_something_we_lack() {
    let mls = MoatSession::new();
    let g = vec![6u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1")], false);
    let _ = s.on_paired(vec![state_with(&g, &["r1"])], 0);

    let outs = s.on_message(
        &mls,
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1", "r2"])], ring_epoch: 0 },
        "did:plc:alice",
    );
    assert_eq!(batch_req_count(&outs), 1, "r2 is missing locally, so ask for it");
}

#[test]
fn a_conversation_the_peer_alone_knows_about_is_still_requested() {
    // The membership-only `UserConvWelcome` case: a sibling fanned us into
    // a conversation after our pairing sync had already finished, so we
    // hold the group but not one message of its history.
    let mls = MoatSession::new();
    let ours = vec![7u8; 32];
    let theirs = vec![8u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(ours.clone(), hex::encode(&ours), vec![msg("r1")], false);
    let _ = s.on_paired(vec![state_with(&ours, &["r1"])], 0);

    let outs = s.on_message(
        &mls,
        SyncMsg::Hello {
            convs: vec![state_with(&ours, &["r1"]), state_with(&theirs, &["r9"])],
            ring_epoch: 0,
        },
        "did:plc:alice",
    );
    assert_eq!(batch_req_count(&outs), 1, "the unknown conversation must be requested");
}

// ── Both directions at once ───────────────────────────────────────────────────

#[test]
fn each_side_serves_the_other_in_the_same_session() {
    // The bidirectional case the design has always described: a laptop with
    // deep old history and a phone with a recent week converge on the union
    // in one session, each acting as donor and recipient at once.
    let mls = MoatSession::new();
    let g = vec![9u8; 32];

    let mut laptop = SyncSession::new();
    laptop.add_conv_plan(
        g.clone(),
        hex::encode(&g),
        vec![msg("r1"), msg("r2"), msg("r3")],
        false,
    );
    let _ = laptop.on_paired(vec![state_with(&g, &["r1", "r2", "r3"])], 0);

    // Phone holds r3 and the newer r4, r5.
    let outs = laptop.on_message(
        &mls,
        SyncMsg::Hello { convs: vec![state_with(&g, &["r3", "r4", "r5"])], ring_epoch: 0 },
        "did:plc:alice",
    );
    assert_eq!(batch_req_count(&outs), 1, "the laptop wants r4 and r5");

    let outs = laptop.on_message(
        &mls,
        SyncMsg::BatchReq { group_id: g.clone(), from_rkey: None, to_rkey: None, cursor: None },
        "did:plc:alice",
    );
    assert_eq!(
        batch_rkeys(sent_batches(&outs)[0]),
        vec!["r1".to_string(), "r2".to_string()],
        "and serves the phone only r1 and r2"
    );
}
