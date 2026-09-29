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

use moat_core::{
    fit_hello_inventories, ConvInventory, ConvState, MoatSession, SyncMessage, SyncMsg,
    SyncOutput, SyncSession, HELLO_INVENTORY_BUDGET_BYTES,
};

fn msg(rkey: &str) -> SyncMessage {
    SyncMessage {
        rkey: rkey.to_string(),
        message_id: None,
        sender_did: "did:plc:alice".to_string(),
        sender_device_name: "laptop".to_string(),
        timestamp_ms: 0,
        content: format!("content of {rkey}"),
        blob_uri: None,
        blob_key: None,
        blob_ciphertext_hash: None,
        blob_ciphertext_size: None,
        blob_content_hash: None,
        blob_mime: None,
        blob_width: None,
        blob_height: None,
        blob_thumbhash: None,
        reactions: Vec::new(),
    }
}

/// A `ConvState` enumerating exactly what its side holds.
fn state_with(group_id: &[u8], rkeys: &[&str]) -> ConvState {
    ConvState {
        group_id: group_id.to_vec(),
        inventory: ConvInventory::of(rkeys.iter().map(|r| r.to_string()).collect()),
    }
}

/// A `ConvState` from a peer whose list did not fit the Hello budget, so
/// it declared only its span.
fn state_with_range(group_id: &[u8], oldest: &str, newest: &str, count: u64) -> ConvState {
    ConvState {
        group_id: group_id.to_vec(),
        inventory: ConvInventory::Range {
            oldest: oldest.to_string(),
            newest: newest.to_string(),
            count,
        },
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
    let g = vec![1u8; 32];

    let mut donor = SyncSession::new();
    donor.add_conv_plan(
        g.clone(),
        hex::encode(&g),
        vec![msg("r1"), msg("r2"), msg("r3"), msg("r4")]);
    let _ = donor.on_paired(vec![state_with(&g, &["r1", "r2", "r3", "r4"])], [0; 16]);

    // Peer holds r1 and r2 already.
    let _ = donor.on_message(
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1", "r2"])], device_id: [0; 16] },
    ).unwrap();
    let outs = donor.on_message(
        SyncMsg::BatchReq { group_id: g.clone(), cursor: None },
    ).unwrap();

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
    let g = vec![2u8; 32];

    let mut donor = SyncSession::new();
    donor.add_conv_plan(
        g.clone(),
        hex::encode(&g),
        vec![msg("r1"), msg("r2"), msg("r3"), msg("r4"), msg("r5")]);
    let _ = donor.on_paired(vec![state_with(&g, &["r1", "r2", "r3", "r4", "r5"])], [0; 16]);
    let _ = donor.on_message(
        SyncMsg::Hello {
            convs: vec![state_with(&g, &["r1", "r2", "r4", "r5"])],
            device_id: [0; 16],
        },
    ).unwrap();
    let outs = donor.on_message(
        SyncMsg::BatchReq { group_id: g.clone(), cursor: None },
    ).unwrap();

    let batches = sent_batches(&outs);
    assert_eq!(batch_rkeys(batches[0]), vec!["r3".to_string()]);
}

#[test]
fn a_donor_serves_outside_a_peers_declared_span() {
    // Fallback path: no inventory declared, so the donor cannot compute a
    // complement and must not guess from the range.
    let g = vec![3u8; 32];

    let mut donor = SyncSession::new();
    donor.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1"), msg("r2")]);
    let _ = donor.on_paired(vec![state_with(&g, &["r1", "r2"])], [0; 16]);
    let _ = donor.on_message(
        SyncMsg::Hello { convs: vec![state_with_range(&g, "r1", "r1", 1)], device_id: [0; 16] },
    ).unwrap();
    let outs = donor.on_message(
        SyncMsg::BatchReq { group_id: g.clone(), cursor: None },
    ).unwrap();

    assert_eq!(
        batch_rkeys(sent_batches(&outs)[0]),
        vec!["r2".to_string()],
        "only what falls outside the peer's span is served — a span cannot \
         reveal holes inside itself, but it still narrows the transfer"
    );
}

// ── Requester side: ask only when there is something to ask for ───────────────

#[test]
fn no_request_is_sent_when_the_peer_holds_nothing_new() {
    let g = vec![4u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1"), msg("r2")]);
    let _ = s.on_paired(vec![state_with(&g, &["r1", "r2"])], [0; 16]);

    let outs = s.on_message(
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1", "r2"])], device_id: [0; 16] },
    ).unwrap();
    assert_eq!(
        batch_req_count(&outs),
        0,
        "identical inventories mean there is nothing to transfer"
    );
}

#[test]
fn two_identical_devices_complete_without_transferring_anything() {
    let g = vec![5u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1")]);
    let _ = s.on_paired(vec![state_with(&g, &["r1"])], [0; 16]);
    let outs = s.on_message(
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1"])], device_id: [0; 16] },
    ).unwrap();

    assert!(
        matches!(outs.as_slice(), [SyncOutput::Send(SyncMsg::Fin)]),
        "with no delta in either direction the only thing to say is Fin"
    );
    let _ = s.on_message(SyncMsg::Fin).unwrap();
    assert!(s.is_done(), "the peer's Fin finishes a session with no delta");
}

#[test]
fn a_request_is_sent_when_the_peer_holds_something_we_lack() {
    let g = vec![6u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1")]);
    let _ = s.on_paired(vec![state_with(&g, &["r1"])], [0; 16]);

    let outs = s.on_message(
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1", "r2"])], device_id: [0; 16] },
    ).unwrap();
    assert_eq!(batch_req_count(&outs), 1, "r2 is missing locally, so ask for it");
}

#[test]
fn a_conversation_the_peer_alone_knows_about_is_still_requested() {
    // The membership-only `UserConvWelcome` case: a sibling fanned us into
    // a conversation after our pairing sync had already finished, so we
    // hold the group but not one message of its history.
    let ours = vec![7u8; 32];
    let theirs = vec![8u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(ours.clone(), hex::encode(&ours), vec![msg("r1")]);
    let _ = s.on_paired(vec![state_with(&ours, &["r1"])], [0; 16]);

    let outs = s.on_message(
        SyncMsg::Hello {
            convs: vec![state_with(&ours, &["r1"]), state_with(&theirs, &["r9"])],
            device_id: [0; 16],
        },
    ).unwrap();
    assert_eq!(batch_req_count(&outs), 1, "the unknown conversation must be requested");
}

// ── Both directions at once ───────────────────────────────────────────────────

#[test]
fn each_side_serves_the_other_in_the_same_session() {
    // The bidirectional case the design has always described: a laptop with
    // deep old history and a phone with a recent week converge on the union
    // in one session, each acting as donor and recipient at once.
    let g = vec![9u8; 32];

    let mut laptop = SyncSession::new();
    laptop.add_conv_plan(
        g.clone(),
        hex::encode(&g),
        vec![msg("r1"), msg("r2"), msg("r3")]);
    let _ = laptop.on_paired(vec![state_with(&g, &["r1", "r2", "r3"])], [0; 16]);

    // Phone holds r3 and the newer r4, r5.
    let outs = laptop.on_message(
        SyncMsg::Hello { convs: vec![state_with(&g, &["r3", "r4", "r5"])], device_id: [0; 16] },
    ).unwrap();
    assert_eq!(batch_req_count(&outs), 1, "the laptop wants r4 and r5");

    let outs = laptop.on_message(
        SyncMsg::BatchReq { group_id: g.clone(), cursor: None },
    ).unwrap();
    assert_eq!(
        batch_rkeys(sent_batches(&outs)[0]),
        vec!["r1".to_string(), "r2".to_string()],
        "and serves the phone only r1 and r2"
    );
}

#[test]
fn a_session_with_no_conversations_does_not_declare_itself_complete() {
    // `check_complete` folds over the plan list, so an empty list is
    // vacuously "all done". Reporting `Complete` here makes the host close
    // the pair channel — and a host that opened a plan-less session while
    // another was mid-transfer would truncate it. Having nothing to offer
    // is not the same as the exchange being finished.
    let g = vec![1u8; 32];

    let mut s = SyncSession::new();
    let outs = s.on_paired(vec![], [0; 16]);
    assert!(!s.is_done());
    assert_eq!(outs.len(), 1, "just the Hello");

    let outs = s.on_message(
        SyncMsg::Hello { convs: vec![state_with(&g, &["r1"])], device_id: [0; 16] },
    ).unwrap();
    assert!(
        !s.is_done(),
        "a session that knows about no conversations must not declare itself \
         finished on the strength of an empty plan list — the host closes \
         the channel when it does"
    );
    assert_eq!(
        batch_req_count(&outs),
        1,
        "and it should adopt the peer's conversation rather than ignore it"
    );
}

// ── The Hello frame budget ────────────────────────────────────────────────────
//
// The pair WS closes the connection outright on a frame over 1 MiB, and a
// Hello carries every conversation at once. A per-conversation cap guards
// the wrong dimension: many mid-sized conversations blow the frame while
// none of them is individually large.

#[test]
fn a_small_hello_keeps_every_inventory_intact() {
    let mut convs: Vec<ConvState> = (0..5u8)
        .map(|i| state_with(&[i; 32], &["r1", "r2", "r3"]))
        .collect();
    fit_hello_inventories(&mut convs);
    assert!(
        convs
            .iter()
            .all(|c| matches!(c.inventory, ConvInventory::Complete { .. })),
        "nothing should be downgraded when the whole frame fits"
    );
}

#[test]
fn an_oversized_hello_is_brought_under_budget() {
    // Fifty conversations of two thousand messages: no single conversation
    // is remarkable, and together they are far past the frame limit.
    let mut convs: Vec<ConvState> = (0..50u8)
        .map(|i| {
            let rkeys: Vec<String> = (0..2000).map(|n| format!("3l6yq2{i:02}{n:06}")).collect();
            ConvState {
                group_id: vec![i; 32],
                inventory: ConvInventory::of(rkeys),
            }
        })
        .collect();

    let before: usize = convs.iter().map(encoded_len).sum();
    assert!(
        before > HELLO_INVENTORY_BUDGET_BYTES,
        "the fixture must actually be over budget to be testing anything"
    );

    fit_hello_inventories(&mut convs);

    let after: usize = convs.iter().map(encoded_len).sum();
    assert!(
        after <= HELLO_INVENTORY_BUDGET_BYTES,
        "still {after} bytes after fitting, budget is {HELLO_INVENTORY_BUDGET_BYTES}"
    );
    assert!(
        convs
            .iter()
            .any(|c| matches!(c.inventory, ConvInventory::Range { .. })),
        "fitting happens by downgrading to spans, not by dropping conversations"
    );
    assert_eq!(convs.len(), 50, "no conversation may be dropped outright");
    assert!(
        convs.iter().all(|c| !c.inventory.is_empty()),
        "a downgraded conversation must not come out looking empty — the \
         peer would then think we hold nothing and send us everything"
    );
}

#[test]
fn fitting_downgrades_the_largest_first() {
    // Fewest conversations lose precision.
    let big: Vec<String> = (0..60_000).map(|n| format!("bigbigbig{n:06}")).collect();
    let mut convs = vec![
        state_with(&[1u8; 32], &["r1", "r2"]),
        ConvState {
            group_id: vec![2u8; 32],
            inventory: ConvInventory::of(big),
        },
    ];
    fit_hello_inventories(&mut convs);

    assert!(
        matches!(convs[0].inventory, ConvInventory::Complete { .. }),
        "the small conversation keeps its enumeration"
    );
    assert!(
        matches!(convs[1].inventory, ConvInventory::Range { .. }),
        "the one actually costing the bytes is the one that gives them up"
    );
}

/// Mirrors the budgeting cost model closely enough to assert against.
fn encoded_len(c: &ConvState) -> usize {
    match &c.inventory {
        ConvInventory::Complete { rkeys } => rkeys.iter().map(|r| r.len() + 3).sum::<usize>() + 32,
        ConvInventory::Range { oldest, newest, .. } => oldest.len() + newest.len() + 64,
        ConvInventory::Empty => 16,
    }
}

// ── What the session reports at the end ──────────────────────────────────────

/// The session counts what it took, so a host does not have to. Both
/// runtimes then report the same number from the same events, which is
/// the whole reason this lives in core rather than twice in the hosts.
#[test]
fn a_session_counts_the_messages_and_conversations_it_received() {
    let a = vec![1u8; 32];
    let b = vec![2u8; 32];

    let mut s = SyncSession::new();
    s.add_conv_plan(a.clone(), hex::encode(&a), vec![]);
    s.add_conv_plan(b.clone(), hex::encode(&b), vec![]);
    let _ = s.on_paired(vec![], [0; 16]);
    let _ = s
        .on_message(SyncMsg::Hello {
            convs: vec![state_with(&a, &["r1", "r2"]), state_with(&b, &["r9"])],
            device_id: [0; 16],
        })
        .unwrap();

    assert_eq!(s.tally().messages, 0, "nothing has arrived yet");

    let _ = s
        .on_message(SyncMsg::Batch {
            group_id: a.clone(),
            messages: vec![msg("r1"), msg("r2")],
            next_cursor: None,
            total: 2,
        })
        .unwrap();
    let _ = s
        .on_message(SyncMsg::Batch {
            group_id: b.clone(),
            messages: vec![msg("r9")],
            next_cursor: None,
            total: 1,
        })
        .unwrap();

    let tally = s.tally();
    assert_eq!(tally.messages, 3);
    assert_eq!(tally.conversations, 2);
}

/// Two devices that already agree exchange nothing, and the report has to
/// say that rather than looking like any other completed sync — it is the
/// result that means "ask a different device".
#[test]
fn a_session_that_moves_nothing_reports_an_empty_tally() {
    let g = vec![7u8; 32];
    let mut s = SyncSession::new();
    s.add_conv_plan(g.clone(), hex::encode(&g), vec![msg("r1")]);
    let _ = s.on_paired(vec![], [0; 16]);
    let _ = s
        .on_message(SyncMsg::Hello {
            convs: vec![state_with(&g, &["r1"])],
            device_id: [0; 16],
        })
        .unwrap();
    let _ = s.on_message(SyncMsg::Fin).unwrap();

    assert!(s.is_done(), "identical inventories finish on one exchange of Fins");
    assert_eq!(s.tally().messages, 0);
    assert_eq!(s.tally().conversations, 0);
}

// ── The Hello frame against the wire that carries it ─────────────────────────

/// A PDS record has no bucket to round an oversized payload up to.
#[test]
fn a_pds_bound_event_still_refuses_to_exceed_its_bucket() {
    let session = MoatSession::new();
    let credential = moat_core::MoatCredential::new("did:plc:alice", "laptop", [1u8; 16]);
    let (_kp, key_bundle) = session.generate_key_package(&credential).unwrap();
    let group_id = session.create_group(&credential, &key_bundle).unwrap();

    let event = moat_core::Event::ring_msg(group_id.clone(), 7, vec![0x42; 20_000]);
    match session.encrypt_event(&group_id, &key_bundle, &event) {
        Err(moat_core::Error::PayloadTooLarge(_)) => {}
        Err(other) => panic!("expected PayloadTooLarge, got {other:?}"),
        Ok(_) => panic!("an oversized PDS record has no bucket to round up to"),
    }
}
