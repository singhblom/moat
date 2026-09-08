//! Sync-request session: the user-initiated "sync my history" gesture
//! between two devices that are already ring members.
//!
//! Onboarding history sync rides the pairing channel and is covered by
//! `pairing_simulation.rs`. This is the *other* case: a device that is
//! already in the ring but is missing history — because the sibling it
//! paired with didn't hold it, because a conversation reached it as a
//! membership-only `UserConvWelcome` after its pairing sync had finished,
//! or because a transfer was interrupted and the pairing channel's secret
//! is gone. The user asks for it explicitly, and a sibling's user
//! approves, exactly as with pairing: the human is the sequencer.

use moat_core::sync_request::{
    decode_ring_msg, encode_ring_msg, RingMsg, SyncFailure, SyncRequestSession,
    SyncRequestUiState, SYNC_REQUEST_TTL_MS,
};
use moat_core::SyncTally;

fn token(b: u8) -> [u8; 16] {
    [b; 16]
}

fn tally(messages: u64, conversations: u64) -> SyncTally {
    SyncTally { messages, conversations }
}

// ── Wire codec ────────────────────────────────────────────────────────────────

#[test]
fn ring_msg_roundtrips_through_json() {
    let msg = RingMsg::SyncRequest { token: token(7), target_device_id: None };
    let decoded = decode_ring_msg(&encode_ring_msg(&msg)).expect("decode");
    match decoded {
        RingMsg::SyncRequest { token: t, .. } => assert_eq!(t, token(7)),
        other => panic!("expected SyncRequest, got {other:?}"),
    }
}

#[test]
fn ring_msg_rejects_garbage() {
    assert!(decode_ring_msg(b"not json at all").is_err());
}

#[test]
fn ring_msg_rejects_a_wrong_length_token() {
    // A 15-byte token must not silently truncate or pad into a valid message.
    let json = br#"{"type":"sync_request","token":"AAAAAAAAAAAAAAAAAAAA"}"#;
    assert!(decode_ring_msg(json).is_err());
}

// ── Requester side ────────────────────────────────────────────────────────────

#[test]
fn a_fresh_session_reports_idle() {
    assert_eq!(SyncRequestSession::ui_state_of(None), SyncRequestUiState::Idle);
}

#[test]
fn requesting_publishes_a_token_and_awaits_a_peer() {
    let session = SyncRequestSession::request(token(1), 1_000);
    assert_eq!(session.token(), &token(1));
    assert_eq!(session.ui_state(), SyncRequestUiState::AwaitingPeer);
}

#[test]
fn a_requester_becomes_active_when_the_channel_comes_up() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.on_channel_up().expect("channel up");
    assert_eq!(session.ui_state(), SyncRequestUiState::Active);
}

#[test]
fn a_completed_session_reports_complete() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.on_channel_up().expect("channel up");
    session.on_complete(tally(412, 6), Some("Pixel 8".to_string()));
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Complete {
            tally: tally(412, 6),
            device_name: Some("Pixel 8".to_string()),
        }
    );
}

/// A sync that moved nothing is the outcome that tells the user to try a
/// different device, so it has to be distinguishable from one that moved
/// everything — not merely "complete".
#[test]
fn a_session_that_transferred_nothing_says_so() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.on_channel_up().expect("channel up");
    session.on_complete(SyncTally::default(), Some("Laptop".to_string()));
    match session.ui_state() {
        SyncRequestUiState::Complete { tally, .. } => assert!(tally.is_empty()),
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn a_request_expires_on_the_relay_token_ttl() {
    let session = SyncRequestSession::request(token(1), 1_000);
    assert!(!session.is_expired(1_000 + SYNC_REQUEST_TTL_MS - 1));
    assert!(session.is_expired(1_000 + SYNC_REQUEST_TTL_MS));
}

#[test]
fn an_active_session_does_not_expire_mid_transfer() {
    // The TTL bounds the *rendezvous*, not the transfer: a large history
    // can legitimately take longer than the relay's token lifetime.
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.on_channel_up().expect("channel up");
    assert!(!session.is_expired(1_000 + SYNC_REQUEST_TTL_MS * 10));
}

// ── Responder side ────────────────────────────────────────────────────────────

#[test]
fn an_incoming_request_prompts_with_the_authenticated_device_name() {
    // The name comes from the MLS leaf credential of the sender, not from
    // the payload — the payload carries only the rendezvous token.
    let session = SyncRequestSession::received(token(2), "Alice's laptop".into(), 5_000);
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::AwaitingApproval { device_name: "Alice's laptop".into() }
    );
}

#[test]
fn accepting_yields_the_token_to_join_the_rendezvous_with() {
    let mut session = SyncRequestSession::received(token(2), "Alice's laptop".into(), 5_000);
    let joined = session.accept().expect("accept");
    assert_eq!(joined, token(2));
    assert_eq!(session.ui_state(), SyncRequestUiState::AwaitingPeer);
}

#[test]
fn declining_is_terminal_and_local() {
    // No wire message: with several siblings prompted, one decline must not
    // cancel the requester's outstanding request.
    let mut session = SyncRequestSession::received(token(2), "Alice's laptop".into(), 5_000);
    session.decline();
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Failed { reason: SyncFailure::Declined }
    );
    assert!(session.accept().is_err(), "a declined session must not be acceptable");
}

#[test]
fn accepting_twice_is_refused() {
    let mut session = SyncRequestSession::received(token(2), "Alice's laptop".into(), 5_000);
    session.accept().expect("first accept");
    assert!(session.accept().is_err(), "second accept must be refused");
}

#[test]
fn an_unanswered_prompt_expires_with_the_token() {
    let session = SyncRequestSession::received(token(2), "Alice's laptop".into(), 5_000);
    assert!(session.is_expired(5_000 + SYNC_REQUEST_TTL_MS));
}

// ── Terminal-state discipline (mirrors PairingSession) ────────────────────────

#[test]
fn failure_retains_its_reason() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.fail(SyncFailure::PublishFailed { detail: "relay refused".into() });
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Failed {
            reason: SyncFailure::PublishFailed { detail: "relay refused".into() }
        }
    );
}

#[test]
fn a_later_failure_does_not_overwrite_a_completed_session() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.on_channel_up().expect("channel up");
    session.on_complete(tally(3, 1), Some("Laptop".to_string()));
    session.fail(SyncFailure::ChannelClosed { detail: "late teardown".into() });
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Complete {
            tally: tally(3, 1),
            device_name: Some("Laptop".to_string()),
        }
    );
}

#[test]
fn a_later_failure_does_not_overwrite_an_earlier_one() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.fail(SyncFailure::NoAnswer);
    session.fail(SyncFailure::Declined);
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Failed { reason: SyncFailure::NoAnswer }
    );
}

// ── The answer deadline ───────────────────────────────────────────────────────

#[test]
fn an_unanswered_request_fails_once_its_token_expires() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    assert!(!session.expire_if_due(1_000 + SYNC_REQUEST_TTL_MS - 1));
    assert_eq!(session.ui_state(), SyncRequestUiState::AwaitingPeer);

    assert!(session.expire_if_due(1_000 + SYNC_REQUEST_TTL_MS));
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Failed { reason: SyncFailure::NoAnswer },
        "the device that asked hears that nobody answered"
    );
}

#[test]
fn an_unanswered_prompt_fails_once_its_token_expires() {
    // The responder side times out too: a prompt whose token has died must
    // not still offer to send, since the rendezvous can no longer be joined.
    let mut session = SyncRequestSession::received(token(2), "Alice's laptop".into(), 5_000);
    assert!(session.expire_if_due(5_000 + SYNC_REQUEST_TTL_MS));
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Failed { reason: SyncFailure::RequestExpired },
        "the prompted device hears that the request expired, not that \
         'no device answered' — it is the device with the history"
    );
    assert!(
        session.accept().is_err(),
        "an expired prompt must not be acceptable"
    );
}

#[test]
fn a_transfer_in_progress_is_never_expired() {
    // Only the rendezvous is bounded. A large history can legitimately take
    // longer to move than the relay allows for *finding* a peer.
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.on_channel_up().expect("channel up");
    assert!(!session.expire_if_due(1_000 + SYNC_REQUEST_TTL_MS * 10));
    assert_eq!(session.ui_state(), SyncRequestUiState::Active);
}

#[test]
fn expiry_does_not_overwrite_a_completed_session() {
    let mut session = SyncRequestSession::request(token(1), 1_000);
    session.on_channel_up().expect("channel up");
    session.on_complete(tally(3, 1), Some("Laptop".to_string()));
    assert!(!session.expire_if_due(1_000 + SYNC_REQUEST_TTL_MS * 10));
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Complete {
            tally: tally(3, 1),
            device_name: Some("Laptop".to_string()),
        }
    );
}

#[test]
fn expiring_twice_reports_the_change_only_once() {
    // Hosts call this from a periodic tick, so a second call must be a
    // no-op rather than a fresh state change to react to.
    let mut session = SyncRequestSession::request(token(1), 1_000);
    let now = 1_000 + SYNC_REQUEST_TTL_MS;
    assert!(session.expire_if_due(now));
    assert!(!session.expire_if_due(now));
}

// ── The history advertisement ────────────────────────────────────────────────

use moat_core::{
    decode_history_summary, encode_history_summary, ConvInventory, ConvSummary,
    DeviceRingState, HistorySummaryPayload,
};

fn summary(count: u64) -> ConvSummary {
    ConvSummary {
        group_id: vec![7u8; 16],
        inventory: ConvInventory::Range {
            oldest: "3lkzq7xk2ps2n".to_string(),
            newest: "3lkzq7xk2pt4m".to_string(),
            count,
        },
    }
}

#[test]
fn a_history_summary_roundtrips_through_its_blob() {
    let payload = HistorySummaryPayload { convs: vec![summary(412), summary(3)] };
    let restored = decode_history_summary(&encode_history_summary(&payload)).unwrap();
    assert_eq!(restored, payload);
    assert_eq!(restored.total_messages(), 415);
    assert!(!restored.is_empty());
}

/// The case a sibling should *offer* to fill: a device that advertises
/// nothing is a fresh one.
#[test]
fn a_device_holding_nothing_advertises_an_empty_summary() {
    assert!(HistorySummaryPayload::default().is_empty());
    assert!(HistorySummaryPayload { convs: vec![] }.is_empty());
    assert!(HistorySummaryPayload {
        convs: vec![ConvSummary {
            group_id: vec![1u8; 16],
            inventory: ConvInventory::Empty
        }]
    }
    .is_empty());
}

/// The advertisement is a hint, not a log: only the newest matters, so a
/// second one replaces the first outright.
#[test]
fn a_new_advertisement_replaces_the_previous_one() {
    let mut driver = DeviceRingState::default();
    let device = [3u8; 16];

    driver.record_sibling_summary(&device, vec![summary(10)], 1_000);
    assert_eq!(driver.sibling_summary(&device).unwrap().total_messages(), 10);

    driver.record_sibling_summary(&device, vec![summary(90)], 2_000);
    let held = driver.sibling_summary(&device).unwrap();
    assert_eq!(held.total_messages(), 90);
    assert_eq!(held.received_at_ms, 2_000);
}

/// §2.4's whole fix: a summary the user has dismissed must not re-prompt
/// on every launch — but a sibling that now says something *different* is
/// asking a different question, and the old "no thanks" does not answer
/// it.
#[test]
fn dismissal_survives_a_repeat_but_not_a_change() {
    let mut driver = DeviceRingState::default();
    let device = [3u8; 16];

    driver.record_sibling_summary(&device, vec![summary(10)], 1_000);
    driver.dismiss_sibling_summary(&device);
    assert!(driver.sibling_summary(&device).unwrap().dismissed);

    // The same advertisement again — a poll re-reading what it already
    // saw — must not resurrect the prompt.
    driver.record_sibling_summary(&device, vec![summary(10)], 2_000);
    assert!(
        driver.sibling_summary(&device).unwrap().dismissed,
        "re-seeing an advertisement is not the sibling saying something new"
    );

    // Different contents: worth asking about again.
    driver.record_sibling_summary(&device, vec![summary(400)], 3_000);
    assert!(
        !driver.sibling_summary(&device).unwrap().dismissed,
        "a sibling that now holds more is a new question"
    );
}

/// Exactly one summary per device stays live, or they accumulate on the
/// PDS forever. The *record* is what gets deleted — the PDS collects the
/// blob once nothing references it.
#[test]
fn the_superseded_summary_record_is_remembered_for_deletion() {
    let mut driver = DeviceRingState::default();
    assert_eq!(driver.published_summary_record(), None);

    let first = "at://did:plc:alice/social.moat.event/3lkzq7xk2ps2n";
    let second = "at://did:plc:alice/social.moat.event/3lkzq7xk2pt4m";

    driver.set_published_summary_record(Some(first.to_string()));
    assert_eq!(driver.published_summary_record(), Some(first));

    driver.set_published_summary_record(Some(second.to_string()));
    assert_eq!(
        driver.published_summary_record(),
        Some(second),
        "the reference must move on so the next publish deletes the right record"
    );
}

// ── The offer direction ──────────────────────────────────────────────────────

/// A request may name one sibling. Siblings that are named but are not the
/// target ignore it rather than prompting about someone else's business.
#[test]
fn a_targeted_request_roundtrips_with_its_target() {
    let msg = RingMsg::SyncRequest {
        token: token(4),
        target_device_id: Some([9u8; 16]),
    };
    let decoded = decode_ring_msg(&encode_ring_msg(&msg)).expect("decode");
    assert_eq!(decoded, msg);
}

/// A broadcast is still a broadcast: `None` means every sibling prompts,
/// which is what the gesture did before targeting existed.
#[test]
fn an_untargeted_request_carries_no_target() {
    let msg = RingMsg::SyncRequest { token: token(4), target_device_id: None };
    let decoded = decode_ring_msg(&encode_ring_msg(&msg)).expect("decode");
    assert_eq!(decoded, msg);
}

/// An offer is always targeted: the relay admits exactly two attaches, so
/// an untargeted offer would make the winner arbitrary.
#[test]
fn an_offer_roundtrips_with_its_target() {
    let msg = RingMsg::SyncOffer {
        token: token(5),
        target_device_id: [3u8; 16],
    };
    let decoded = decode_ring_msg(&encode_ring_msg(&msg)).expect("decode");
    assert_eq!(decoded, msg);
}

/// Exactly one human approval per session, on the side that can judge.
/// The offerer has already approved, so the recipient joins without a
/// prompt — a second one would ask the user to approve receiving their
/// own messages.
#[test]
fn accepting_an_offer_needs_no_approval_phase() {
    let session = SyncRequestSession::accept_offer(token(5), 1_000);
    assert_eq!(session.ui_state(), SyncRequestUiState::AwaitingPeer);
}

/// The offerer published a rendezvous and is waiting for the target to
/// join it, so an unanswered offer reads the way an unanswered request
/// does — from the perspective of the device that did the asking.
#[test]
fn an_unanswered_offer_reads_as_nobody_answering() {
    let mut session = SyncRequestSession::offer(token(5), 1_000);
    assert!(session.expire_if_due(1_000 + SYNC_REQUEST_TTL_MS));
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Failed { reason: SyncFailure::NoAnswer }
    );
}

/// The receiving side of an offer reads it as its own deadline, the same
/// as a device that was prompted and never answered.
#[test]
fn an_offer_the_recipient_never_joins_expires_on_its_side_too() {
    let mut session = SyncRequestSession::accept_offer(token(5), 1_000);
    assert!(session.expire_if_due(1_000 + SYNC_REQUEST_TTL_MS));
    assert_eq!(
        session.ui_state(),
        SyncRequestUiState::Failed { reason: SyncFailure::RequestExpired }
    );
}

// ── Deciding when to prompt ──────────────────────────────────────────────────

/// The trigger for the offer direction: a device that just joined
/// advertises holding nothing, and the device in the user's hand can fix
/// it. Prompting promptly is the point.
#[test]
fn a_sibling_that_advertised_less_is_worth_offering_to() {
    let mut driver = DeviceRingState::default();
    let empty_device = [1u8; 16];
    driver.record_sibling_summary(&empty_device, vec![summary(0)], 1_000);

    assert_eq!(driver.offerable_siblings(50), vec![empty_device]);
}

/// Silence is not an invitation: a device that has said nothing might
/// hold everything.
#[test]
fn a_sibling_that_never_advertised_is_not_offered_to() {
    let driver = DeviceRingState::default();
    assert!(driver.offerable_siblings(50).is_empty());
}

/// Offering what the other side already has is a prompt with nothing
/// behind it.
#[test]
fn a_sibling_holding_as_much_is_not_offered_to() {
    let mut driver = DeviceRingState::default();
    driver.record_sibling_summary(&[2u8; 16], vec![summary(50)], 1_000);
    assert!(driver.offerable_siblings(50).is_empty());

    let mut richer = DeviceRingState::default();
    richer.record_sibling_summary(&[2u8; 16], vec![summary(90)], 1_000);
    assert!(richer.offerable_siblings(50).is_empty());
}

/// The whole point of the dismissal flag: a declined prompt must not come
/// back on the next launch, or people learn to dismiss reflexively and
/// the mechanism defeats itself.
#[test]
fn a_dismissed_advertisement_stops_prompting() {
    let mut driver = DeviceRingState::default();
    let device = [3u8; 16];
    driver.record_sibling_summary(&device, vec![summary(0)], 1_000);
    assert_eq!(driver.offerable_siblings(50), vec![device]);

    driver.dismiss_sibling_summary(&device);
    assert!(
        driver.offerable_siblings(50).is_empty(),
        "a prompt the user declined must not return on the next app open"
    );

    // …but a sibling that now says something different is asking a
    // different question, and the old refusal does not answer it.
    driver.record_sibling_summary(&device, vec![summary(2)], 2_000);
    assert_eq!(
        driver.offerable_siblings(50),
        vec![device],
        "a changed advertisement is a new question"
    );
}

/// A host that prompts about "the first one" must not pick a different
/// device on each launch.
#[test]
fn the_offerable_order_is_stable() {
    let mut driver = DeviceRingState::default();
    driver.record_sibling_summary(&[9u8; 16], vec![summary(0)], 1_000);
    driver.record_sibling_summary(&[1u8; 16], vec![summary(0)], 1_000);
    driver.record_sibling_summary(&[5u8; 16], vec![summary(0)], 1_000);

    assert_eq!(
        driver.offerable_siblings(50),
        vec![[1u8; 16], [5u8; 16], [9u8; 16]]
    );
}
