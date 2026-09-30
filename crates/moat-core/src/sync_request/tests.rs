use super::*;
use crate::SyncTally;

const SECRET: [u8; 16] = [0x5e; 16];
const TOKEN: [u8; 16] = [0x01; 16];
const T0: i64 = 1_000;

fn requested() -> SyncRequestSession {
    SyncRequestSession::request(TOKEN, SECRET, T0)
}

fn received() -> SyncRequestSession {
    SyncRequestSession::received(TOKEN, SECRET, "laptop".into(), T0)
}

fn failed(reason: SyncFailure) -> SyncRequestUiState {
    SyncRequestUiState::Failed { reason }
}

fn complete() -> SyncRequestUiState {
    SyncRequestUiState::Complete {
        tally: SyncTally {
            messages: 3,
            conversations: 1,
            ..SyncTally::default()
        },
        device_name: Some("laptop".into()),
    }
}

fn completed() -> SyncRequestSession {
    let mut session = requested();
    session.on_channel_up().unwrap();
    session.on_complete(
        SyncTally {
            messages: 3,
            conversations: 1,
            ..SyncTally::default()
        },
        Some("laptop".into()),
    );
    session
}

// ── Wire codec ───────────────────────────────────────────────────────────────

#[test]
fn ring_msgs_roundtrip() {
    for msg in [
        RingMsg::SyncRequest {
            token: TOKEN,
            secret: SECRET,
            target_device_id: None,
        },
        RingMsg::SyncRequest {
            token: TOKEN,
            secret: SECRET,
            target_device_id: Some([9; 16]),
        },
        RingMsg::SyncOffer {
            token: TOKEN,
            secret: SECRET,
            target_device_id: [3; 16],
        },
    ] {
        assert_eq!(decode_ring_msg(&encode_ring_msg(&msg)).unwrap(), msg);
    }
}

/// A 15-byte token must not truncate or pad into a valid message.
#[test]
fn a_ring_msg_with_a_short_token_is_rejected() {
    let json = br#"{"type":"sync_request","token":"AAAAAAAAAAAAAAAAAAAA"}"#;
    assert!(decode_ring_msg(json).is_err());
}

// ── Answering ────────────────────────────────────────────────────────────────

/// Local only: with several siblings prompted, one decline must not cancel
/// the requester's request.
#[test]
fn a_declined_request_cannot_be_accepted() {
    let mut session = received();
    session.decline();
    assert_eq!(session.ui_state(), failed(SyncFailure::Declined));
    assert!(session.accept().is_err());
}

#[test]
fn accepting_twice_is_refused() {
    let mut session = received();
    session.accept().unwrap();
    assert!(session.accept().is_err());
}

// ── The answer deadline ──────────────────────────────────────────────────────

#[test]
fn an_unanswered_request_fails_as_no_answer_once_its_token_expires() {
    let mut session = requested();
    assert!(!session.expire_if_due(T0 + SYNC_REQUEST_TTL_MS - 1));
    assert_eq!(session.ui_state(), SyncRequestUiState::AwaitingPeer);

    assert!(session.expire_if_due(T0 + SYNC_REQUEST_TTL_MS));
    assert_eq!(session.ui_state(), failed(SyncFailure::NoAnswer));
}

/// The prompted device holds the history, so it hears that the request
/// expired rather than that nobody answered.
#[test]
fn an_unanswered_prompt_fails_as_expired_and_cannot_be_accepted() {
    let mut session = received();
    assert!(session.expire_if_due(T0 + SYNC_REQUEST_TTL_MS));
    assert_eq!(session.ui_state(), failed(SyncFailure::RequestExpired));
    assert!(session.accept().is_err());
}

#[test]
fn an_offer_the_recipient_never_joins_expires_on_its_side_too() {
    let mut session = SyncRequestSession::accept_offer(TOKEN, SECRET, T0);
    assert!(session.expire_if_due(T0 + SYNC_REQUEST_TTL_MS));
    assert_eq!(session.ui_state(), failed(SyncFailure::RequestExpired));
}

/// Only the rendezvous is bounded; a large history can take longer to move.
#[test]
fn a_transfer_in_progress_never_expires() {
    let mut session = requested();
    session.on_channel_up().unwrap();
    assert!(!session.expire_if_due(T0 + SYNC_REQUEST_TTL_MS * 10));
    assert_eq!(session.ui_state(), SyncRequestUiState::Active);
}

/// Driven from a periodic tick, so there is exactly one edge to react to.
#[test]
fn expiring_twice_reports_the_change_only_once() {
    let mut session = requested();
    assert!(session.expire_if_due(T0 + SYNC_REQUEST_TTL_MS));
    assert!(!session.expire_if_due(T0 + SYNC_REQUEST_TTL_MS));
}

// ── Terminal states ──────────────────────────────────────────────────────────

/// The relay closes the channel right after a successful sync.
#[test]
fn a_later_failure_does_not_overwrite_a_completed_session() {
    let mut session = completed();
    session.fail(SyncFailure::ChannelClosed {
        detail: "late teardown".into(),
    });
    assert_eq!(session.ui_state(), complete());
}

#[test]
fn a_later_failure_does_not_overwrite_an_earlier_one() {
    let mut session = requested();
    session.fail(SyncFailure::NoAnswer);
    session.fail(SyncFailure::Declined);
    assert_eq!(session.ui_state(), failed(SyncFailure::NoAnswer));
}

// ── The transfer channel ─────────────────────────────────────────────────────

#[test]
fn the_channel_is_handed_out_once_and_only_once_up() {
    let mut session = requested();
    assert!(
        session.transfer_channel().is_none(),
        "not before the channel is up"
    );
    session.on_channel_up().unwrap();
    assert!(session.transfer_channel().is_some());
    assert!(
        session.transfer_channel().is_none(),
        "a second copy would reuse nonces"
    );
}
