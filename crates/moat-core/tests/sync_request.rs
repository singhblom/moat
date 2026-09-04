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

fn token(b: u8) -> [u8; 16] {
    [b; 16]
}

// ── Wire codec ────────────────────────────────────────────────────────────────

#[test]
fn ring_msg_roundtrips_through_json() {
    let msg = RingMsg::SyncRequest { token: token(7) };
    let decoded = decode_ring_msg(&encode_ring_msg(&msg)).expect("decode");
    match decoded {
        RingMsg::SyncRequest { token: t } => assert_eq!(t, token(7)),
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
    session.on_complete();
    assert_eq!(session.ui_state(), SyncRequestUiState::Complete);
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
    session.on_complete();
    session.fail(SyncFailure::ChannelClosed { detail: "late teardown".into() });
    assert_eq!(session.ui_state(), SyncRequestUiState::Complete);
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
    session.on_complete();
    assert!(!session.expire_if_due(1_000 + SYNC_REQUEST_TTL_MS * 10));
    assert_eq!(session.ui_state(), SyncRequestUiState::Complete);
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
