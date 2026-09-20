//! Unit tests for `PairingSession` message-ordering violations.
//!
//! These describe protocol-level misuse that the driver must reject with a
//! structured error rather than panic, hang, or silently do the wrong
//! thing.

use moat_core::{
    encode_pairing_msg, seal_frame, Admit, MoatCredential, MoatSession, PairingCommand,
    PairingMsg, PairingPayload, PairingSession, PairingUiState,
};

const SECRET: [u8; 16] = [0xAA; 16];
const TOKEN: [u8; 16] = [0xBB; 16];

fn new_device_payload() -> PairingPayload {
    PairingPayload {
        secret: SECRET,
        token: TOKEN,
    }
}

fn new_device() -> (MoatSession, MoatCredential, Vec<u8>) {
    let mls = MoatSession::new();
    let credential = MoatCredential::new("did:plc:alice", "Alice's Phone", *mls.device_id());
    let (_kp, key_bundle) = mls.generate_key_package(&credential).unwrap();
    (mls, credential, key_bundle)
}

#[test]
fn new_device_session_starts_not_done() {
    let session = PairingSession::new_device(&new_device_payload());
    assert!(
        !session.is_done(),
        "a freshly constructed session must not report done before any exchange"
    );
}

#[test]
fn existing_device_session_has_no_pending_enroll_before_receiving_one() {
    let session = PairingSession::existing_device(&SECRET, &TOKEN);
    assert!(
        session.pending_enroll().is_none(),
        "there is nothing to approve before an Enroll has arrived"
    );
}

#[test]
fn existing_device_approve_without_enroll_is_rejected() {
    let (mls, credential, key_bundle) = new_device();
    let mut session = PairingSession::existing_device(&SECRET, &TOKEN);

    let result = session.approve(&mls, &credential, &key_bundle, [0u8; 32], &[], None);

    assert!(
        result.is_err(),
        "approve() before any Enroll has been received must be rejected, \
         not silently create/mutate a ring"
    );
}

#[test]
fn new_device_rejects_admit_frame_before_sending_enroll() {
    let (mls_new, _credential_new, _kb_new) = new_device();
    let mut new_session = PairingSession::new_device(&new_device_payload());

    // An (unsolicited) Admit-shaped frame, sealed as if the existing device
    // had sent it — but the new device never sent Enroll, so this must be
    // rejected as an out-of-order message rather than processed as a real
    // Welcome.
    let keys = moat_core::derive_pairing_keys(&SECRET, &TOKEN);
    let bogus_admit = PairingMsg::Admit(Admit {
        ring_id: vec![1, 2, 3],
        welcome: vec![9, 9, 9],
        roster: vec![],
    });
    let plaintext = encode_pairing_msg(&bogus_admit);
    let ciphertext = seal_frame(&keys.k_old_to_new, 0, &plaintext);

    let result = new_session.on_frame_received(&mls_new, &_credential_new, &ciphertext);

    assert!(
        result.is_err(),
        "Admit received before Enroll was ever sent is an ordering violation"
    );
}

#[test]
fn existing_device_rejects_a_second_enroll_while_awaiting_approval() {
    let (mls_existing, credential_existing, kb_existing) = new_device();
    let (mls_new, credential_new, kb_new) = new_device();
    let mut new_session = PairingSession::new_device(&new_device_payload());
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);

    let enroll_cmds = new_session
        .start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    let enroll_frame = enroll_cmds
        .iter()
        .find_map(|c| match c {
            PairingCommand::SendFrame { ciphertext } => Some(ciphertext.clone()),
            _ => None,
        })
        .expect("start_enroll must emit a SendFrame command");

    // First Enroll: accepted, session moves to AwaitingApproval.
    existing_session
        .on_frame_received(&mls_existing, &credential_existing, &enroll_frame)
        .expect("first Enroll must be accepted");
    assert!(existing_session.pending_enroll().is_some());

    // A second Enroll arrives before the user has approved the first. It
    // must not silently replace the pending approval — the peer's approval
    // decision applies to the specific Enroll it saw on screen. Sealed at
    // counter 1 (the correct next position in the sender's stream, reusing
    // the same Enroll content) so this exercises the "second Enroll while
    // pending" guard at the protocol layer, not the replay/counter guard —
    // a fresh session reseals at counter 0, which the receiver's replay
    // check must already reject before the protocol layer ever sees a
    // "second Enroll while pending" at all.
    let keys = moat_core::derive_pairing_keys(&SECRET, &TOKEN);
    let enroll_plaintext = moat_core::open_frame(&keys.k_new_to_old, 0, &enroll_frame)
        .expect("the first Enroll frame must open under its own keys");
    let second_enroll_frame = moat_core::seal_frame(&keys.k_new_to_old, 1, &enroll_plaintext);

    let result =
        existing_session.on_frame_received(&mls_existing, &credential_existing, &second_enroll_frame);
    assert!(
        result.is_err(),
        "a second Enroll while one is already pending approval must be rejected"
    );

    // kb_existing kept in scope for symmetry with the paired-session tests
    // in pairing_simulation.rs.
    let _ = kb_existing;
}

#[test]
fn did_mismatch_between_enroll_and_the_channel_owner_is_a_hard_abort() {
    // A pairing code is per-account, so an Enroll claiming a different DID
    // than the existing device's own must never be approvable — DID
    // equality is a hard abort, not a warning.
    let (mls_existing, credential_existing, _kb_existing) = new_device();
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);

    let mls_attacker = MoatSession::new();
    let attacker_credential =
        MoatCredential::new("did:plc:mallory", "Mallory's Phone", *mls_attacker.device_id());
    let (_kp, kb_attacker) = mls_attacker.generate_key_package(&attacker_credential).unwrap();
    let mut attacker_session = PairingSession::new_device(&new_device_payload());

    let enroll_cmds = attacker_session
        .start_enroll(&mls_attacker, &attacker_credential, &kb_attacker, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    let enroll_frame = enroll_cmds
        .iter()
        .find_map(|c| match c {
            PairingCommand::SendFrame { ciphertext } => Some(ciphertext.clone()),
            _ => None,
        })
        .expect("start_enroll must emit a SendFrame command");

    let result =
        existing_session.on_frame_received(&mls_existing, &credential_existing, &enroll_frame);
    assert!(
        result.is_err(),
        "an Enroll for a different DID than the existing device's own must be rejected outright"
    );
}

#[test]
fn new_device_rejects_admit_whose_welcome_lands_it_in_a_foreign_dids_ring() {
    // The mirror image of `did_mismatch_between_enroll_and_the_channel_owner_is_a_hard_abort`:
    // a malicious or misrouted Admit could carry a real, validly-signed MLS
    // Welcome — just for the wrong ring. There is no `did` field on
    // `Admit`/`SiblingInfo` to check up front (see `SiblingInfo`'s docs);
    // the new device's only anchor is the ring's own MLS member
    // credentials, available only after it actually processes the
    // Welcome. This pins that post-Welcome check as a hard abort too.
    let mls_new = MoatSession::new();
    let credential_new =
        MoatCredential::new("did:plc:alice", "Alice's Phone", *mls_new.device_id());
    let (new_device_kp, kb_new) = mls_new.generate_key_package(&credential_new).unwrap();

    let mut new_session = PairingSession::new_device(&new_device_payload());
    new_session
        .start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");

    // A ring under a completely different DID adds the new device's real
    // KeyPackage directly at the MLS layer (`add_member`, not
    // `PairingSession::approve` — the driver is unimplemented, and this
    // test only needs a real Welcome, not the pairing exchange that would
    // produce one).
    let mls_rogue = MoatSession::new();
    let credential_rogue =
        MoatCredential::new("did:plc:mallory", "Mallory's Laptop", *mls_rogue.device_id());
    let (_rogue_kp, kb_rogue) = mls_rogue.generate_key_package(&credential_rogue).unwrap();
    let rogue_ring_id = mls_rogue
        .create_device_ring(&credential_rogue, &kb_rogue)
        .expect("create rogue ring");
    let welcome_result = mls_rogue
        .add_member(&rogue_ring_id, &kb_rogue, &new_device_kp)
        .expect("rogue ring adds the new device's real KP");

    let admit = PairingMsg::Admit(Admit {
        ring_id: rogue_ring_id,
        welcome: welcome_result.welcome,
        roster: vec![],
    });
    let plaintext = encode_pairing_msg(&admit);
    let keys = moat_core::derive_pairing_keys(&SECRET, &TOKEN);
    let ciphertext = seal_frame(&keys.k_old_to_new, 0, &plaintext);

    let result = new_session.on_frame_received(&mls_new, &credential_new, &ciphertext);

    assert!(
        result.is_err(),
        "an Admit whose Welcome lands the new device in a ring under a \
         different DID than its own must be rejected outright"
    );
}

// ─── PairingUiState ──────────────────────────────────────────────────────

fn find_send_frame(cmds: &[PairingCommand]) -> Vec<u8> {
    cmds.iter()
        .find_map(|c| match c {
            PairingCommand::SendFrame { ciphertext } => Some(ciphertext.clone()),
            _ => None,
        })
        .expect("expected a SendFrame command in this batch")
}

#[test]
fn full_ui_state_sequence_for_both_roles() {
    let (mls_new, credential_new, kb_new) = new_device();
    let (mls_existing, credential_existing, _kb_existing) = new_device();

    let mut new_session = PairingSession::new_device(&new_device_payload());
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);

    // New device: ShowingCode from construction, unchanged by start_enroll.
    match new_session.ui_state() {
        PairingUiState::ShowingCode { code, uri } => {
            assert!(!code.is_empty());
            assert!(uri.starts_with("moat-pair:"));
        }
        other => panic!("expected ShowingCode before start_enroll, got {other:?}"),
    }
    // Existing device: AwaitingPeer from construction.
    assert_eq!(existing_session.ui_state(), PairingUiState::AwaitingPeer);

    let enroll_cmds = new_session
        .start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    let enroll_frame = find_send_frame(&enroll_cmds);
    assert!(
        matches!(new_session.ui_state(), PairingUiState::ShowingCode { .. }),
        "the code stays displayed while Enroll is in flight"
    );

    existing_session
        .on_frame_received(&mls_existing, &credential_existing, &enroll_frame)
        .expect("Enroll must be accepted");
    match existing_session.ui_state() {
        PairingUiState::AwaitingApproval { device_name, did } => {
            assert_eq!(device_name, "Alice's Phone");
            assert_eq!(did, "did:plc:alice");
        }
        other => panic!("expected AwaitingApproval after Enroll, got {other:?}"),
    }

    let admit_cmds = existing_session
        .approve(&mls_existing, &credential_existing, &_kb_existing, [0u8; 32], &[], None)
        .expect("approve must succeed");
    let admit_frame = find_send_frame(&admit_cmds);
    let existing_ring_id = match existing_session.ui_state() {
        PairingUiState::Done { ring_id } => ring_id,
        other => panic!("expected Done after approve, got {other:?}"),
    };

    new_session
        .on_frame_received(&mls_new, &credential_new, &admit_frame)
        .expect("Admit must be accepted");
    match new_session.ui_state() {
        PairingUiState::Done { ring_id } => assert_eq!(ring_id, existing_ring_id),
        other => panic!("expected Done after Admit, got {other:?}"),
    }
}

#[test]
fn reject_from_awaiting_approval_moves_to_failed() {
    let (mls_new, credential_new, kb_new) = new_device();
    let (mls_existing, credential_existing, _kb_existing) = new_device();

    let mut new_session = PairingSession::new_device(&new_device_payload());
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);

    // Too early: no pending Enroll yet.
    let early = existing_session.reject();
    assert!(early.is_err(), "reject() with nothing pending must be rejected");
    assert_eq!(existing_session.ui_state(), PairingUiState::AwaitingPeer);

    let enroll_cmds = new_session
        .start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    let enroll_frame = find_send_frame(&enroll_cmds);
    existing_session
        .on_frame_received(&mls_existing, &credential_existing, &enroll_frame)
        .expect("Enroll must be accepted");

    existing_session.reject().expect("reject from AwaitingApproval must succeed");

    match existing_session.ui_state() {
        PairingUiState::Failed { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Failed after reject, got {other:?}"),
    }
    assert!(existing_session.pending_enroll().is_none());
    assert!(!existing_session.is_done());
}

#[test]
fn cancel_from_each_non_terminal_state_moves_to_failed() {
    // New device, Idle (fresh construction, before start_enroll).
    let mut s = PairingSession::new_device(&new_device_payload());
    s.cancel().expect("cancel from Idle must succeed");
    assert!(matches!(s.ui_state(), PairingUiState::Failed { .. }));

    // New device, AwaitingAdmit (after start_enroll).
    let (mls_new, credential_new, kb_new) = new_device();
    let mut s = PairingSession::new_device(&new_device_payload());
    s.start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    s.cancel().expect("cancel from AwaitingAdmit must succeed");
    assert!(matches!(s.ui_state(), PairingUiState::Failed { .. }));

    // Existing device, AwaitingEnroll (fresh construction).
    let mut s = PairingSession::existing_device(&SECRET, &TOKEN);
    s.cancel().expect("cancel from AwaitingEnroll must succeed");
    assert!(matches!(s.ui_state(), PairingUiState::Failed { .. }));

    // Existing device, AwaitingApproval (Enroll received).
    let (mls_new2, credential_new2, kb_new2) = new_device();
    let (mls_existing, credential_existing, _kb_existing) = new_device();
    let mut new_session = PairingSession::new_device(&new_device_payload());
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);
    let enroll_cmds = new_session
        .start_enroll(&mls_new2, &credential_new2, &kb_new2, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    let enroll_frame = find_send_frame(&enroll_cmds);
    existing_session
        .on_frame_received(&mls_existing, &credential_existing, &enroll_frame)
        .expect("Enroll must be accepted");
    existing_session
        .cancel()
        .expect("cancel from AwaitingApproval must succeed");
    assert!(matches!(existing_session.ui_state(), PairingUiState::Failed { .. }));
}

#[test]
fn every_err_path_leaves_a_failed_with_non_empty_reason() {
    // Ordering violation: Admit before Enroll was ever sent.
    let (mls_new, credential_new, _kb_new) = new_device();
    let mut s = PairingSession::new_device(&new_device_payload());
    let keys = moat_core::derive_pairing_keys(&SECRET, &TOKEN);
    let bogus_admit = PairingMsg::Admit(Admit {
        ring_id: vec![1, 2, 3],
        welcome: vec![9, 9, 9],
        roster: vec![],
    });
    let plaintext = encode_pairing_msg(&bogus_admit);
    let ciphertext = seal_frame(&keys.k_old_to_new, 0, &plaintext);
    assert!(s.on_frame_received(&mls_new, &credential_new, &ciphertext).is_err());
    match s.ui_state() {
        PairingUiState::Failed { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Failed, got {other:?}"),
    }

    // DID mismatch on Enroll.
    let (mls_existing, credential_existing, _kb_existing) = new_device();
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);
    let mls_attacker = MoatSession::new();
    let attacker_credential =
        MoatCredential::new("did:plc:mallory", "Mallory's Phone", *mls_attacker.device_id());
    let (_kp, kb_attacker) = mls_attacker.generate_key_package(&attacker_credential).unwrap();
    let mut attacker_session = PairingSession::new_device(&new_device_payload());
    let enroll_cmds = attacker_session
        .start_enroll(&mls_attacker, &attacker_credential, &kb_attacker, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    let enroll_frame = find_send_frame(&enroll_cmds);
    assert!(existing_session
        .on_frame_received(&mls_existing, &credential_existing, &enroll_frame)
        .is_err());
    match existing_session.ui_state() {
        PairingUiState::Failed { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Failed, got {other:?}"),
    }

    // Decryption failure: garbage ciphertext.
    let mut s = PairingSession::existing_device(&SECRET, &TOKEN);
    let (mls_garbage, credential_garbage, _kb) = new_device();
    assert!(s
        .on_frame_received(&mls_garbage, &credential_garbage, b"not a real frame")
        .is_err());
    match s.ui_state() {
        PairingUiState::Failed { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn reject_and_cancel_from_a_terminal_state_are_rejected_and_leave_it_unchanged() {
    // Failed is terminal: neither reject() nor cancel() can act on it again.
    let mut s = PairingSession::existing_device(&SECRET, &TOKEN);
    s.cancel().expect("first cancel must succeed");
    let state_before = s.ui_state();
    assert!(s.cancel().is_err(), "cancel from Failed must be rejected");
    assert_eq!(s.ui_state(), state_before, "a second cancel must not change the reason");
    assert!(s.reject().is_err(), "reject from Failed must be rejected");
    assert_eq!(s.ui_state(), state_before);

    // Done is terminal: a full successful exchange, then reject()/cancel()
    // afterward must not downgrade it back to Failed.
    let (mls_new, credential_new, kb_new) = new_device();
    let (mls_existing, credential_existing, _kb_existing) = new_device();
    let mut new_session = PairingSession::new_device(&new_device_payload());
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);
    let enroll_cmds = new_session
        .start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new())
        .expect("start_enroll must succeed");
    let enroll_frame = find_send_frame(&enroll_cmds);
    existing_session
        .on_frame_received(&mls_existing, &credential_existing, &enroll_frame)
        .expect("Enroll must be accepted");
    existing_session
        .approve(&mls_existing, &credential_existing, &_kb_existing, [0u8; 32], &[], None)
        .expect("approve must succeed");
    assert!(matches!(existing_session.ui_state(), PairingUiState::Done { .. }));

    assert!(existing_session.cancel().is_err(), "cancel from Done must be rejected");
    assert!(
        matches!(existing_session.ui_state(), PairingUiState::Done { .. }),
        "cancel() on a Done session must not overwrite it with Failed"
    );
    assert!(existing_session.reject().is_err(), "reject from Done must be rejected");
    assert!(
        matches!(existing_session.ui_state(), PairingUiState::Done { .. }),
        "reject() on a Done session must not overwrite it with Failed"
    );
}
