//! Unit tests for `PairingSession` message-ordering violations.
//!
//! These describe protocol-level misuse that the driver must reject with a
//! structured error rather than panic, hang, or silently do the wrong
//! thing.

use moat_core::{
    encode_pairing_msg, seal_frame, Admit, MoatCredential, MoatSession, PairingCommand,
    PairingMsg, PairingSession,
};

const SECRET: [u8; 32] = [0xAA; 32];
const TOKEN: [u8; 16] = [0xBB; 16];

fn new_device() -> (MoatSession, MoatCredential, Vec<u8>) {
    let mls = MoatSession::new();
    let credential = MoatCredential::new("did:plc:alice", "Alice's Phone", *mls.device_id());
    let (_kp, key_bundle) = mls.generate_key_package(&credential).unwrap();
    (mls, credential, key_bundle)
}

#[test]
fn new_device_session_starts_not_done() {
    let session = PairingSession::new_device(&SECRET, &TOKEN);
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
    let mut new_session = PairingSession::new_device(&SECRET, &TOKEN);

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
    let mut new_session = PairingSession::new_device(&SECRET, &TOKEN);
    let mut existing_session = PairingSession::existing_device(&SECRET, &TOKEN);

    let enroll_cmds = new_session.start_enroll(
        &mls_new,
        &credential_new,
        &kb_new,
        [0u8; 32],
        Vec::new(),
    );
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
    let mut attacker_session = PairingSession::new_device(&SECRET, &TOKEN);

    let enroll_cmds = attacker_session.start_enroll(
        &mls_attacker,
        &attacker_credential,
        &kb_attacker,
        [0u8; 32],
        Vec::new(),
    );
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

    let mut new_session = PairingSession::new_device(&SECRET, &TOKEN);
    new_session.start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new());

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
