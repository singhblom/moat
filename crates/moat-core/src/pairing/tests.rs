use super::*;

const SECRET: [u8; 16] = [0xAA; 16];
const TOKEN: [u8; 16] = [0xBB; 16];
const DRAWBRIDGE: &str = "wss://drawbridge.example.com/ws";

fn payload() -> PairingPayload {
    PairingPayload {
        secret: SECRET,
        token: TOKEN,
    }
}

fn device(did: &str, name: &str) -> (MoatSession, MoatCredential, Vec<u8>) {
    let mls = MoatSession::new();
    let credential = MoatCredential::new(did, name, *mls.device_id());
    let (_kp, key_bundle) = mls.generate_key_package(&credential).unwrap();
    (mls, credential, key_bundle)
}

fn alice(name: &str) -> (MoatSession, MoatCredential, Vec<u8>) {
    device("did:plc:alice", name)
}

fn send_frame(cmds: &[PairingCommand]) -> Vec<u8> {
    cmds.iter()
        .find_map(|c| match c {
            PairingCommand::SendFrame { ciphertext } => Some(ciphertext.clone()),
            _ => None,
        })
        .expect("expected a SendFrame command in this batch")
}

/// `mls`'s Enroll frame, sealed for the existing device.
fn enroll_frame(mls: &MoatSession, credential: &MoatCredential, key_bundle: &[u8]) -> Vec<u8> {
    let mut session = PairingSession::new_device(&payload(), DRAWBRIDGE);
    let cmds = session
        .start_enroll(mls, credential, key_bundle, [0u8; 32], Vec::new())
        .unwrap();
    send_frame(&cmds)
}

/// An Admit sealed as the existing device's first frame.
fn admit_frame(admit: Admit) -> Vec<u8> {
    let keys = derive_pairing_keys(&SECRET, &TOKEN);
    seal_frame(
        &keys.k_old_to_new,
        0,
        &encode_pairing_msg(&PairingMsg::Admit(admit)),
    )
}

fn assert_failed_with_reason(session: &PairingSession) {
    match session.ui_state() {
        PairingUiState::Failed { reason } => assert!(!reason.is_empty()),
        other => panic!("expected Failed with a reason, got {other:?}"),
    }
}

// ── Code codec ───────────────────────────────────────────────────────────────

#[test]
fn payload_roundtrips_through_text_form() {
    let text = payload().to_text();
    assert!(text.contains('-'), "text form should be hyphen-grouped");
    assert_eq!(PairingPayload::from_text(&text).unwrap(), payload());
}

/// The text form is typed by hand, so its length is a product decision:
/// 33 payload bytes make 53 Crockford characters.
#[test]
fn text_form_is_53_characters_plus_grouping() {
    let bare: String = payload().to_text().chars().filter(|c| *c != '-').collect();
    assert_eq!(bare.len(), 53, "{bare}");
}

#[test]
fn payload_and_drawbridge_roundtrip_through_uri_form() {
    let uri = payload().to_uri(DRAWBRIDGE);
    assert!(uri.starts_with(PAIRING_URI_SCHEME), "{uri}");
    assert_eq!(
        PairingPayload::from_uri(&uri).unwrap(),
        (payload(), Some(DRAWBRIDGE.to_string()))
    );
}

#[test]
fn a_uri_without_a_drawbridge_yields_none() {
    let uri = format!("{PAIRING_URI_SCHEME}{}", payload().to_text());
    assert_eq!(PairingPayload::from_uri(&uri).unwrap(), (payload(), None));
}

#[test]
fn a_drawbridge_in_a_uri_is_normalised() {
    let uri = format!("{PAIRING_URI_SCHEME}{}?drawbridge=drawbridge.example.com", payload().to_text());
    assert_eq!(
        PairingPayload::from_uri(&uri).unwrap().1.as_deref(),
        Some("wss://drawbridge.example.com/ws")
    );
}

#[test]
fn normalize_drawbridge_url_accepts_the_forms_a_user_types() {
    for (typed, want) in [
        ("wss://drawbridge.example.com/ws", "wss://drawbridge.example.com/ws"),
        ("drawbridge.example.com", "wss://drawbridge.example.com/ws"),
        ("  drawbridge.example.com/ws  ", "wss://drawbridge.example.com/ws"),
        ("WSS://drawbridge.example.com", "wss://drawbridge.example.com/ws"),
        ("ws://127.0.0.1:8080", "ws://127.0.0.1:8080/ws"),
        ("ws://127.0.0.1:8080/", "ws://127.0.0.1:8080/ws"),
        ("wss://drawbridge.example.com/custom", "wss://drawbridge.example.com/custom"),
    ] {
        assert_eq!(normalize_drawbridge_url(typed).unwrap(), want, "{typed:?}");
    }
}

#[test]
fn normalize_drawbridge_url_rejects_what_is_not_a_drawbridge() {
    for typed in ["", "   ", "https://drawbridge.example.com", "wss://", "ws:///ws", "a b"] {
        assert!(normalize_drawbridge_url(typed).is_err(), "{typed:?}");
    }
}

#[test]
fn from_text_is_case_insensitive() {
    let lower = payload().to_text().to_lowercase();
    assert_eq!(PairingPayload::from_text(&lower).unwrap(), payload());
}

#[test]
fn from_text_ignores_where_the_hyphens_fall() {
    let bare: Vec<char> = payload().to_text().chars().filter(|c| *c != '-').collect();
    let regrouped = bare
        .chunks(3)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-");
    assert_eq!(PairingPayload::from_text(&regrouped).unwrap(), payload());
}

#[test]
fn from_text_rejects_confusable_letters() {
    assert!(PairingPayload::from_text("IIIII-LLLLL-OOOOO-UUUUU").is_err());
    for c in [b'I', b'L', b'O', b'U'] {
        assert!(!CROCKFORD_ALPHABET.contains(&c), "{}", c as char);
    }
}

#[test]
fn from_uri_rejects_a_foreign_scheme() {
    let foreign = format!("https://evil.example/{}", payload().to_text());
    assert!(PairingPayload::from_uri(&foreign).is_err());
}

#[test]
fn decode_rejects_a_bad_version() {
    let mut bytes = payload().encode();
    bytes[0] = 0xFF;
    let err = PairingPayload::decode(&bytes).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("version"), "{err}");
}

#[test]
fn decode_rejects_a_payload_of_the_wrong_length() {
    let bytes = payload().encode();
    assert!(PairingPayload::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut long = bytes;
    long.push(0);
    assert!(PairingPayload::decode(&long).is_err());
}

// ── Channel crypto ───────────────────────────────────────────────────────────

/// Excludes the relay and anyone holding only the token.
#[test]
fn a_frame_does_not_open_under_another_secret() {
    let keys = derive_pairing_keys(&SECRET, &TOKEN);
    let other = derive_pairing_keys(&[0x55; 16], &TOKEN);
    let ciphertext = seal_frame(&keys.k_new_to_old, 0, b"secret");
    assert!(open_frame(&other.k_new_to_old, 0, &ciphertext).is_err());
}

/// A device's own frames, replayed back at it, must not pass as the peer's.
#[test]
fn a_frame_does_not_open_in_the_other_direction() {
    let keys = derive_pairing_keys(&SECRET, &TOKEN);
    let ciphertext = seal_frame(&keys.k_new_to_old, 0, b"n2o frame");
    assert!(open_frame(&keys.k_old_to_new, 0, &ciphertext).is_err());
}

#[test]
fn a_tampered_frame_does_not_open() {
    let keys = derive_pairing_keys(&SECRET, &TOKEN);
    let mut ciphertext = seal_frame(&keys.k_new_to_old, 0, b"integrity check");
    *ciphertext.last_mut().unwrap() ^= 0x01;
    assert!(open_frame(&keys.k_new_to_old, 0, &ciphertext).is_err());
}

/// The counter is the nonce, so a frame replayed at another position fails.
#[test]
fn a_frame_does_not_open_at_another_counter() {
    let keys = derive_pairing_keys(&SECRET, &TOKEN);
    let ciphertext = seal_frame(&keys.k_new_to_old, 3, b"counter bound");
    assert!(open_frame(&keys.k_new_to_old, 4, &ciphertext).is_err());
}

// ── Session: what it refuses ─────────────────────────────────────────────────

#[test]
fn an_admit_before_enroll_was_sent_fails_the_pairing() {
    let (mls, credential, _) = alice("Phone");
    let mut session = PairingSession::new_device(&payload(), DRAWBRIDGE);
    let frame = admit_frame(Admit {
        ring_id: vec![1, 2, 3],
        welcome: vec![9, 9, 9],
        roster: vec![],
    });

    assert!(session
        .on_frame_received(&mls, &credential, &frame)
        .is_err());
    assert_failed_with_reason(&session);
}

#[test]
fn an_unopenable_frame_fails_the_pairing() {
    let (mls, credential, _) = alice("Laptop");
    let mut session = PairingSession::existing_device(&SECRET, &TOKEN);

    assert!(session
        .on_frame_received(&mls, &credential, b"not a real frame")
        .is_err());
    assert_failed_with_reason(&session);
}

/// The user's approval applies to the Enroll they saw on screen. Sealed at
/// counter 1 so the protocol guard, not the replay guard, rejects it.
#[test]
fn a_second_enroll_while_one_awaits_approval_is_refused() {
    let (mls_new, credential_new, kb_new) = alice("Phone");
    let (mls, credential, _) = alice("Laptop");
    let mut session = PairingSession::existing_device(&SECRET, &TOKEN);
    let first = enroll_frame(&mls_new, &credential_new, &kb_new);
    session
        .on_frame_received(&mls, &credential, &first)
        .unwrap();

    let keys = derive_pairing_keys(&SECRET, &TOKEN);
    let plaintext = open_frame(&keys.k_new_to_old, 0, &first).unwrap();
    let second = seal_frame(&keys.k_new_to_old, 1, &plaintext);

    assert!(session
        .on_frame_received(&mls, &credential, &second)
        .is_err());
}

/// A pairing code is per account: an Enroll from another DID is never
/// approvable.
#[test]
fn an_enroll_from_another_did_fails_the_pairing() {
    let (mls, credential, _) = alice("Laptop");
    let (mls_mallory, credential_mallory, kb_mallory) = device("did:plc:mallory", "Phone");
    let mut session = PairingSession::existing_device(&SECRET, &TOKEN);
    let frame = enroll_frame(&mls_mallory, &credential_mallory, &kb_mallory);

    assert!(session
        .on_frame_received(&mls, &credential, &frame)
        .is_err());
    assert_failed_with_reason(&session);
}

/// `Admit` carries no DID to check up front; the ring's member credentials,
/// read after processing the Welcome, are the new device's only anchor.
#[test]
fn an_admit_into_another_dids_ring_fails_the_pairing() {
    let mls = MoatSession::new();
    let credential = MoatCredential::new("did:plc:alice", "Phone", *mls.device_id());
    let (kp, key_bundle) = mls.generate_key_package(&credential).unwrap();
    let mut session = PairingSession::new_device(&payload(), DRAWBRIDGE);
    session
        .start_enroll(&mls, &credential, &key_bundle, [0u8; 32], Vec::new())
        .unwrap();

    let (mls_mallory, credential_mallory, kb_mallory) = device("did:plc:mallory", "Laptop");
    let ring_id = mls_mallory
        .create_group(&credential_mallory, &kb_mallory)
        .unwrap();
    let welcome = mls_mallory
        .add_member(&ring_id, &kb_mallory, &kp)
        .unwrap()
        .welcome;
    let frame = admit_frame(Admit {
        ring_id,
        welcome,
        roster: vec![],
    });

    assert!(session
        .on_frame_received(&mls, &credential, &frame)
        .is_err());
    assert_failed_with_reason(&session);
}

// ── Session: terminal states ─────────────────────────────────────────────────

#[test]
fn cancel_from_each_non_terminal_state_fails_the_pairing() {
    let mut idle = PairingSession::new_device(&payload(), DRAWBRIDGE);
    idle.cancel().unwrap();
    assert_failed_with_reason(&idle);

    let (mls_new, credential_new, kb_new) = alice("Phone");
    let mut awaiting_admit = PairingSession::new_device(&payload(), DRAWBRIDGE);
    awaiting_admit
        .start_enroll(&mls_new, &credential_new, &kb_new, [0u8; 32], Vec::new())
        .unwrap();
    awaiting_admit.cancel().unwrap();
    assert_failed_with_reason(&awaiting_admit);

    let mut awaiting_enroll = PairingSession::existing_device(&SECRET, &TOKEN);
    awaiting_enroll.cancel().unwrap();
    assert_failed_with_reason(&awaiting_enroll);

    let (mls, credential, _) = alice("Laptop");
    let mut awaiting_approval = PairingSession::existing_device(&SECRET, &TOKEN);
    let frame = enroll_frame(&mls_new, &credential_new, &kb_new);
    awaiting_approval
        .on_frame_received(&mls, &credential, &frame)
        .unwrap();
    awaiting_approval.cancel().unwrap();
    assert_failed_with_reason(&awaiting_approval);
}

#[test]
fn a_failed_pairing_keeps_its_reason() {
    let mut session = PairingSession::existing_device(&SECRET, &TOKEN);
    session.cancel().unwrap();
    let failed = session.ui_state();

    assert!(session.cancel().is_err());
    assert!(session.reject().is_err());
    assert_eq!(session.ui_state(), failed);
}

/// A late cancel, such as the relay closing the channel after success,
/// must not turn `Done` into `Failed`.
#[test]
fn a_done_pairing_stays_done() {
    let (mls_new, credential_new, kb_new) = alice("Phone");
    let (mls, credential, key_bundle) = alice("Laptop");
    let mut session = PairingSession::existing_device(&SECRET, &TOKEN);
    let frame = enroll_frame(&mls_new, &credential_new, &kb_new);
    session
        .on_frame_received(&mls, &credential, &frame)
        .unwrap();
    session
        .approve(&mls, &credential, &key_bundle, [0u8; 32], &[], None)
        .unwrap();

    assert!(session.cancel().is_err());
    assert!(session.reject().is_err());
    assert!(matches!(session.ui_state(), PairingUiState::Done { .. }));
}
