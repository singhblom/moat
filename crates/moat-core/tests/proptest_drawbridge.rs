use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use moat_core::{KeyBundle, MoatSession};
use proptest::prelude::*;

proptest! {
    /// For any random 32-byte signing seed, signing a message and verifying with
    /// the returned public key must always succeed.
    #[test]
    fn sign_drawbridge_challenge_verifies(
        seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let bundle = KeyBundle {
            key_package: vec![],
            init_private_key: vec![],
            encryption_private_key: vec![],
            signature_key: vec![],
            signature_private_key: seed.to_vec(),
        };
        let bundle_bytes = serde_json::to_vec(&bundle).unwrap();

        let (sig_bytes, pub_bytes) =
            MoatSession::sign_drawbridge_challenge(&bundle_bytes, &message).unwrap();

        prop_assert_eq!(sig_bytes.len(), 64);
        prop_assert_eq!(pub_bytes.len(), 32);

        let vk = VerifyingKey::from_bytes(&pub_bytes.try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        prop_assert!(vk.verify(&message, &sig).is_ok());
    }

    /// Signing the same message with two different seeds must produce different signatures.
    #[test]
    fn different_seeds_produce_different_signatures(
        seed_a in prop::array::uniform32(any::<u8>()),
        seed_b in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(seed_a != seed_b);

        let message = b"nonce\nwss://relay.test\n1700000000\n";

        let make_bundle = |seed: [u8; 32]| -> Vec<u8> {
            serde_json::to_vec(&KeyBundle {
                key_package: vec![],
                init_private_key: vec![],
                encryption_private_key: vec![],
                signature_key: vec![],
                signature_private_key: seed.to_vec(),
            }).unwrap()
        };

        let (_sig_a, pub_a) = MoatSession::sign_drawbridge_challenge(&make_bundle(seed_a), message).unwrap();
        let (sig_b, pub_b) = MoatSession::sign_drawbridge_challenge(&make_bundle(seed_b), message).unwrap();

        // Different keys → different public keys → signatures won't cross-verify
        let pub_a_arr: [u8; 32] = pub_a.try_into().unwrap();
        let pub_b_arr: [u8; 32] = pub_b.try_into().unwrap();
        prop_assert_ne!(pub_a_arr, pub_b_arr);
        let vk_a = VerifyingKey::from_bytes(&pub_a_arr).unwrap();
        let sig_b_parsed = Signature::from_bytes(&sig_b.try_into().unwrap());
        prop_assert!(vk_a.verify(message, &sig_b_parsed).is_err());
    }

    /// Signature over message A must not verify for message B.
    #[test]
    fn signature_does_not_verify_wrong_message(
        seed in prop::array::uniform32(any::<u8>()),
        msg_a in prop::collection::vec(any::<u8>(), 1..128),
        msg_b in prop::collection::vec(any::<u8>(), 1..128),
    ) {
        prop_assume!(msg_a != msg_b);

        let bundle_bytes = serde_json::to_vec(&KeyBundle {
            key_package: vec![],
            init_private_key: vec![],
            encryption_private_key: vec![],
            signature_key: vec![],
            signature_private_key: seed.to_vec(),
        }).unwrap();

        let (sig_bytes, pub_bytes) =
            MoatSession::sign_drawbridge_challenge(&bundle_bytes, &msg_a).unwrap();

        let vk = VerifyingKey::from_bytes(&pub_bytes.try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        prop_assert!(vk.verify(&msg_b, &sig).is_err());
    }
}
