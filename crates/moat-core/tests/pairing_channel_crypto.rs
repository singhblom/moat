//! Unit tests for the pairing channel crypto.

use moat_core::{derive_pairing_keys, open_frame, seal_frame, PairingChannelKeys};

fn keys() -> PairingChannelKeys {
    derive_pairing_keys(&[0x33; 32], &[0x44; 16])
}

#[test]
fn seal_open_roundtrips() {
    let k = keys();
    let plaintext = b"hello pairing channel";

    let ciphertext = seal_frame(&k.k_new_to_old, 0, plaintext);
    let opened = open_frame(&k.k_new_to_old, 0, &ciphertext).expect("valid frame should open");

    assert_eq!(opened, plaintext);
}

#[test]
fn directional_keys_differ() {
    let k = keys();
    assert_ne!(
        k.k_new_to_old, k.k_old_to_new,
        "n2o and o2n keys must not collide, or reflection defense is void"
    );
}

#[test]
fn derivation_is_deterministic_given_the_same_secret_and_token() {
    let a = derive_pairing_keys(&[0x33; 32], &[0x44; 16]);
    let b = derive_pairing_keys(&[0x33; 32], &[0x44; 16]);
    assert_eq!(a.k_new_to_old, b.k_new_to_old);
    assert_eq!(a.k_old_to_new, b.k_old_to_new);
}

#[test]
fn different_secrets_derive_different_keys() {
    let a = derive_pairing_keys(&[0x33; 32], &[0x44; 16]);
    let b = derive_pairing_keys(&[0x55; 32], &[0x44; 16]);
    assert_ne!(a.k_new_to_old, b.k_new_to_old);
}

#[test]
fn wrong_key_fails_to_open() {
    let k = keys();
    let other = derive_pairing_keys(&[0x55; 32], &[0x44; 16]);

    let ciphertext = seal_frame(&k.k_new_to_old, 0, b"secret");

    assert!(
        open_frame(&other.k_new_to_old, 0, &ciphertext).is_err(),
        "a frame sealed under one secret must not open under a different one \
         (this is what excludes the relay and any token thief)"
    );
}

#[test]
fn reflection_across_directions_fails_to_open() {
    // A frame sealed under k_new_to_old must not open under k_old_to_new —
    // this stops the existing device's own frames (or a relay replaying
    // them) from being accepted as if sent by the new device.
    let k = keys();
    let ciphertext = seal_frame(&k.k_new_to_old, 0, b"n2o frame");

    assert!(
        open_frame(&k.k_old_to_new, 0, &ciphertext).is_err(),
        "reflection across directions must fail"
    );
}

#[test]
fn tampered_ciphertext_fails_to_open() {
    let k = keys();
    let mut ciphertext = seal_frame(&k.k_new_to_old, 0, b"integrity check");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(
        open_frame(&k.k_new_to_old, 0, &ciphertext).is_err(),
        "a single bit-flip must be caught by the AEAD tag"
    );
}

#[test]
fn wrong_counter_fails_to_open() {
    let k = keys();
    let ciphertext = seal_frame(&k.k_new_to_old, 3, b"counter bound");

    assert!(
        open_frame(&k.k_new_to_old, 4, &ciphertext).is_err(),
        "the nonce must be bound to the counter it was sealed under, so a \
         replayed frame at the wrong position in the stream is rejected"
    );
}

#[test]
fn same_plaintext_at_different_counters_produces_different_ciphertext() {
    let k = keys();
    let a = seal_frame(&k.k_new_to_old, 0, b"same plaintext");
    let b = seal_frame(&k.k_new_to_old, 1, b"same plaintext");

    assert_ne!(
        a, b,
        "the counter must vary the nonce, or repeated plaintexts leak equality"
    );
}
