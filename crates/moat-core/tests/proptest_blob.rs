/// Property-based tests for `moat_core::blob_encrypt` / `blob_decrypt`.
///
/// These tests verify invariants that must hold for **all** possible plaintexts,
/// not just the hand-crafted inputs in the unit tests inside `blob.rs`.
use moat_core::{blob_decrypt, blob_encrypt};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

proptest! {
    /// For any plaintext, encrypt then decrypt must recover the original bytes.
    #[test]
    fn roundtrip_arbitrary_plaintext(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let r = blob_encrypt(&plaintext).expect("encryption must succeed");

        let decrypted = blob_decrypt(&r.blob, &r.key, &r.ciphertext_hash, &r.content_hash)
            .expect("decryption must succeed after roundtrip");

        prop_assert_eq!(decrypted, plaintext);
    }

    /// `content_hash` = SHA-256(plaintext) and is therefore deterministic: two
    /// calls with the same input always produce the same content_hash.
    #[test]
    fn content_hash_is_sha256_of_plaintext(plaintext in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let r = blob_encrypt(&plaintext).expect("encrypt ok");
        let expected = Sha256::digest(&plaintext).to_vec();
        prop_assert_eq!(r.content_hash, expected);
    }

    /// Two encryptions of the same plaintext produce different blobs (different
    /// random nonce each time) but the same content_hash.
    #[test]
    fn same_plaintext_produces_different_blobs(plaintext in proptest::collection::vec(any::<u8>(), 1..512)) {
        let r1 = blob_encrypt(&plaintext).expect("first encrypt ok");
        let r2 = blob_encrypt(&plaintext).expect("second encrypt ok");

        // Different nonces → different ciphertext (overwhelmingly likely).
        prop_assert_ne!(r1.blob, r2.blob);
        // But the plaintext hash is stable.
        prop_assert_eq!(r1.content_hash, r2.content_hash);
    }

    /// Two encryptions of the same plaintext also produce different keys.
    #[test]
    fn same_plaintext_produces_different_keys(plaintext in proptest::collection::vec(any::<u8>(), 1..128)) {
        let r1 = blob_encrypt(&plaintext).expect("first encrypt ok");
        let r2 = blob_encrypt(&plaintext).expect("second encrypt ok");
        prop_assert_ne!(r1.key.to_vec(), r2.key.to_vec());
    }

    /// Flipping any single byte in the blob must cause either the ciphertext
    /// hash check or the AEAD decryption to fail.
    #[test]
    fn single_byte_flip_in_blob_is_detected(
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        flip_offset in any::<u8>(),
    ) {
        let mut r = blob_encrypt(&plaintext).expect("encrypt ok");

        // Flip a byte, wrapping the offset into bounds.
        let idx = (flip_offset as usize) % r.blob.len();
        r.blob[idx] ^= 0xFF;

        // Recompute the ciphertext hash of the corrupted blob so the hash check
        // passes; the AEAD tag verification should then catch the corruption.
        let corrupted_ciphertext_hash = Sha256::digest(&r.blob).to_vec();

        let result = blob_decrypt(&r.blob, &r.key, &corrupted_ciphertext_hash, &r.content_hash);
        prop_assert!(result.is_err(), "corrupted blob must not decrypt successfully");
    }

    /// Wrong key must always fail decryption (with astronomically high probability).
    #[test]
    fn wrong_key_always_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        wrong_key in prop::array::uniform32(any::<u8>()),
    ) {
        let r = blob_encrypt(&plaintext).expect("encrypt ok");

        // If the random wrong_key happens to equal the correct key, skip this case.
        prop_assume!(wrong_key != r.key);

        let result = blob_decrypt(&r.blob, &wrong_key, &r.ciphertext_hash, &r.content_hash);
        prop_assert!(result.is_err(), "decryption with wrong key must fail");
    }

    /// `ciphertext_hash` is the SHA-256 of the entire blob (`nonce || ciphertext`).
    #[test]
    fn ciphertext_hash_is_sha256_of_blob(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
        let r = blob_encrypt(&plaintext).expect("encrypt ok");
        let expected = Sha256::digest(&r.blob).to_vec();
        prop_assert_eq!(r.ciphertext_hash, expected);
    }
}
