//! Off-chain blob encryption for large payloads (long text, images).
//!
//! Each blob is encrypted with a fresh random key and nonce using
//! XChaCha20-Poly1305. The encrypted payload is `nonce (24 bytes) || ciphertext`.
//! Two SHA-256 hashes are returned for integrity verification:
//!
//! - **ciphertext_hash**: SHA-256 of the entire blob (`nonce || ciphertext`). Allows
//!   the recipient to detect tampering before attempting decryption.
//! - **content_hash**: SHA-256 of the plaintext. Allows the recipient to verify
//!   integrity after decryption, and serves as a stable cache key across
//!   re-encryptions.
//!
//! Both hashes are embedded in the MLS-encrypted envelope (`ExternalBlob`), so
//! they inherit the MLS group's authenticated-encryption guarantees.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Size of the XChaCha20-Poly1305 nonce in bytes.
const NONCE_SIZE: usize = 24;

/// Size of the blob encryption key in bytes.
const KEY_SIZE: usize = 32;

/// Output of [`blob_encrypt`].
pub struct EncryptedBlob {
    /// `nonce (24 bytes) || ciphertext`. This is what gets uploaded to the PDS.
    pub blob: Vec<u8>,
    /// 32-byte symmetric key. Embedded (MLS-encrypted) in the event record.
    pub key: [u8; KEY_SIZE],
    /// SHA-256 of `blob`. Stored in `ExternalBlob` for pre-decryption integrity check.
    pub ciphertext_hash: Vec<u8>,
    /// SHA-256 of `plaintext`. Stored in `ExternalBlob` for post-decryption integrity
    /// check and as the local cache key.
    pub content_hash: Vec<u8>,
}

/// Encrypt `plaintext` as an off-chain blob.
pub fn blob_encrypt(plaintext: &[u8]) -> Result<EncryptedBlob> {
    let mut rng = rand::thread_rng();

    // Generate a fresh random key and nonce for each blob.
    let mut key = [0u8; KEY_SIZE];
    rng.fill_bytes(&mut key);

    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);

    // Hash the plaintext before encryption.
    let content_hash = Sha256::digest(plaintext).to_vec();

    // Encrypt.
    let cipher = XChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(&nonce.into(), plaintext)
        .map_err(|e| Error::BlobDecryptionFailed(format!("encryption failed: {e}")))?;

    // Assemble blob: nonce || ciphertext.
    let mut blob = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    // Hash the assembled blob.
    let ciphertext_hash = Sha256::digest(&blob).to_vec();

    Ok(EncryptedBlob { blob, key, ciphertext_hash, content_hash })
}

/// Decrypt and verify an off-chain blob.
///
/// # Arguments
///
/// * `blob` — Raw bytes retrieved from the PDS: `nonce (24) || ciphertext`.
/// * `key` — The 32-byte symmetric key from `ExternalBlob.key`.
/// * `expected_ciphertext_hash` — SHA-256 of `blob` from `ExternalBlob.ciphertext_hash`.
/// * `expected_content_hash` — SHA-256 of the plaintext from `ExternalBlob.content_hash`.
///
/// # Errors
///
/// - [`Error::CiphertextHashMismatch`] — blob was corrupted or tampered with before decryption.
/// - [`Error::BlobDecryptionFailed`] — XChaCha20-Poly1305 decryption failed (wrong key or corrupt ciphertext).
/// - [`Error::ContentHashMismatch`] — plaintext hash does not match after decryption (integrity failure).
pub fn blob_decrypt(
    blob: &[u8],
    key: &[u8; KEY_SIZE],
    expected_ciphertext_hash: &[u8],
    expected_content_hash: &[u8],
) -> Result<Vec<u8>> {
    // Verify blob integrity before attempting decryption.
    let actual_ciphertext_hash = Sha256::digest(blob);
    if actual_ciphertext_hash.as_slice() != expected_ciphertext_hash {
        return Err(Error::CiphertextHashMismatch(
            "blob hash does not match expected value".to_string(),
        ));
    }

    if blob.len() < NONCE_SIZE {
        return Err(Error::BlobDecryptionFailed(
            "blob too short to contain nonce".to_string(),
        ));
    }

    let nonce: [u8; NONCE_SIZE] = blob[..NONCE_SIZE]
        .try_into()
        .expect("slice length checked above");
    let ciphertext = &blob[NONCE_SIZE..];

    // Decrypt.
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(&nonce.into(), ciphertext)
        .map_err(|e| Error::BlobDecryptionFailed(format!("decryption failed: {e}")))?;

    // Verify plaintext integrity.
    let actual_content_hash = Sha256::digest(&plaintext);
    if actual_content_hash.as_slice() != expected_content_hash {
        return Err(Error::ContentHashMismatch(
            "plaintext hash does not match expected value".to_string(),
        ));
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_nonempty() {
        let plaintext = b"Hello, off-chain blob!";
        let r = blob_encrypt(plaintext).expect("encryption should succeed");

        let decrypted = blob_decrypt(&r.blob, &r.key, &r.ciphertext_hash, &r.content_hash)
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_empty() {
        let plaintext = b"";
        let r = blob_encrypt(plaintext).expect("encryption should succeed");

        let decrypted = blob_decrypt(&r.blob, &r.key, &r.ciphertext_hash, &r.content_hash)
            .expect("decryption should succeed for empty plaintext");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_large() {
        let plaintext = vec![0xAB_u8; 64 * 1024]; // 64 KB
        let r = blob_encrypt(&plaintext).expect("encryption should succeed");

        let decrypted = blob_decrypt(&r.blob, &r.key, &r.ciphertext_hash, &r.content_hash)
            .expect("decryption should succeed for large plaintext");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_ciphertext_hash_rejected() {
        let plaintext = b"test message";
        let r = blob_encrypt(plaintext).expect("encryption should succeed");

        let wrong_hash = vec![0u8; 32];
        let result = blob_decrypt(&r.blob, &r.key, &wrong_hash, &r.content_hash);

        assert!(matches!(result, Err(Error::CiphertextHashMismatch(_))));
    }

    #[test]
    fn wrong_content_hash_rejected() {
        let plaintext = b"test message";
        let r = blob_encrypt(plaintext).expect("encryption should succeed");

        let wrong_hash = vec![0u8; 32];
        let result = blob_decrypt(&r.blob, &r.key, &r.ciphertext_hash, &wrong_hash);

        assert!(matches!(result, Err(Error::ContentHashMismatch(_))));
    }

    #[test]
    fn corrupted_blob_rejected() {
        let plaintext = b"test message";
        let mut r = blob_encrypt(plaintext).expect("encryption should succeed");

        // Flip a byte in the ciphertext (after the nonce).
        let last = r.blob.len() - 1;
        r.blob[last] ^= 0xFF;

        // Re-hash the corrupted blob so the hash check passes, but decryption fails.
        let corrupted_hash = Sha256::digest(&r.blob).to_vec();

        let result = blob_decrypt(&r.blob, &r.key, &corrupted_hash, &r.content_hash);
        assert!(matches!(result, Err(Error::BlobDecryptionFailed(_))));
    }

    #[test]
    fn wrong_key_rejected() {
        let plaintext = b"test message";
        let r = blob_encrypt(plaintext).expect("encryption should succeed");

        let wrong_key = [0u8; 32];
        let result = blob_decrypt(&r.blob, &wrong_key, &r.ciphertext_hash, &r.content_hash);

        // Either ciphertext hash will fail (unlikely — correct blob) or decryption will fail.
        assert!(result.is_err());
    }

    #[test]
    fn different_encryptions_produce_different_blobs() {
        let plaintext = b"same content";
        let r1 = blob_encrypt(plaintext).expect("ok");
        let r2 = blob_encrypt(plaintext).expect("ok");
        // Different nonces → different ciphertexts.
        assert_ne!(r1.blob, r2.blob);
    }

    #[test]
    fn content_hash_is_deterministic() {
        let plaintext = b"deterministic";
        let r1 = blob_encrypt(plaintext).expect("ok");
        let r2 = blob_encrypt(plaintext).expect("ok");
        // content_hash = SHA-256(plaintext), independent of key/nonce.
        assert_eq!(r1.content_hash, r2.content_hash);
    }
}
