//! Stealth address cryptography for private invitations.
//!
//! This module implements stealth addresses to allow Alice to send an encrypted
//! invitation (MLS Welcome) to Bob without revealing to observers that Bob is
//! the recipient.
//!
//! # Scheme
//!
//! Bob publishes a stealth meta-address containing a scan public key (X25519).
//! When Alice wants to invite Bob:
//!
//! 1. Alice generates an ephemeral X25519 keypair (r, R)
//! 2. Alice computes a shared secret via ECDH: shared = r * S (Bob's scan pubkey)
//! 3. Alice derives an encryption key: key = HKDF-SHA256(shared, "moat-stealth-v1")
//! 4. Alice encrypts the Welcome: ciphertext = XChaCha20-Poly1305(key, nonce, welcome)
//! 5. Alice publishes: R || nonce || ciphertext
//!
//! Bob scans events by:
//! 1. Parsing R || nonce || ciphertext from each event payload
//! 2. Computing shared = s * R (using his scan private key)
//! 3. Deriving the same key and attempting decryption
//! 4. If decryption succeeds, the invite was for Bob
//!
//! # Privacy Properties
//!
//! - Each invite uses a fresh ephemeral key R, so multiple invites to Bob are unlinkable
//! - Observers cannot determine who the recipient is without Bob's private key
//! - The invite tag is random (not derived from any group), providing no correlation

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, Result};

/// Domain separation label for stealth address key derivation
const STEALTH_LABEL: &[u8] = b"moat-stealth-v1";

/// Size of the ephemeral public key (X25519)
const PUBKEY_SIZE: usize = 32;

/// Size of the XChaCha20-Poly1305 nonce
const NONCE_SIZE: usize = 24;

/// Minimum payload size: pubkey + nonce + auth tag (16 bytes)
const MIN_PAYLOAD_SIZE: usize = PUBKEY_SIZE + NONCE_SIZE + 16;

/// Generate a new stealth keypair.
///
/// Returns (private_key, public_key) where:
/// - private_key (32 bytes) should be stored locally and kept secret
/// - public_key (32 bytes) should be published to the user's PDS
pub fn generate_stealth_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = rand::thread_rng();
    let mut privkey_bytes = [0u8; 32];
    rng.fill_bytes(&mut privkey_bytes);

    let privkey = StaticSecret::from(privkey_bytes);
    let pubkey = PublicKey::from(&privkey);

    (privkey_bytes, pubkey.to_bytes())
}

/// Encrypt a Welcome message for a recipient's stealth address.
///
/// # Arguments
///
/// * `recipient_scan_pubkey` - The recipient's published stealth scan public key (32 bytes)
/// * `welcome_bytes` - The MLS Welcome message bytes to encrypt
///
/// # Returns
///
/// The encrypted payload: ephemeral_pubkey (32) || nonce (24) || ciphertext
///
/// # Example
///
/// ```ignore
/// let (_, bob_pubkey) = generate_stealth_keypair();
/// let welcome = b"MLS welcome message...";
/// let payload = encrypt_for_stealth(&bob_pubkey, welcome)?;
/// // Publish payload with a random tag
/// ```
pub fn encrypt_for_stealth(
    recipient_scan_pubkey: &[u8; 32],
    welcome_bytes: &[u8],
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // Generate ephemeral keypair
    let mut ephemeral_privkey_bytes = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_privkey_bytes);
    let ephemeral_secret = StaticSecret::from(ephemeral_privkey_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH with recipient's scan pubkey
    let recipient_pubkey = PublicKey::from(*recipient_scan_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);

    // Derive encryption key via HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(STEALTH_LABEL, &mut key)
        .expect("32 bytes is a valid HKDF output length");

    // Generate random nonce
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);

    // Encrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(&nonce.into(), welcome_bytes)
        .map_err(|e| Error::StealthEncryption(e.to_string()))?;

    // Pack: ephemeral_pubkey (32) || nonce (24) || ciphertext
    let mut result = Vec::with_capacity(PUBKEY_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Try to decrypt a stealth-encrypted Welcome message.
///
/// This function attempts to decrypt a payload using the recipient's stealth
/// private key. If decryption succeeds, the payload was intended for this recipient.
/// If it fails, the payload was for someone else (or corrupted).
///
/// # Arguments
///
/// * `scan_privkey` - The recipient's stealth scan private key (32 bytes)
/// * `payload` - The encrypted payload: ephemeral_pubkey || nonce || ciphertext
///
/// # Returns
///
/// `Some(welcome_bytes)` if decryption succeeds, `None` otherwise.
///
/// # Example
///
/// ```ignore
/// let (bob_privkey, _) = generate_stealth_keypair();
/// if let Some(welcome) = try_decrypt_stealth(&bob_privkey, &payload) {
///     // This invite was for us, process the MLS Welcome
///     session.process_welcome(&welcome)?;
/// }
/// ```
pub fn try_decrypt_stealth(scan_privkey: &[u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
    // Check minimum size
    if payload.len() < MIN_PAYLOAD_SIZE {
        return None;
    }

    // Unpack: ephemeral_pubkey (32) || nonce (24) || ciphertext
    let ephemeral_pubkey_bytes: [u8; PUBKEY_SIZE] = payload[..PUBKEY_SIZE].try_into().ok()?;
    let nonce: [u8; NONCE_SIZE] = payload[PUBKEY_SIZE..PUBKEY_SIZE + NONCE_SIZE]
        .try_into()
        .ok()?;
    let ciphertext = &payload[PUBKEY_SIZE + NONCE_SIZE..];

    // Reconstruct ephemeral public key
    let ephemeral_public = PublicKey::from(ephemeral_pubkey_bytes);

    // ECDH with our private key
    let privkey = StaticSecret::from(*scan_privkey);
    let shared_secret = privkey.diffie_hellman(&ephemeral_public);

    // Derive decryption key via HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(STEALTH_LABEL, &mut key).ok()?;

    // Decrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new(&key.into());
    cipher.decrypt(&nonce.into(), ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (privkey, pubkey) = generate_stealth_keypair();

        // Keys should not be all zeros
        assert_ne!(privkey, [0u8; 32]);
        assert_ne!(pubkey, [0u8; 32]);

        // Multiple generations should produce different keys
        let (privkey2, pubkey2) = generate_stealth_keypair();
        assert_ne!(privkey, privkey2);
        assert_ne!(pubkey, pubkey2);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = b"This is a test MLS Welcome message with some content";

        // Alice encrypts for Bob
        let payload = encrypt_for_stealth(&bob_pubkey, welcome).expect("encryption should succeed");

        // Payload should be larger than the original (pubkey + nonce + auth tag overhead)
        assert!(payload.len() > welcome.len());
        assert!(payload.len() >= MIN_PAYLOAD_SIZE);

        // Bob decrypts
        let decrypted =
            try_decrypt_stealth(&bob_privkey, &payload).expect("decryption should succeed");

        assert_eq!(decrypted, welcome);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let (_bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let (eve_privkey, _eve_pubkey) = generate_stealth_keypair();
        let welcome = b"Secret message for Bob";

        // Alice encrypts for Bob
        let payload = encrypt_for_stealth(&bob_pubkey, welcome).expect("encryption should succeed");

        // Eve tries to decrypt with her key - should fail
        let result = try_decrypt_stealth(&eve_privkey, &payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_corrupted_payload_fails() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = b"Test message";

        let mut payload =
            encrypt_for_stealth(&bob_pubkey, welcome).expect("encryption should succeed");

        // Corrupt a byte in the ciphertext
        let last_idx = payload.len() - 1;
        payload[last_idx] ^= 0xFF;

        // Decryption should fail
        let result = try_decrypt_stealth(&bob_privkey, &payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_too_short_payload_fails() {
        let (bob_privkey, _) = generate_stealth_keypair();

        // Payload too short
        let short_payload = vec![0u8; MIN_PAYLOAD_SIZE - 1];
        let result = try_decrypt_stealth(&bob_privkey, &short_payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_message() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = b"";

        let payload = encrypt_for_stealth(&bob_pubkey, welcome).expect("encryption should succeed");
        let decrypted =
            try_decrypt_stealth(&bob_privkey, &payload).expect("decryption should succeed");

        assert_eq!(decrypted, welcome);
    }

    #[test]
    fn test_large_message() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = vec![0xAB; 10000]; // 10KB message

        let payload =
            encrypt_for_stealth(&bob_pubkey, &welcome).expect("encryption should succeed");
        let decrypted =
            try_decrypt_stealth(&bob_privkey, &payload).expect("decryption should succeed");

        assert_eq!(decrypted, welcome);
    }

    #[test]
    fn test_multiple_encryptions_are_unlinkable() {
        let (_bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = b"Same message";

        // Encrypt the same message twice
        let payload1 =
            encrypt_for_stealth(&bob_pubkey, welcome).expect("encryption should succeed");
        let payload2 =
            encrypt_for_stealth(&bob_pubkey, welcome).expect("encryption should succeed");

        // The payloads should be different (different ephemeral keys and nonces)
        assert_ne!(payload1, payload2);

        // Specifically, the ephemeral public keys should differ
        assert_ne!(&payload1[..32], &payload2[..32]);
    }
}
