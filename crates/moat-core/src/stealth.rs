//! Stealth address cryptography for private invitations.
//!
//! This module implements stealth addresses to allow Alice to send an encrypted
//! invitation (MLS Welcome) to Bob without revealing to observers that Bob is
//! the recipient.
//!
//! # Multi-Device Scheme (Key Encapsulation)
//!
//! Bob may have multiple devices, each with its own stealth address (X25519 keypair).
//! Alice encrypts once and wraps the key for each device:
//!
//! 1. Alice generates a random content encryption key (CEK)
//! 2. Alice encrypts the Welcome with the CEK: encrypted_welcome = encrypt(CEK, welcome)
//! 3. For each of Bob's devices, Alice wraps the CEK: wrapped_key_i = wrap(pubkey_i, CEK)
//! 4. Alice publishes: num_recipients (1 byte) || [wrapped_key_1, ...] || nonce (24) || encrypted_welcome
//!
//! Any of Bob's devices can:
//! 1. Parse the wrapped keys and encrypted welcome
//! 2. Try to unwrap the CEK with their private key
//! 3. If successful, decrypt the welcome with the CEK
//!
//! # Privacy Properties
//!
//! - Each invite uses fresh ephemeral keys, so invites are unlinkable
//! - Observers cannot determine who the recipient is without a private key
//! - The invite tag is random (not derived from any group), providing no correlation
//! - Number of wrapped keys reveals device count, but not which devices

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
const STEALTH_LABEL: &[u8] = b"moat-stealth-v2";

/// Size of the ephemeral public key (X25519)
const PUBKEY_SIZE: usize = 32;

/// Size of the XChaCha20-Poly1305 nonce
const NONCE_SIZE: usize = 24;

/// Size of the content encryption key
const CEK_SIZE: usize = 32;

/// Size of the auth tag
const TAG_SIZE: usize = 16;

/// Size of a wrapped key: ephemeral_pubkey (32) + nonce (24) + encrypted_cek (32) + tag (16)
const WRAPPED_KEY_SIZE: usize = PUBKEY_SIZE + NONCE_SIZE + CEK_SIZE + TAG_SIZE;

/// Maximum number of recipients (devices) supported
const MAX_RECIPIENTS: usize = 255;

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

/// Encrypt a Welcome message for one or more recipients (devices).
///
/// Uses key encapsulation: the welcome is encrypted once with a random CEK,
/// and the CEK is wrapped separately for each recipient's stealth public key.
/// This is efficient because the (potentially large) welcome is only encrypted once.
///
/// # Arguments
///
/// * `recipient_pubkeys` - Slice of recipient stealth public keys (32 bytes each)
/// * `welcome_bytes` - The MLS Welcome message bytes to encrypt
///
/// # Returns
///
/// The encrypted payload:
/// ```text
/// num_recipients (1 byte) || wrapped_key_1 || ... || wrapped_key_n || nonce (24) || encrypted_welcome
/// ```
///
/// Each wrapped_key is 104 bytes: ephemeral_pubkey (32) || nonce (24) || encrypted_cek (32) || tag (16)
///
/// # Errors
///
/// Returns an error if no recipients are provided or if encryption fails.
pub fn encrypt_for_stealth(
    recipient_pubkeys: &[[u8; 32]],
    welcome_bytes: &[u8],
) -> Result<Vec<u8>> {
    if recipient_pubkeys.is_empty() {
        return Err(Error::StealthEncryption("no recipients provided".to_string()));
    }
    if recipient_pubkeys.len() > MAX_RECIPIENTS {
        return Err(Error::StealthEncryption(format!(
            "too many recipients: {} > {}",
            recipient_pubkeys.len(),
            MAX_RECIPIENTS
        )));
    }

    let mut rng = rand::thread_rng();

    // Generate random content encryption key (CEK)
    let mut cek = [0u8; CEK_SIZE];
    rng.fill_bytes(&mut cek);

    // Encrypt the welcome with the CEK
    let mut content_nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut content_nonce);

    let cipher = XChaCha20Poly1305::new(&cek.into());
    let encrypted_welcome = cipher
        .encrypt(&content_nonce.into(), welcome_bytes)
        .map_err(|e| Error::StealthEncryption(e.to_string()))?;

    // Wrap the CEK for each recipient
    let mut wrapped_keys = Vec::with_capacity(recipient_pubkeys.len() * WRAPPED_KEY_SIZE);
    for pubkey in recipient_pubkeys {
        let wrapped = wrap_key_for_recipient(pubkey, &cek)?;
        wrapped_keys.extend_from_slice(&wrapped);
    }

    // Build the final payload
    let num_recipients = recipient_pubkeys.len() as u8;
    let total_size = 1 + wrapped_keys.len() + NONCE_SIZE + encrypted_welcome.len();
    let mut result = Vec::with_capacity(total_size);

    result.push(num_recipients);
    result.extend_from_slice(&wrapped_keys);
    result.extend_from_slice(&content_nonce);
    result.extend_from_slice(&encrypted_welcome);

    Ok(result)
}

/// Wrap a content encryption key for a single recipient using their stealth public key.
fn wrap_key_for_recipient(recipient_pubkey: &[u8; 32], cek: &[u8; CEK_SIZE]) -> Result<[u8; WRAPPED_KEY_SIZE]> {
    let mut rng = rand::thread_rng();

    // Generate ephemeral keypair for this recipient
    let mut ephemeral_privkey_bytes = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_privkey_bytes);
    let ephemeral_secret = StaticSecret::from(ephemeral_privkey_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH with recipient's public key
    let recipient_pk = PublicKey::from(*recipient_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    // Derive wrapping key via HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut wrapping_key = [0u8; 32];
    hk.expand(STEALTH_LABEL, &mut wrapping_key)
        .expect("32 bytes is a valid HKDF output length");

    // Generate nonce for key wrapping
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);

    // Encrypt the CEK
    let cipher = XChaCha20Poly1305::new(&wrapping_key.into());
    let encrypted_cek = cipher
        .encrypt(&nonce.into(), cek.as_slice())
        .map_err(|e| Error::StealthEncryption(e.to_string()))?;

    // Pack: ephemeral_pubkey (32) || nonce (24) || encrypted_cek (48 = 32 + 16 tag)
    let mut result = [0u8; WRAPPED_KEY_SIZE];
    result[..PUBKEY_SIZE].copy_from_slice(ephemeral_public.as_bytes());
    result[PUBKEY_SIZE..PUBKEY_SIZE + NONCE_SIZE].copy_from_slice(&nonce);
    result[PUBKEY_SIZE + NONCE_SIZE..].copy_from_slice(&encrypted_cek);

    Ok(result)
}

/// Try to decrypt a stealth-encrypted Welcome message.
///
/// This function attempts to unwrap the CEK using the recipient's stealth private key,
/// then decrypts the welcome. If successful, the payload was intended for this recipient
/// (or one of their devices).
///
/// # Arguments
///
/// * `scan_privkey` - The recipient's stealth scan private key (32 bytes)
/// * `payload` - The encrypted payload from `encrypt_for_stealth`
///
/// # Returns
///
/// `Some(welcome_bytes)` if decryption succeeds, `None` otherwise.
pub fn try_decrypt_stealth(scan_privkey: &[u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
    // Minimum size: 1 (count) + 1 wrapped key + nonce + tag
    if payload.len() < 1 + WRAPPED_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
        return None;
    }

    let num_recipients = payload[0] as usize;
    if num_recipients == 0 || num_recipients > MAX_RECIPIENTS {
        return None;
    }

    let wrapped_keys_end = 1 + num_recipients * WRAPPED_KEY_SIZE;
    if payload.len() < wrapped_keys_end + NONCE_SIZE + TAG_SIZE {
        return None;
    }

    // Try to unwrap the CEK from each wrapped key
    let mut cek: Option<[u8; CEK_SIZE]> = None;
    for i in 0..num_recipients {
        let start = 1 + i * WRAPPED_KEY_SIZE;
        let end = start + WRAPPED_KEY_SIZE;
        let wrapped_key: [u8; WRAPPED_KEY_SIZE] = payload[start..end].try_into().ok()?;

        if let Some(unwrapped) = try_unwrap_key(scan_privkey, &wrapped_key) {
            cek = Some(unwrapped);
            break;
        }
    }

    let cek = cek?;

    // Extract content nonce and encrypted welcome
    let content_nonce: [u8; NONCE_SIZE] = payload[wrapped_keys_end..wrapped_keys_end + NONCE_SIZE]
        .try_into()
        .ok()?;
    let encrypted_welcome = &payload[wrapped_keys_end + NONCE_SIZE..];

    // Decrypt the welcome
    let cipher = XChaCha20Poly1305::new(&cek.into());
    cipher.decrypt(&content_nonce.into(), encrypted_welcome).ok()
}

/// Try to unwrap a CEK using the recipient's private key.
fn try_unwrap_key(scan_privkey: &[u8; 32], wrapped_key: &[u8; WRAPPED_KEY_SIZE]) -> Option<[u8; CEK_SIZE]> {
    // Unpack: ephemeral_pubkey (32) || nonce (24) || encrypted_cek (48)
    let ephemeral_pubkey_bytes: [u8; PUBKEY_SIZE] = wrapped_key[..PUBKEY_SIZE].try_into().ok()?;
    let nonce: [u8; NONCE_SIZE] = wrapped_key[PUBKEY_SIZE..PUBKEY_SIZE + NONCE_SIZE]
        .try_into()
        .ok()?;
    let encrypted_cek = &wrapped_key[PUBKEY_SIZE + NONCE_SIZE..];

    // ECDH
    let ephemeral_public = PublicKey::from(ephemeral_pubkey_bytes);
    let privkey = StaticSecret::from(*scan_privkey);
    let shared_secret = privkey.diffie_hellman(&ephemeral_public);

    // Derive wrapping key
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut wrapping_key = [0u8; 32];
    hk.expand(STEALTH_LABEL, &mut wrapping_key).ok()?;

    // Decrypt the CEK
    let cipher = XChaCha20Poly1305::new(&wrapping_key.into());
    let cek_bytes = cipher.decrypt(&nonce.into(), encrypted_cek).ok()?;

    if cek_bytes.len() != CEK_SIZE {
        return None;
    }

    let mut cek = [0u8; CEK_SIZE];
    cek.copy_from_slice(&cek_bytes);
    Some(cek)
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
    fn test_encrypt_decrypt_single_recipient() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = b"This is a test MLS Welcome message with some content";

        // Alice encrypts for Bob (single device)
        let payload = encrypt_for_stealth(&[bob_pubkey], welcome).expect("encryption should succeed");

        // Payload should be larger than the original
        assert!(payload.len() > welcome.len());

        // Bob decrypts
        let decrypted =
            try_decrypt_stealth(&bob_privkey, &payload).expect("decryption should succeed");

        assert_eq!(decrypted, welcome);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_recipients() {
        let (bob_privkey1, bob_pubkey1) = generate_stealth_keypair();
        let (bob_privkey2, bob_pubkey2) = generate_stealth_keypair();
        let (bob_privkey3, bob_pubkey3) = generate_stealth_keypair();
        let welcome = b"Welcome message for Bob's devices";

        // Alice encrypts for all of Bob's devices
        let payload = encrypt_for_stealth(&[bob_pubkey1, bob_pubkey2, bob_pubkey3], welcome)
            .expect("encryption should succeed");

        // Any of Bob's devices can decrypt
        let decrypted1 = try_decrypt_stealth(&bob_privkey1, &payload);
        let decrypted2 = try_decrypt_stealth(&bob_privkey2, &payload);
        let decrypted3 = try_decrypt_stealth(&bob_privkey3, &payload);

        assert_eq!(decrypted1, Some(welcome.to_vec()));
        assert_eq!(decrypted2, Some(welcome.to_vec()));
        assert_eq!(decrypted3, Some(welcome.to_vec()));
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let (_bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let (eve_privkey, _eve_pubkey) = generate_stealth_keypair();
        let welcome = b"Secret message for Bob";

        // Alice encrypts for Bob
        let payload = encrypt_for_stealth(&[bob_pubkey], welcome).expect("encryption should succeed");

        // Eve tries to decrypt with her key - should fail
        let result = try_decrypt_stealth(&eve_privkey, &payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_corrupted_payload_fails() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = b"Test message";

        let mut payload =
            encrypt_for_stealth(&[bob_pubkey], welcome).expect("encryption should succeed");

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
        let short_payload = vec![0u8; 10];
        let result = try_decrypt_stealth(&bob_privkey, &short_payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_message() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = b"";

        let payload = encrypt_for_stealth(&[bob_pubkey], welcome).expect("encryption should succeed");
        let decrypted =
            try_decrypt_stealth(&bob_privkey, &payload).expect("decryption should succeed");

        assert_eq!(decrypted, welcome);
    }

    #[test]
    fn test_large_message() {
        let (bob_privkey, bob_pubkey) = generate_stealth_keypair();
        let welcome = vec![0xAB; 10000]; // 10KB message

        let payload =
            encrypt_for_stealth(&[bob_pubkey], &welcome).expect("encryption should succeed");
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
            encrypt_for_stealth(&[bob_pubkey], welcome).expect("encryption should succeed");
        let payload2 =
            encrypt_for_stealth(&[bob_pubkey], welcome).expect("encryption should succeed");

        // The payloads should be different (different ephemeral keys and nonces)
        assert_ne!(payload1, payload2);
    }

    #[test]
    fn test_no_recipients_fails() {
        let welcome = b"Test message";
        let result = encrypt_for_stealth(&[], welcome);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_device_match() {
        // Bob has 3 devices, but only device 2's key is in the recipient list
        let (bob_privkey1, _bob_pubkey1) = generate_stealth_keypair();
        let (_bob_privkey2, bob_pubkey2) = generate_stealth_keypair();
        let (bob_privkey3, bob_pubkey3) = generate_stealth_keypair();
        let welcome = b"Welcome for devices 2 and 3";

        // Alice encrypts for devices 2 and 3 only
        let payload = encrypt_for_stealth(&[bob_pubkey2, bob_pubkey3], welcome)
            .expect("encryption should succeed");

        // Device 1 cannot decrypt (not in recipient list)
        assert!(try_decrypt_stealth(&bob_privkey1, &payload).is_none());

        // Device 3 can decrypt
        assert_eq!(
            try_decrypt_stealth(&bob_privkey3, &payload),
            Some(welcome.to_vec())
        );
    }
}
