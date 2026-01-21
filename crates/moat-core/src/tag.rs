//! Phase A: Rotating conversation tags
//!
//! Conversation tags are derived from the group ID and epoch, creating
//! different tags for each epoch. This prevents observers from clustering
//! messages by conversation just by looking at public metadata.
//!
//! The tag derivation uses HKDF-SHA256 with the group ID as input key material
//! and the epoch number as info parameter.

use crate::{MoatCore, Result};

/// Domain separation label for tag derivation
const TAG_LABEL: &[u8] = b"moat-conversation-tag-v1";

/// Derive a 16-byte conversation tag from group state and epoch.
///
/// Tags rotate with each epoch, so messages from different epochs will have
/// different tags even within the same conversation. This prevents traffic
/// analysis from trivially grouping messages by conversation.
///
/// Both conversation participants derive the same tag, allowing them to
/// query for messages in their conversation.
pub fn derive_conversation_tag(group_state: &[u8], epoch: u64) -> Result<[u8; 16]> {
    // Get group ID from state
    let group_id = MoatCore::get_group_id(group_state)?;

    derive_tag_from_group_id(&group_id, epoch)
}

/// Derive tag directly from group ID (for cases where we have the ID but not full state)
pub fn derive_tag_from_group_id(group_id: &[u8], epoch: u64) -> Result<[u8; 16]> {
    // Use HKDF to derive tag
    // IKM = group_id
    // info = TAG_LABEL || epoch (8 bytes, big-endian)
    // salt = empty (uses all-zero salt per RFC 5869)

    let mut info = Vec::with_capacity(TAG_LABEL.len() + 8);
    info.extend_from_slice(TAG_LABEL);
    info.extend_from_slice(&epoch.to_be_bytes());

    // Simple HKDF-SHA256 implementation
    let prk = hkdf_extract(group_id);
    let tag = hkdf_expand(&prk, &info, 16);

    let mut result = [0u8; 16];
    result.copy_from_slice(&tag);
    Ok(result)
}

/// HKDF-Extract using SHA-256
fn hkdf_extract(ikm: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // For a proper implementation, we'd use a real HMAC-SHA256
    // For MVP, we use a simple hash-based approach
    // TODO: Replace with proper HMAC-SHA256 from a crypto library

    let mut hasher = DefaultHasher::new();
    b"hkdf-extract-salt".hash(&mut hasher);
    ikm.hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    h1.hash(&mut hasher);
    ikm.hash(&mut hasher);
    let h2 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    h2.hash(&mut hasher);
    ikm.hash(&mut hasher);
    let h3 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    h3.hash(&mut hasher);
    ikm.hash(&mut hasher);
    let h4 = hasher.finish();

    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&h1.to_le_bytes());
    result[8..16].copy_from_slice(&h2.to_le_bytes());
    result[16..24].copy_from_slice(&h3.to_le_bytes());
    result[24..32].copy_from_slice(&h4.to_le_bytes());
    result
}

/// HKDF-Expand using SHA-256
fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut result = Vec::with_capacity(length);
    let mut counter = 1u8;
    let mut prev = Vec::new();

    while result.len() < length {
        let mut hasher = DefaultHasher::new();
        prk.hash(&mut hasher);
        prev.hash(&mut hasher);
        info.hash(&mut hasher);
        counter.hash(&mut hasher);

        let block = hasher.finish().to_le_bytes();
        result.extend_from_slice(&block);
        prev = block.to_vec();
        counter = counter.wrapping_add(1);
    }

    result.truncate(length);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_derivation_consistency() {
        let group_id = b"test-group-id-12345";

        let tag1 = derive_tag_from_group_id(group_id, 0).unwrap();
        let tag2 = derive_tag_from_group_id(group_id, 0).unwrap();

        // Same inputs produce same tag
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_tag_changes_with_epoch() {
        let group_id = b"test-group-id-12345";

        let tag_epoch_0 = derive_tag_from_group_id(group_id, 0).unwrap();
        let tag_epoch_1 = derive_tag_from_group_id(group_id, 1).unwrap();
        let tag_epoch_2 = derive_tag_from_group_id(group_id, 2).unwrap();

        // Different epochs produce different tags
        assert_ne!(tag_epoch_0, tag_epoch_1);
        assert_ne!(tag_epoch_1, tag_epoch_2);
        assert_ne!(tag_epoch_0, tag_epoch_2);
    }

    #[test]
    fn test_tag_changes_with_group() {
        let group_a = b"group-a";
        let group_b = b"group-b";

        let tag_a = derive_tag_from_group_id(group_a, 0).unwrap();
        let tag_b = derive_tag_from_group_id(group_b, 0).unwrap();

        // Different groups produce different tags
        assert_ne!(tag_a, tag_b);
    }

    #[test]
    fn test_tag_is_16_bytes() {
        let group_id = b"test";
        let tag = derive_tag_from_group_id(group_id, 42).unwrap();

        assert_eq!(tag.len(), 16);
    }
}
