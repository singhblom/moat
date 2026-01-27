//! Phase A: Rotating conversation tags
//!
//! Conversation tags are derived from the group ID and epoch, creating
//! different tags for each epoch. This prevents observers from clustering
//! messages by conversation just by looking at public metadata.
//!
//! The tag derivation uses HKDF-SHA256 with the group ID as input key material
//! and the epoch number as info parameter.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::Result;

/// Domain separation label for tag derivation
const TAG_LABEL: &[u8] = b"moat-conversation-tag-v1";

/// Derive a 16-byte conversation tag from a group ID and epoch.
pub fn derive_tag_from_group_id(group_id: &[u8], epoch: u64) -> Result<[u8; 16]> {
    // Use HKDF-SHA256 to derive tag
    // IKM = group_id
    // salt = TAG_LABEL (domain separation)
    // info = epoch (8 bytes, big-endian)

    let hk = Hkdf::<Sha256>::new(Some(TAG_LABEL), group_id);

    let info = epoch.to_be_bytes();
    let mut tag = [0u8; 16];

    hk.expand(&info, &mut tag)
        .expect("16 bytes is a valid output length for HKDF-SHA256");

    Ok(tag)
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

    #[test]
    fn test_tag_high_epoch_values() {
        let group_id = b"test";

        // Should work with high epoch values
        let tag_max = derive_tag_from_group_id(group_id, u64::MAX).unwrap();
        let tag_near_max = derive_tag_from_group_id(group_id, u64::MAX - 1).unwrap();

        assert_ne!(tag_max, tag_near_max);
    }
}
