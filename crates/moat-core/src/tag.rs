//! Per-event unique tag derivation (v2)
//!
//! Each event gets a unique 16-byte tag derived from the MLS export secret,
//! sender identity, and a per-device counter. This prevents observers from
//! linking events to the same conversation by tag.
//!
//! The derivation is analogous to BIP-32 hierarchical deterministic key
//! derivation: group members who know the export secret can reconstruct
//! all valid tags, while observers see random-looking 16-byte values.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::Result;

/// Domain separation label for v2 tag derivation
const TAG_LABEL_V2: &[u8] = b"moat-event-tag-v2";

/// Default gap limit for recipient scanning
pub const TAG_GAP_LIMIT: u64 = 5;

/// MLS export_secret label for tag derivation keying material
pub const TAG_EXPORT_SECRET_LABEL: &str = "moat-event-tag-v2";

/// Length of the export secret used for tag derivation
pub const TAG_EXPORT_SECRET_LEN: usize = 32;

/// Derive a unique 16-byte tag for a single event.
///
/// # Arguments
///
/// * `export_secret` - The MLS export secret for the current group+epoch (32 bytes)
/// * `group_id` - The MLS group identifier
/// * `sender_did` - The sender's ATProto DID (UTF-8 bytes)
/// * `sender_device_id` - The sender's 16-byte device ID
/// * `counter` - Per-device counter, starting at 0 each epoch
pub fn derive_event_tag(
    export_secret: &[u8],
    group_id: &[u8],
    sender_did: &str,
    sender_device_id: &[u8; 16],
    counter: u64,
) -> Result<[u8; 16]> {
    // IKM = group_id || sender_did || sender_device_id || counter_BE
    let mut ikm = Vec::with_capacity(group_id.len() + sender_did.len() + 16 + 8);
    ikm.extend_from_slice(group_id);
    ikm.extend_from_slice(sender_did.as_bytes());
    ikm.extend_from_slice(sender_device_id);
    ikm.extend_from_slice(&counter.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(export_secret), &ikm);

    let mut tag = [0u8; 16];
    hk.expand(TAG_LABEL_V2, &mut tag)
        .expect("16 bytes is a valid output length for HKDF-SHA256");

    Ok(tag)
}

/// Generate candidate tags for recipient scanning.
///
/// Returns a vector of (tag, counter) pairs for the given window.
///
/// # Arguments
///
/// * `export_secret` - The MLS export secret for the group+epoch
/// * `group_id` - The MLS group identifier
/// * `sender_did` - The sender's ATProto DID
/// * `sender_device_id` - The sender's 16-byte device ID
/// * `from_counter` - Start of the scanning window (inclusive)
/// * `count` - Number of candidate tags to generate
pub fn generate_candidate_tags(
    export_secret: &[u8],
    group_id: &[u8],
    sender_did: &str,
    sender_device_id: &[u8; 16],
    from_counter: u64,
    count: u64,
) -> Result<Vec<([u8; 16], u64)>> {
    let mut tags = Vec::with_capacity(count as usize);
    for i in 0..count {
        let counter = from_counter + i;
        let tag = derive_event_tag(export_secret, group_id, sender_did, sender_device_id, counter)?;
        tags.push((tag, counter));
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_derivation_consistency() {
        let secret = [1u8; 32];
        let group_id = b"test-group-id-12345";
        let did = "did:plc:alice123";
        let device_id = [2u8; 16];

        let tag1 = derive_event_tag(&secret, group_id, did, &device_id, 0).unwrap();
        let tag2 = derive_event_tag(&secret, group_id, did, &device_id, 0).unwrap();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_tag_changes_with_counter() {
        let secret = [1u8; 32];
        let group_id = b"test-group";
        let did = "did:plc:alice";
        let device_id = [2u8; 16];

        let tag0 = derive_event_tag(&secret, group_id, did, &device_id, 0).unwrap();
        let tag1 = derive_event_tag(&secret, group_id, did, &device_id, 1).unwrap();
        let tag2 = derive_event_tag(&secret, group_id, did, &device_id, 2).unwrap();

        assert_ne!(tag0, tag1);
        assert_ne!(tag1, tag2);
        assert_ne!(tag0, tag2);
    }

    #[test]
    fn test_tag_changes_with_sender_did() {
        let secret = [1u8; 32];
        let group_id = b"test-group";
        let device_id = [2u8; 16];

        let tag_alice = derive_event_tag(&secret, group_id, "did:plc:alice", &device_id, 0).unwrap();
        let tag_bob = derive_event_tag(&secret, group_id, "did:plc:bob", &device_id, 0).unwrap();

        assert_ne!(tag_alice, tag_bob);
    }

    #[test]
    fn test_tag_changes_with_device_id() {
        let secret = [1u8; 32];
        let group_id = b"test-group";
        let did = "did:plc:alice";

        let tag_dev1 = derive_event_tag(&secret, group_id, did, &[1u8; 16], 0).unwrap();
        let tag_dev2 = derive_event_tag(&secret, group_id, did, &[2u8; 16], 0).unwrap();

        assert_ne!(tag_dev1, tag_dev2);
    }

    #[test]
    fn test_tag_changes_with_export_secret() {
        let group_id = b"test-group";
        let did = "did:plc:alice";
        let device_id = [2u8; 16];

        let tag_epoch1 = derive_event_tag(&[1u8; 32], group_id, did, &device_id, 0).unwrap();
        let tag_epoch2 = derive_event_tag(&[2u8; 32], group_id, did, &device_id, 0).unwrap();

        assert_ne!(tag_epoch1, tag_epoch2);
    }

    #[test]
    fn test_tag_changes_with_group() {
        let secret = [1u8; 32];
        let did = "did:plc:alice";
        let device_id = [2u8; 16];

        let tag_a = derive_event_tag(&secret, b"group-a", did, &device_id, 0).unwrap();
        let tag_b = derive_event_tag(&secret, b"group-b", did, &device_id, 0).unwrap();

        assert_ne!(tag_a, tag_b);
    }

    #[test]
    fn test_tag_is_16_bytes() {
        let tag = derive_event_tag(&[1u8; 32], b"test", "did:plc:x", &[0u8; 16], 42).unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_generate_candidate_tags() {
        let secret = [1u8; 32];
        let group_id = b"test-group";
        let did = "did:plc:alice";
        let device_id = [2u8; 16];

        let candidates = generate_candidate_tags(&secret, group_id, did, &device_id, 3, 5).unwrap();
        assert_eq!(candidates.len(), 5);
        assert_eq!(candidates[0].1, 3);
        assert_eq!(candidates[4].1, 7);

        // Each tag should be unique
        for i in 0..candidates.len() {
            for j in (i + 1)..candidates.len() {
                assert_ne!(candidates[i].0, candidates[j].0);
            }
        }

        // Tags should match individual derivation
        for (tag, counter) in &candidates {
            let expected = derive_event_tag(&secret, group_id, did, &device_id, *counter).unwrap();
            assert_eq!(tag, &expected);
        }
    }
}
