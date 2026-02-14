use moat_core::{pad_to_bucket, unpad, Bucket, derive_event_tag};
use proptest::prelude::*;

proptest! {
    // --- Padding properties ---

    #[test]
    fn pad_unpad_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..4092)) {
        let padded = pad_to_bucket(&data);
        let recovered = unpad(&padded);
        prop_assert_eq!(&recovered, &data);
    }

    #[test]
    fn padded_size_is_valid_bucket(data in proptest::collection::vec(any::<u8>(), 0..4092)) {
        let padded = pad_to_bucket(&data);
        let len = padded.len();
        prop_assert!(
            len == 256 || len == 1024 || len == 4096,
            "padded length {} is not a valid bucket size", len
        );
    }

    #[test]
    fn bucket_selection_matches_padded_size(data in proptest::collection::vec(any::<u8>(), 0..4092)) {
        let bucket = Bucket::for_size(data.len());
        let padded = pad_to_bucket(&data);
        prop_assert_eq!(padded.len(), bucket.size());
    }

    #[test]
    fn padding_at_bucket_boundaries(len in 0usize..4092) {
        let data = vec![0x42; len];
        let padded = pad_to_bucket(&data);
        let expected_bucket = Bucket::for_size(len);
        prop_assert_eq!(padded.len(), expected_bucket.size());

        // Verify content survives
        let recovered = unpad(&padded);
        prop_assert_eq!(recovered, data);
    }

    // --- Tag derivation properties ---

    #[test]
    fn tag_is_always_16_bytes(
        export_secret in proptest::collection::vec(any::<u8>(), 32..=32),
        group_id in proptest::collection::vec(any::<u8>(), 1..64),
        counter in any::<u64>(),
    ) {
        let tag = derive_event_tag(&export_secret, &group_id, "did:plc:test", &[0u8; 16], counter).unwrap();
        prop_assert_eq!(tag.len(), 16);
    }

    #[test]
    fn tag_is_deterministic(
        export_secret in proptest::collection::vec(any::<u8>(), 32..=32),
        group_id in proptest::collection::vec(any::<u8>(), 1..64),
        counter in any::<u64>(),
    ) {
        let tag1 = derive_event_tag(&export_secret, &group_id, "did:plc:test", &[0u8; 16], counter).unwrap();
        let tag2 = derive_event_tag(&export_secret, &group_id, "did:plc:test", &[0u8; 16], counter).unwrap();
        prop_assert_eq!(tag1, tag2);
    }

    #[test]
    fn different_counters_produce_different_tags(
        export_secret in proptest::collection::vec(any::<u8>(), 32..=32),
        group_id in proptest::collection::vec(any::<u8>(), 1..64),
        counter1 in any::<u64>(),
        counter2 in any::<u64>(),
    ) {
        prop_assume!(counter1 != counter2);
        let tag1 = derive_event_tag(&export_secret, &group_id, "did:plc:test", &[0u8; 16], counter1).unwrap();
        let tag2 = derive_event_tag(&export_secret, &group_id, "did:plc:test", &[0u8; 16], counter2).unwrap();
        prop_assert_ne!(tag1, tag2);
    }

    #[test]
    fn different_groups_produce_different_tags(
        export_secret in proptest::collection::vec(any::<u8>(), 32..=32),
        group_id1 in proptest::collection::vec(any::<u8>(), 1..64),
        group_id2 in proptest::collection::vec(any::<u8>(), 1..64),
        counter in any::<u64>(),
    ) {
        prop_assume!(group_id1 != group_id2);
        let tag1 = derive_event_tag(&export_secret, &group_id1, "did:plc:test", &[0u8; 16], counter).unwrap();
        let tag2 = derive_event_tag(&export_secret, &group_id2, "did:plc:test", &[0u8; 16], counter).unwrap();
        prop_assert_ne!(tag1, tag2);
    }
}
