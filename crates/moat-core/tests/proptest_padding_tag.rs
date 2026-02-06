use moat_core::{pad_to_bucket, unpad, Bucket, derive_tag_from_group_id};
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
        group_id in proptest::collection::vec(any::<u8>(), 1..64),
        epoch in any::<u64>(),
    ) {
        let tag = derive_tag_from_group_id(&group_id, epoch).unwrap();
        prop_assert_eq!(tag.len(), 16);
    }

    #[test]
    fn tag_is_deterministic(
        group_id in proptest::collection::vec(any::<u8>(), 1..64),
        epoch in any::<u64>(),
    ) {
        let tag1 = derive_tag_from_group_id(&group_id, epoch).unwrap();
        let tag2 = derive_tag_from_group_id(&group_id, epoch).unwrap();
        prop_assert_eq!(tag1, tag2);
    }

    #[test]
    fn different_epochs_produce_different_tags(
        group_id in proptest::collection::vec(any::<u8>(), 1..64),
        epoch1 in any::<u64>(),
        epoch2 in any::<u64>(),
    ) {
        prop_assume!(epoch1 != epoch2);
        let tag1 = derive_tag_from_group_id(&group_id, epoch1).unwrap();
        let tag2 = derive_tag_from_group_id(&group_id, epoch2).unwrap();
        prop_assert_ne!(tag1, tag2);
    }

    #[test]
    fn different_groups_produce_different_tags(
        group_id1 in proptest::collection::vec(any::<u8>(), 1..64),
        group_id2 in proptest::collection::vec(any::<u8>(), 1..64),
        epoch in any::<u64>(),
    ) {
        prop_assume!(group_id1 != group_id2);
        let tag1 = derive_tag_from_group_id(&group_id1, epoch).unwrap();
        let tag2 = derive_tag_from_group_id(&group_id2, epoch).unwrap();
        // With overwhelming probability, different inputs produce different tags.
        // HKDF is a PRF so collisions are negligible for distinct inputs.
        prop_assert_ne!(tag1, tag2);
    }
}
