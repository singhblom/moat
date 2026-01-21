//! Integration tests for moat-core

use crate::{derive_tag_from_group_id, pad_to_bucket, unpad, MoatCore};

#[test]
fn test_key_package_generation() {
    let identity = b"alice@example.com";

    let result = MoatCore::generate_key_package(identity);
    assert!(result.is_ok(), "Key package generation should succeed");

    let (key_package, key_bundle) = result.unwrap();

    // Key package should be non-empty
    assert!(!key_package.is_empty());
    assert!(!key_bundle.is_empty());

    // Generating again should produce different results (due to randomness)
    let (key_package2, key_bundle2) = MoatCore::generate_key_package(identity).unwrap();
    assert_ne!(key_package, key_package2);
    assert_ne!(key_bundle, key_bundle2);
}

#[test]
fn test_create_group() {
    let identity = b"alice@example.com";
    let (_key_package, key_bundle) = MoatCore::generate_key_package(identity).unwrap();

    let group_state = MoatCore::create_group(identity, &key_bundle).unwrap();

    // Group state should be non-empty
    assert!(!group_state.is_empty());

    // Should be able to get epoch (starts at 0)
    let epoch = MoatCore::get_epoch(&group_state).unwrap();
    assert_eq!(epoch, 0);

    // Should be able to get group ID
    let group_id = MoatCore::get_group_id(&group_state).unwrap();
    assert!(!group_id.is_empty());
}

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
fn test_padding_small_message() {
    let plaintext = b"Hello, world!";
    let padded = pad_to_bucket(plaintext);

    assert_eq!(padded.len(), 256);
    assert_eq!(unpad(&padded), plaintext);
}

#[test]
fn test_padding_medium_message() {
    let plaintext = vec![0x42; 500];
    let padded = pad_to_bucket(&plaintext);

    assert_eq!(padded.len(), 1024);
    assert_eq!(unpad(&padded), plaintext);
}

#[test]
fn test_padding_large_message() {
    let plaintext = vec![0x42; 2000];
    let padded = pad_to_bucket(&plaintext);

    assert_eq!(padded.len(), 4096);
    assert_eq!(unpad(&padded), plaintext);
}

#[test]
fn test_padding_preserves_content() {
    let messages = vec![
        b"Short".to_vec(),
        b"A slightly longer message".to_vec(),
        vec![0xAB; 300], // Medium bucket
        vec![0xCD; 1500], // Large bucket
    ];

    for msg in messages {
        let padded = pad_to_bucket(&msg);
        let recovered = unpad(&padded);
        assert_eq!(recovered, msg, "Padding round-trip should preserve content");
    }
}
