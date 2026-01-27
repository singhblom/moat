//! Integration tests for moat-core

use crate::{derive_tag_from_group_id, pad_to_bucket, unpad, Event, EventKind, MoatCore};

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
        vec![0xAB; 300],  // Medium bucket
        vec![0xCD; 1500], // Large bucket
    ];

    for msg in messages {
        let padded = pad_to_bucket(&msg);
        let recovered = unpad(&padded);
        assert_eq!(recovered, msg, "Padding round-trip should preserve content");
    }
}

#[test]
fn test_event_creation() {
    let event = Event::message(b"group-123".to_vec(), 5, b"Hello, world!");
    assert_eq!(event.kind, EventKind::Message);
    assert_eq!(event.group_id, b"group-123");
    assert_eq!(event.epoch, 5);
    assert_eq!(event.payload, b"Hello, world!");
}

#[test]
fn test_event_roundtrip() {
    let event = Event::message(b"group-123".to_vec(), 5, b"Hello, world!");

    let bytes = event.to_bytes().unwrap();
    let recovered = Event::from_bytes(&bytes).unwrap();

    assert_eq!(recovered.kind, EventKind::Message);
    assert_eq!(recovered.group_id, b"group-123");
    assert_eq!(recovered.epoch, 5);
    assert_eq!(recovered.payload, b"Hello, world!");
}

#[test]
fn test_event_kinds() {
    let msg = Event::message(vec![], 0, b"text");
    assert_eq!(msg.kind, EventKind::Message);

    let commit = Event::commit(vec![], 0, vec![1, 2, 3]);
    assert_eq!(commit.kind, EventKind::Commit);

    let welcome = Event::welcome(vec![], 0, vec![4, 5, 6]);
    assert_eq!(welcome.kind, EventKind::Welcome);

    let checkpoint = Event::checkpoint(vec![], 0, vec![7, 8, 9]);
    assert_eq!(checkpoint.kind, EventKind::Checkpoint);
}

#[test]
fn test_event_with_device_id() {
    let event = Event::message(vec![], 0, b"test").with_device_id("device-1".to_string());
    assert_eq!(event.sender_device_id, Some("device-1".to_string()));
}

#[test]
fn test_get_current_tag() {
    let identity = b"alice@example.com";
    let (_key_package, key_bundle) = MoatCore::generate_key_package(identity).unwrap();
    let group_state = MoatCore::create_group(identity, &key_bundle).unwrap();

    // Should be able to derive tag
    let tag = MoatCore::get_current_tag(&group_state).unwrap();
    assert_eq!(tag.len(), 16);

    // Tag should be consistent
    let tag2 = MoatCore::get_current_tag(&group_state).unwrap();
    assert_eq!(tag, tag2);
}

#[test]
fn test_get_tags_for_epochs() {
    let identity = b"alice@example.com";
    let (_key_package, key_bundle) = MoatCore::generate_key_package(identity).unwrap();
    let group_state = MoatCore::create_group(identity, &key_bundle).unwrap();

    let epochs = vec![0, 1, 2, 3];
    let tags = MoatCore::get_tags_for_epochs(&group_state, &epochs).unwrap();

    assert_eq!(tags.len(), 4);

    // All tags should be different
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i], tags[j], "Tags for different epochs should differ");
        }
    }
}

#[test]
fn test_tag_derived_from_group_state() {
    // Create a group
    let identity = b"alice@example.com";
    let (_key_package, key_bundle) = MoatCore::generate_key_package(identity).unwrap();
    let group_state = MoatCore::create_group(identity, &key_bundle).unwrap();

    // Get tag from group state
    let tag_from_state = MoatCore::get_current_tag(&group_state).unwrap();

    // Get tag directly from group ID and epoch
    let group_id = MoatCore::get_group_id(&group_state).unwrap();
    let epoch = MoatCore::get_epoch(&group_state).unwrap();
    let tag_direct = derive_tag_from_group_id(&group_id, epoch).unwrap();

    // Should match
    assert_eq!(tag_from_state, tag_direct);
}

#[test]
fn test_event_serialization_with_padding() {
    // Test that events can be serialized, padded, and recovered
    let event = Event::message(b"group-xyz".to_vec(), 42, b"Hello, this is a test message!");

    // Serialize
    let event_bytes = event.to_bytes().unwrap();

    // Pad
    let padded = pad_to_bucket(&event_bytes);
    assert_eq!(padded.len(), 256); // Should fit in small bucket

    // Unpad
    let unpadded = unpad(&padded);

    // Deserialize
    let recovered = Event::from_bytes(&unpadded).unwrap();

    assert_eq!(recovered.kind, EventKind::Message);
    assert_eq!(recovered.group_id, b"group-xyz");
    assert_eq!(recovered.epoch, 42);
    assert_eq!(recovered.payload, b"Hello, this is a test message!");
}

#[test]
fn test_moat_session_in_memory() {
    use crate::MoatSession;

    let session = MoatSession::new();

    // Generate key package
    let identity = b"alice@example.com";
    let (key_package, key_bundle) = session.generate_key_package(identity).unwrap();

    assert!(!key_package.is_empty());
    assert!(!key_bundle.is_empty());

    // Create a group
    let group_id = session.create_group(identity, &key_bundle).unwrap();
    assert!(!group_id.is_empty());

    // Should be able to load the group back
    let loaded_group = session.load_group(&group_id).unwrap();
    assert!(loaded_group.is_some());
}

#[test]
fn test_moat_session_persistence() {
    use crate::MoatSession;

    let group_id: Vec<u8>;
    let identity = b"alice@example.com";
    let state: Vec<u8>;

    // First session: create group, export state
    {
        let session = MoatSession::new();

        let (_key_package, key_bundle) = session.generate_key_package(identity).unwrap();
        group_id = session.create_group(identity, &key_bundle).unwrap();

        // Verify group is accessible
        let loaded = session.load_group(&group_id).unwrap();
        assert!(loaded.is_some(), "Group should be loadable in same session");

        // Export state (like writing to a file)
        state = session.export_state().unwrap();
    }

    // Second session: restore from exported state
    {
        let session = MoatSession::from_state(&state).unwrap();

        // Group should still be accessible
        let loaded = session.load_group(&group_id).unwrap();
        assert!(loaded.is_some(), "Group should be loadable after restore");
    }
}

#[test]
fn test_encrypt_event() {
    use crate::{MoatSession, Event};

    let session = MoatSession::new();

    // Create Alice
    let alice_identity = b"alice@example.com";
    let (_alice_kp, alice_bundle) = session.generate_key_package(alice_identity).unwrap();
    let group_id = session.create_group(alice_identity, &alice_bundle).unwrap();

    // Create an event
    let original_event = Event::message(group_id.clone(), 0, b"Hello, world!");

    // Encrypt
    let encrypt_result = session.encrypt_event(&group_id, &alice_bundle, &original_event).unwrap();
    assert!(!encrypt_result.ciphertext.is_empty());
    assert_eq!(encrypt_result.tag.len(), 16);

    // Note: In MLS, a sender cannot decrypt their own messages.
    // Full encrypt/decrypt test requires two parties (see test_two_party_messaging).
}

#[test]
fn test_two_party_messaging() {
    use crate::{MoatSession, Event};

    // Create separate sessions for Alice and Bob
    let alice_session = MoatSession::new();
    let bob_session = MoatSession::new();

    // Alice creates her identity
    let alice_identity = b"alice@example.com";
    let (_alice_kp, alice_bundle) = alice_session.generate_key_package(alice_identity).unwrap();

    // Bob creates his identity
    let bob_identity = b"bob@example.com";
    let (bob_kp, bob_bundle) = bob_session.generate_key_package(bob_identity).unwrap();

    // Alice creates a group
    let group_id = alice_session.create_group(alice_identity, &alice_bundle).unwrap();

    // Alice adds Bob to the group
    let welcome_result = alice_session.add_member(&group_id, &alice_bundle, &bob_kp).unwrap();
    assert!(!welcome_result.welcome.is_empty());
    assert!(!welcome_result.commit.is_empty());

    // Bob joins using the welcome
    let bob_group_id = bob_session.process_welcome(&welcome_result.welcome).unwrap();
    assert_eq!(bob_group_id, group_id);

    // Alice sends a message
    let message = Event::message(group_id.clone(), 0, b"Hello Bob!");
    let encrypted = alice_session.encrypt_event(&group_id, &alice_bundle, &message).unwrap();

    // Bob decrypts the message
    let decrypted = bob_session.decrypt_event(&bob_group_id, &encrypted.ciphertext).unwrap();
    assert_eq!(decrypted.event.kind, EventKind::Message);
    assert_eq!(decrypted.event.payload, b"Hello Bob!");

    // Bob replies
    let reply = Event::message(group_id.clone(), 0, b"Hello Alice!");
    let encrypted_reply = bob_session.encrypt_event(&bob_group_id, &bob_bundle, &reply).unwrap();

    // Alice decrypts Bob's reply
    let decrypted_reply = alice_session.decrypt_event(&group_id, &encrypted_reply.ciphertext).unwrap();
    assert_eq!(decrypted_reply.event.kind, EventKind::Message);
    assert_eq!(decrypted_reply.event.payload, b"Hello Alice!");
}

#[test]
fn test_state_version_header() {
    use crate::MoatSession;

    let session = MoatSession::new();
    let state = session.export_state().unwrap();

    // Check magic bytes
    assert_eq!(&state[0..4], b"MOAT");

    // Check version (little-endian u16 = 1)
    assert_eq!(state[4], 1);
    assert_eq!(state[5], 0);

    // Header is at least 22 bytes (4 magic + 2 version + 16 device_id)
    assert!(state.len() >= 22);
}

#[test]
fn test_state_rejects_invalid_magic() {
    use crate::MoatSession;

    let bad_state = b"BADXsome data here plus padding!";
    let result = MoatSession::from_state(bad_state);
    assert!(result.is_err());
}

#[test]
fn test_state_rejects_unsupported_version() {
    use crate::MoatSession;

    let mut state = vec![0u8; 30];
    state[0..4].copy_from_slice(b"MOAT");
    state[4..6].copy_from_slice(&99u16.to_le_bytes()); // unsupported version
    let result = MoatSession::from_state(&state);
    assert!(result.is_err());
}

#[test]
fn test_state_rejects_too_short() {
    use crate::MoatSession;

    let result = MoatSession::from_state(b"MOAT");
    assert!(result.is_err());
}

#[test]
fn test_device_id_persists() {
    use crate::MoatSession;

    let session = MoatSession::new();
    let device_id = *session.device_id();

    // Device ID should be non-zero (extremely unlikely to be all zeros)
    assert_ne!(device_id, [0u8; 16]);

    // Export and restore
    let state = session.export_state().unwrap();
    let session2 = MoatSession::from_state(&state).unwrap();

    assert_eq!(*session2.device_id(), device_id);
}

#[test]
fn test_device_id_unique_per_session() {
    use crate::MoatSession;

    let session1 = MoatSession::new();
    let session2 = MoatSession::new();

    // Two sessions should have different device IDs
    assert_ne!(session1.device_id(), session2.device_id());
}
