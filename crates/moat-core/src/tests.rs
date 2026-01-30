//! Integration tests for moat-core

use crate::{derive_tag_from_group_id, pad_to_bucket, unpad, Event, EventKind, Error, ErrorCode, MoatCredential, MoatSession};

#[test]
fn test_key_package_generation() {
    let session = MoatSession::new();
    let credential = MoatCredential::new("did:plc:alice123", "Test Device");

    let (key_package, key_bundle) = session.generate_key_package(&credential).unwrap();

    // Key package should be non-empty
    assert!(!key_package.is_empty());
    assert!(!key_bundle.is_empty());

    // Generating again should produce different results (due to randomness)
    let (key_package2, key_bundle2) = session.generate_key_package(&credential).unwrap();
    assert_ne!(key_package, key_package2);
    assert_ne!(key_bundle, key_bundle2);
}

#[test]
fn test_create_group() {
    let session = MoatSession::new();
    let credential = MoatCredential::new("did:plc:alice123", "Test Device");
    let (_key_package, key_bundle) = session.generate_key_package(&credential).unwrap();

    let group_id = session.create_group(&credential, &key_bundle).unwrap();

    // Group ID should be non-empty
    assert!(!group_id.is_empty());

    // Should be able to get epoch (starts at 0)
    let epoch = session.get_group_epoch(&group_id).unwrap();
    assert_eq!(epoch, Some(0));
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
fn test_tag_from_group() {
    let session = MoatSession::new();
    let credential = MoatCredential::new("did:plc:alice123", "Test Device");
    let (_key_package, key_bundle) = session.generate_key_package(&credential).unwrap();
    let group_id = session.create_group(&credential, &key_bundle).unwrap();

    // Derive tag from group_id and epoch
    let epoch = session.get_group_epoch(&group_id).unwrap().unwrap();
    let tag = derive_tag_from_group_id(&group_id, epoch).unwrap();
    assert_eq!(tag.len(), 16);

    // Tag should be consistent
    let tag2 = derive_tag_from_group_id(&group_id, epoch).unwrap();
    assert_eq!(tag, tag2);
}

#[test]
fn test_tags_differ_across_epochs() {
    let session = MoatSession::new();
    let credential = MoatCredential::new("did:plc:alice123", "Test Device");
    let (_key_package, key_bundle) = session.generate_key_package(&credential).unwrap();
    let group_id = session.create_group(&credential, &key_bundle).unwrap();

    let epochs = vec![0, 1, 2, 3];
    let tags: Vec<[u8; 16]> = epochs
        .iter()
        .map(|&ep| derive_tag_from_group_id(&group_id, ep).unwrap())
        .collect();

    assert_eq!(tags.len(), 4);

    // All tags should be different
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i], tags[j], "Tags for different epochs should differ");
        }
    }
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
    let session = MoatSession::new();

    // Generate key package
    let credential = MoatCredential::new("did:plc:alice123", "Test Device");
    let (key_package, key_bundle) = session.generate_key_package(&credential).unwrap();

    assert!(!key_package.is_empty());
    assert!(!key_bundle.is_empty());

    // Create a group
    let group_id = session.create_group(&credential, &key_bundle).unwrap();
    assert!(!group_id.is_empty());

    // Should be able to get epoch
    let epoch = session.get_group_epoch(&group_id).unwrap();
    assert_eq!(epoch, Some(0));
}

#[test]
fn test_moat_session_persistence() {
    let group_id: Vec<u8>;
    let credential = MoatCredential::new("did:plc:alice123", "Test Device");
    let state: Vec<u8>;

    // First session: create group, export state
    {
        let session = MoatSession::new();

        let (_key_package, key_bundle) = session.generate_key_package(&credential).unwrap();
        group_id = session.create_group(&credential, &key_bundle).unwrap();

        // Verify group is accessible
        let epoch = session.get_group_epoch(&group_id).unwrap();
        assert!(epoch.is_some(), "Group should be loadable in same session");

        // Export state (like writing to a file)
        state = session.export_state().unwrap();
    }

    // Second session: restore from exported state
    {
        let session = MoatSession::from_state(&state).unwrap();

        // Group should still be accessible
        let epoch = session.get_group_epoch(&group_id).unwrap();
        assert!(epoch.is_some(), "Group should be loadable after restore");
    }
}

#[test]
fn test_encrypt_event() {
    let session = MoatSession::new();

    // Create Alice
    let alice_credential = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let (_alice_kp, alice_bundle) = session.generate_key_package(&alice_credential).unwrap();
    let group_id = session.create_group(&alice_credential, &alice_bundle).unwrap();

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
    // Create separate sessions for Alice and Bob
    let alice_session = MoatSession::new();
    let bob_session = MoatSession::new();

    // Alice creates her identity with device name
    let alice_credential = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let (_alice_kp, alice_bundle) = alice_session.generate_key_package(&alice_credential).unwrap();

    // Bob creates his identity with device name
    let bob_credential = MoatCredential::new("did:plc:bob456", "Bob Laptop");
    let (bob_kp, bob_bundle) = bob_session.generate_key_package(&bob_credential).unwrap();

    // Alice creates a group
    let group_id = alice_session.create_group(&alice_credential, &alice_bundle).unwrap();

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

    // Bob decrypts the message and gets sender info
    let decrypted = bob_session.decrypt_event(&bob_group_id, &encrypted.ciphertext).unwrap();
    assert_eq!(decrypted.event.kind, EventKind::Message);
    assert_eq!(decrypted.event.payload, b"Hello Bob!");

    // Verify sender info is extracted
    let sender = decrypted.sender.expect("Should have sender info");
    assert_eq!(sender.did, "did:plc:alice123");
    assert_eq!(sender.device_name, "Alice Phone");

    // Bob replies
    let reply = Event::message(group_id.clone(), 0, b"Hello Alice!");
    let encrypted_reply = bob_session.encrypt_event(&bob_group_id, &bob_bundle, &reply).unwrap();

    // Alice decrypts Bob's reply and gets sender info
    let decrypted_reply = alice_session.decrypt_event(&group_id, &encrypted_reply.ciphertext).unwrap();
    assert_eq!(decrypted_reply.event.kind, EventKind::Message);
    assert_eq!(decrypted_reply.event.payload, b"Hello Alice!");

    // Verify sender info
    let sender = decrypted_reply.sender.expect("Should have sender info");
    assert_eq!(sender.did, "did:plc:bob456");
    assert_eq!(sender.device_name, "Bob Laptop");
}

#[test]
fn test_state_version_header() {
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
    let bad_state = b"BADXsome data here plus padding!";
    let result = MoatSession::from_state(bad_state);
    assert!(result.is_err());
}

#[test]
fn test_state_rejects_unsupported_version() {
    let mut state = vec![0u8; 30];
    state[0..4].copy_from_slice(b"MOAT");
    state[4..6].copy_from_slice(&99u16.to_le_bytes()); // unsupported version
    let result = MoatSession::from_state(&state);
    assert!(result.is_err());
}

#[test]
fn test_state_rejects_too_short() {
    let result = MoatSession::from_state(b"MOAT");
    assert!(result.is_err());
}

#[test]
fn test_device_id_persists() {
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
    let session1 = MoatSession::new();
    let session2 = MoatSession::new();

    // Two sessions should have different device IDs
    assert_ne!(session1.device_id(), session2.device_id());
}

#[test]
fn test_error_code_values() {
    // Verify repr(u32) values are stable (FFI consumers depend on these)
    assert_eq!(ErrorCode::KeyGeneration as u32, 1);
    assert_eq!(ErrorCode::KeyPackageGeneration as u32, 2);
    assert_eq!(ErrorCode::KeyPackageValidation as u32, 3);
    assert_eq!(ErrorCode::GroupCreation as u32, 4);
    assert_eq!(ErrorCode::GroupLoad as u32, 5);
    assert_eq!(ErrorCode::Storage as u32, 6);
    assert_eq!(ErrorCode::Serialization as u32, 7);
    assert_eq!(ErrorCode::Deserialization as u32, 8);
    assert_eq!(ErrorCode::InvalidMessageType as u32, 9);
    assert_eq!(ErrorCode::AddMember as u32, 10);
    assert_eq!(ErrorCode::MergeCommit as u32, 11);
    assert_eq!(ErrorCode::ProcessWelcome as u32, 12);
    assert_eq!(ErrorCode::Encryption as u32, 13);
    assert_eq!(ErrorCode::Decryption as u32, 14);
    assert_eq!(ErrorCode::ProcessCommit as u32, 15);
    assert_eq!(ErrorCode::TagDerivation as u32, 16);
    assert_eq!(ErrorCode::StealthEncryption as u32, 17);
    assert_eq!(ErrorCode::RemoveMember as u32, 18);
}

#[test]
fn test_error_code_and_message_accessors() {
    let err = Error::Deserialization("bad data".into());
    assert_eq!(err.code(), ErrorCode::Deserialization);
    assert_eq!(err.message(), "bad data");

    let err = Error::Encryption("key expired".into());
    assert_eq!(err.code(), ErrorCode::Encryption);
    assert_eq!(err.message(), "key expired");
}

#[test]
fn test_error_code_from_real_failure() {
    // from_state with invalid data should produce a Deserialization error
    let result = MoatSession::from_state(b"BADXsome data here plus padding!");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.code(), ErrorCode::Deserialization);
    assert!(!err.message().is_empty());
}

// Multi-device support tests

#[test]
fn test_moat_credential_creation() {
    let cred = MoatCredential::new("did:plc:test123", "My Phone");
    assert_eq!(cred.did(), "did:plc:test123");
    assert_eq!(cred.device_name(), "My Phone");
}

#[test]
fn test_moat_credential_serialization() {
    let cred = MoatCredential::new("did:plc:abc", "Work Laptop");
    let bytes = cred.to_bytes().unwrap();
    let recovered = MoatCredential::from_bytes(&bytes).unwrap();
    assert_eq!(cred.did(), recovered.did());
    assert_eq!(cred.device_name(), recovered.device_name());
}

#[test]
fn test_extract_credential_from_key_package() {
    let session = MoatSession::new();
    let credential = MoatCredential::new("did:plc:xyz789", "Test Device");

    let (key_package_bytes, _key_bundle) = session.generate_key_package(&credential).unwrap();

    // Extract credential from key package
    let extracted = session.extract_credential_from_key_package(&key_package_bytes).unwrap();
    let extracted = extracted.expect("Should be able to extract credential");

    assert_eq!(extracted.did(), "did:plc:xyz789");
    assert_eq!(extracted.device_name(), "Test Device");
}

#[test]
fn test_get_group_members() {
    let alice_session = MoatSession::new();
    let bob_session = MoatSession::new();

    let alice_credential = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let bob_credential = MoatCredential::new("did:plc:bob456", "Bob Laptop");

    let (_alice_kp, alice_bundle) = alice_session.generate_key_package(&alice_credential).unwrap();
    let (bob_kp, _bob_bundle) = bob_session.generate_key_package(&bob_credential).unwrap();

    // Alice creates a group
    let group_id = alice_session.create_group(&alice_credential, &alice_bundle).unwrap();

    // Check members before adding Bob
    let members = alice_session.get_group_members(&group_id).unwrap();
    assert_eq!(members.len(), 1);
    let (_, alice_cred) = &members[0];
    let alice_cred = alice_cred.as_ref().expect("Should have credential");
    assert_eq!(alice_cred.did(), "did:plc:alice123");

    // Add Bob
    let _welcome = alice_session.add_member(&group_id, &alice_bundle, &bob_kp).unwrap();

    // Check members after adding Bob
    let members = alice_session.get_group_members(&group_id).unwrap();
    assert_eq!(members.len(), 2);

    // Find Bob's credential
    let bob_found = members.iter().any(|(_, cred)| {
        cred.as_ref().map_or(false, |c| c.did() == "did:plc:bob456")
    });
    assert!(bob_found, "Bob should be in the group");
}

#[test]
fn test_multi_device_same_did() {
    // Test that the same DID can have multiple devices (key packages)
    let session = MoatSession::new();

    let did = "did:plc:user123";
    let device1 = MoatCredential::new(did, "Phone");
    let device2 = MoatCredential::new(did, "Laptop");

    let (kp1, _) = session.generate_key_package(&device1).unwrap();
    let (kp2, _) = session.generate_key_package(&device2).unwrap();

    // Extract and verify credentials
    let cred1 = session.extract_credential_from_key_package(&kp1).unwrap().unwrap();
    let cred2 = session.extract_credential_from_key_package(&kp2).unwrap().unwrap();

    // Same DID, different device names
    assert_eq!(cred1.did(), cred2.did());
    assert_ne!(cred1.device_name(), cred2.device_name());
}

#[test]
fn test_get_group_dids() {
    let alice_session = MoatSession::new();
    let bob_session = MoatSession::new();

    let alice_credential = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let bob_credential = MoatCredential::new("did:plc:bob456", "Bob Laptop");

    let (_alice_kp, alice_bundle) = alice_session.generate_key_package(&alice_credential).unwrap();
    let (bob_kp, _bob_bundle) = bob_session.generate_key_package(&bob_credential).unwrap();

    let group_id = alice_session.create_group(&alice_credential, &alice_bundle).unwrap();
    let _welcome = alice_session.add_member(&group_id, &alice_bundle, &bob_kp).unwrap();

    let dids = alice_session.get_group_dids(&group_id).unwrap();
    assert_eq!(dids.len(), 2);
    assert!(dids.contains(&"did:plc:alice123".to_string()));
    assert!(dids.contains(&"did:plc:bob456".to_string()));
}

#[test]
fn test_is_did_in_group() {
    let alice_session = MoatSession::new();
    let bob_session = MoatSession::new();

    let alice_credential = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let bob_credential = MoatCredential::new("did:plc:bob456", "Bob Laptop");

    let (_alice_kp, alice_bundle) = alice_session.generate_key_package(&alice_credential).unwrap();
    let (bob_kp, _bob_bundle) = bob_session.generate_key_package(&bob_credential).unwrap();

    let group_id = alice_session.create_group(&alice_credential, &alice_bundle).unwrap();

    // Before adding Bob
    assert!(alice_session.is_did_in_group(&group_id, "did:plc:alice123").unwrap());
    assert!(!alice_session.is_did_in_group(&group_id, "did:plc:bob456").unwrap());

    // After adding Bob
    let _welcome = alice_session.add_member(&group_id, &alice_bundle, &bob_kp).unwrap();
    assert!(alice_session.is_did_in_group(&group_id, "did:plc:alice123").unwrap());
    assert!(alice_session.is_did_in_group(&group_id, "did:plc:bob456").unwrap());
}

#[test]
fn test_add_device_for_existing_did() {
    // Create sessions for Alice's two devices
    let alice_device1_session = MoatSession::new();
    let alice_device2_session = MoatSession::new();
    let bob_session = MoatSession::new();

    let alice_device1_cred = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let alice_device2_cred = MoatCredential::new("did:plc:alice123", "Alice Laptop");
    let bob_cred = MoatCredential::new("did:plc:bob456", "Bob Laptop");

    let (_kp1, alice_bundle1) = alice_device1_session.generate_key_package(&alice_device1_cred).unwrap();
    let (kp2, _) = alice_device2_session.generate_key_package(&alice_device2_cred).unwrap();
    let (bob_kp, bob_bundle) = bob_session.generate_key_package(&bob_cred).unwrap();

    // Alice device 1 creates group and adds Bob
    let group_id = alice_device1_session.create_group(&alice_device1_cred, &alice_bundle1).unwrap();
    let welcome_result = alice_device1_session.add_member(&group_id, &alice_bundle1, &bob_kp).unwrap();

    // Bob joins
    let bob_group_id = bob_session.process_welcome(&welcome_result.welcome).unwrap();
    assert_eq!(bob_group_id, group_id);

    // Bob adds Alice's second device (same DID as Alice device 1)
    let device2_welcome = bob_session.add_device(&bob_group_id, &bob_bundle, &kp2).unwrap();

    // Alice device 2 joins via welcome
    let device2_group_id = alice_device2_session.process_welcome(&device2_welcome.welcome).unwrap();
    assert_eq!(device2_group_id, group_id);

    // Verify group now has 3 members (2 DIDs: Alice with 2 devices, Bob with 1)
    let members = bob_session.get_group_members(&bob_group_id).unwrap();
    assert_eq!(members.len(), 3);

    // But only 2 unique DIDs
    let dids = bob_session.get_group_dids(&bob_group_id).unwrap();
    assert_eq!(dids.len(), 2);
}

#[test]
fn test_add_device_fails_for_non_member() {
    let alice_session = MoatSession::new();
    let bob_session = MoatSession::new();
    let charlie_session = MoatSession::new();

    let alice_cred = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let bob_cred = MoatCredential::new("did:plc:bob456", "Bob Laptop");
    let charlie_cred = MoatCredential::new("did:plc:charlie789", "Charlie Tablet");

    let (_kp, alice_bundle) = alice_session.generate_key_package(&alice_cred).unwrap();
    let (bob_kp, _) = bob_session.generate_key_package(&bob_cred).unwrap();
    let (charlie_kp, _) = charlie_session.generate_key_package(&charlie_cred).unwrap();

    // Alice creates group and adds Bob
    let group_id = alice_session.create_group(&alice_cred, &alice_bundle).unwrap();
    let _welcome = alice_session.add_member(&group_id, &alice_bundle, &bob_kp).unwrap();

    // Try to add Charlie as a "device" - should fail because Charlie's DID isn't in the group
    let result = alice_session.add_device(&group_id, &alice_bundle, &charlie_kp);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("not a member"));
}

#[test]
fn test_remove_member() {
    let alice_session = MoatSession::new();
    let bob_session = MoatSession::new();

    let alice_cred = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let bob_cred = MoatCredential::new("did:plc:bob456", "Bob Laptop");

    let (_kp, alice_bundle) = alice_session.generate_key_package(&alice_cred).unwrap();
    let (bob_kp, _) = bob_session.generate_key_package(&bob_cred).unwrap();

    // Create group with Alice and Bob
    let group_id = alice_session.create_group(&alice_cred, &alice_bundle).unwrap();
    let _welcome = alice_session.add_member(&group_id, &alice_bundle, &bob_kp).unwrap();

    // Verify 2 members
    let members = alice_session.get_group_members(&group_id).unwrap();
    assert_eq!(members.len(), 2);

    // Find Bob's leaf index
    let bob_leaf_idx = members.iter()
        .find(|(_, cred)| cred.as_ref().map_or(false, |c| c.did() == "did:plc:bob456"))
        .map(|(idx, _)| *idx)
        .unwrap();

    // Remove Bob
    let remove_result = alice_session.remove_member(&group_id, &alice_bundle, bob_leaf_idx).unwrap();
    assert!(!remove_result.commit.is_empty());

    // Verify only 1 member remains
    let members = alice_session.get_group_members(&group_id).unwrap();
    assert_eq!(members.len(), 1);
}

#[test]
fn test_kick_user() {
    // Setup: Alice and two of Bob's devices
    let alice_session = MoatSession::new();
    let bob_device1_session = MoatSession::new();
    let bob_device2_session = MoatSession::new();

    let alice_cred = MoatCredential::new("did:plc:alice123", "Alice Phone");
    let bob_device1_cred = MoatCredential::new("did:plc:bob456", "Bob Phone");
    let bob_device2_cred = MoatCredential::new("did:plc:bob456", "Bob Laptop");

    let (_kp, alice_bundle) = alice_session.generate_key_package(&alice_cred).unwrap();
    let (bob_kp1, _bob_bundle1) = bob_device1_session.generate_key_package(&bob_device1_cred).unwrap();
    let (bob_kp2, _) = bob_device2_session.generate_key_package(&bob_device2_cred).unwrap();

    // Create group
    let group_id = alice_session.create_group(&alice_cred, &alice_bundle).unwrap();

    // Alice adds both of Bob's devices (simpler test - Alice does all adding)
    let _welcome1 = alice_session.add_member(&group_id, &alice_bundle, &bob_kp1).unwrap();
    let _welcome2 = alice_session.add_device(&group_id, &alice_bundle, &bob_kp2).unwrap();

    // Verify 3 members (Alice + Bob's 2 devices)
    let members = alice_session.get_group_members(&group_id).unwrap();
    assert_eq!(members.len(), 3);

    // Alice kicks Bob (all devices)
    let kick_result = alice_session.kick_user(&group_id, &alice_bundle, "did:plc:bob456").unwrap();
    assert!(!kick_result.commit.is_empty());

    // Verify only Alice remains
    let members = alice_session.get_group_members(&group_id).unwrap();
    assert_eq!(members.len(), 1);
    let dids = alice_session.get_group_dids(&group_id).unwrap();
    assert_eq!(dids, vec!["did:plc:alice123"]);
}
