//! Image round-trip smoke tests.
//!
//! Invariant: an image sent by Alice can be fetched and decrypted by Bob,
//! and the decrypted bytes are a valid image (PNG magic bytes present).
//!
//! Covered variants:
//!   - Rust CLI → Rust CLI
//!   - Dart server → Dart server
//!   - Dart server → Rust CLI  (cross-platform receive)

use moat_beacon::world::{ParticipantKind, TestWorld};
use std::time::Duration;

const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Build a minimal valid 16×16 RGBA PNG.
fn make_test_png() -> Vec<u8> {
    use image::{DynamicImage, ImageFormat};
    let img = DynamicImage::new_rgba8(16, 16);
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

/// Core round-trip logic shared across variants.
///
/// Alice sends a PNG; Bob polls, receives the event, then fetches the
/// decrypted image and verifies it is a valid PNG.
async fn run_image_round_trip(
    alice_kind: ParticipantKind,
    bob_kind: ParticipantKind,
) {
    let suffix = ".postern.test";
    let world = TestWorld::new_with_kinds(
        &["alice", "bob"],
        &[alice_kind, bob_kind],
        suffix,
    )
    .await
    .expect("world setup");

    let alice = world.client("alice");
    let bob = world.client("bob");

    // Suffix is ".postern.test", so handles are "alice.postern.test" etc.
    let domain = suffix.trim_start_matches('.');
    let alice_handle = format!("alice.{domain}");
    let bob_handle = format!("bob.{domain}");

    alice.login(&alice_handle, "any-password").await.expect("alice login");
    bob.login(&bob_handle, "any-password").await.expect("bob login");
    tokio::time::sleep(Duration::from_millis(500)).await;

    bob.watch_handle(&alice_handle).await.expect("bob watch alice");

    let group_id = alice
        .start_conversation(&bob_handle)
        .await
        .expect("alice start conversation");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = bob.poll().await.expect("bob welcome poll");
    assert!(stats.new_conversations > 0, "Bob should receive Welcome (got {stats:?})");

    // Alice sends a PNG image.
    let png = make_test_png();
    alice.send_image(&group_id, &png).await.expect("alice send image");

    // Wait for the async blob upload + event publish to complete.
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let stats = bob.poll().await.expect("bob image poll");
    assert!(stats.new_messages > 0, "Bob should receive image message (got {stats:?})");

    // Verify Bob's message list contains an image message with attachment metadata.
    let bob_msgs = bob.get_messages(&group_id).await.expect("bob get messages");

    let img_msg = bob_msgs
        .iter()
        .find(|m| m.content.starts_with("[image"))
        .expect("Bob should have a message with '[image' content preview");

    let attachment = img_msg
        .attachment
        .as_ref()
        .expect("image message must have attachment metadata");

    assert!(!attachment.uri.is_empty(), "blob URI must not be empty");
    assert!(!attachment.key.is_empty(), "encryption key must not be empty");
    assert_eq!(attachment.mime.as_deref(), Some("image/png"), "MIME should be image/png");
    assert!(
        attachment.width.unwrap_or(0) > 0 && attachment.height.unwrap_or(0) > 0,
        "dimensions must be populated"
    );

    // Fetch and decrypt the image — this is the critical test: the blob must
    // be pinned to permanent storage (via the blob ref in the event record).
    let message_id = img_msg.message_id.as_deref().expect("message_id must be present");
    let decrypted = bob
        .fetch_image(&group_id, message_id)
        .await
        .expect("Bob should be able to fetch and decrypt the image");

    assert!(!decrypted.is_empty(), "decrypted image must not be empty");
    assert!(
        decrypted.starts_with(PNG_MAGIC),
        "decrypted bytes should be a PNG (got first 8 bytes: {:?})",
        &decrypted[..decrypted.len().min(8)]
    );
}

#[tokio::test]
async fn image_send_receive_rust() {
    run_image_round_trip(ParticipantKind::RustCli, ParticipantKind::RustCli).await;
}

#[tokio::test]
async fn image_send_receive_dart() {
    run_image_round_trip(ParticipantKind::DartServer, ParticipantKind::DartServer).await;
}

#[tokio::test]
async fn image_send_receive_mixed() {
    // Dart sender → Rust receiver: exercises that the blob ref written by Dart
    // is correctly pinned and fetchable by the Rust CLI.
    run_image_round_trip(ParticipantKind::DartServer, ParticipantKind::RustCli).await;
}
