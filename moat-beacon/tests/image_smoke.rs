//! Smoke test: Alice (Dart) sends a PNG image to Bob (Dart).
//!
//! Verifies that:
//! - The image endpoint accepts raw PNG bytes and returns success.
//! - Bob's polling delivers the encrypted image event.
//! - Bob's message list contains an image message with a content preview
//!   starting with "[image" and a populated `image_attachment`.

use moat_beacon::world::{ParticipantKind, TestWorld};
use std::time::Duration;

/// Build a minimal valid PNG (16×16 RGBA, all zeros).
fn make_test_png() -> Vec<u8> {
    use image::{DynamicImage, ImageFormat};
    let img = DynamicImage::new_rgba8(16, 16);
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

#[tokio::test]
async fn image_send_receive_dart() {
    let world = TestWorld::new_with_kinds(
        &["alice", "bob"],
        &[ParticipantKind::DartServer, ParticipantKind::DartServer],
        ".postern.test",
    )
    .await
    .expect("world setup");

    let alice = world.client("alice");
    let bob = world.client("bob");

    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");

    tokio::time::sleep(Duration::from_millis(500)).await;

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("alice start conversation with bob");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = bob.poll().await.expect("bob welcome poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should receive Welcome (got {stats:?})"
    );

    // Alice sends a PNG image.
    let png = make_test_png();
    alice
        .send_image(&group_id, &png)
        .await
        .expect("alice send image");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bob polls to receive the encrypted image event.
    let stats = bob.poll().await.expect("bob image poll");
    assert!(
        stats.new_messages > 0,
        "Bob should receive image message (got {stats:?})"
    );

    // Verify Bob's received message.
    let bob_msgs = bob
        .get_messages(&group_id)
        .await
        .expect("bob get messages");

    let img_msg = bob_msgs
        .iter()
        .find(|m| m.content.contains("[image"))
        .expect("Bob should have a message with '[image' content preview");

    let attachment = img_msg
        .attachment
        .as_ref()
        .expect("attachment should be present on the image message");

    assert!(
        !attachment.uri.is_empty(),
        "image URI should not be empty, got: {:?}",
        attachment.uri
    );
    assert_eq!(
        attachment.mime.as_deref(),
        Some("image/png"),
        "MIME type should be image/png"
    );
    assert!(
        attachment.width.is_some() && attachment.height.is_some(),
        "width and height should be populated, got: {:?}x{:?}",
        attachment.width,
        attachment.height
    );
    assert!(
        !attachment.key.is_empty(),
        "encryption key should be present"
    );
}
