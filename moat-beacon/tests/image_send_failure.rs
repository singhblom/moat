//! An image send that cannot finish must end in a visible, retryable
//! failure — never a permanent "processing…" row.
//!
//! Covered:
//!   - the upload fails outright (PDS unreachable)
//!   - the sender restarts while the upload is in flight
//!
//! Both then retry once the PDS is back, and Bob must receive the image.

use moat_beacon::client::{Message, MoatCliClient};
use moat_beacon::world::TestWorld;
use serde_json::json;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(45);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const PNG_MAGIC: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const ALICE: &str = "alice.postern.test";
const BOB: &str = "bob.postern.test";

fn make_test_png() -> Vec<u8> {
    use image::{DynamicImage, ImageFormat};
    let img = DynamicImage::new_rgba8(16, 16);
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

/// Alice and Bob in a conversation both of them hold.
async fn setup() -> (TestWorld, String) {
    let world = TestWorld::new(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup");
    let (alice, bob) = (world.client("alice"), world.client("bob"));
    alice.login(ALICE, "any-password").await.expect("alice login");
    bob.login(BOB, "any-password").await.expect("bob login");
    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.watch_handle(ALICE).await.expect("bob watch alice");
    let group_id = alice.start_conversation(BOB).await.expect("start conversation");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let stats = bob.poll().await.expect("bob welcome poll");
    assert!(stats.new_conversations > 0, "Bob should receive the Welcome");
    (world, group_id)
}

/// Alice's single image row, once `done` accepts it.
async fn wait_for_image_row(
    client: &MoatCliClient,
    group_id: &str,
    what: &str,
    done: impl Fn(&Message) -> bool,
) -> Message {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let msgs = client.get_messages(group_id).await.expect("get messages");
        let mut images: Vec<_> =
            msgs.into_iter().filter(|m| m.content.starts_with("[image")).collect();
        assert!(images.len() <= 1, "the image must never be duplicated: {images:?}");
        if images.first().is_some_and(&done) {
            return images.remove(0);
        }
        assert!(Instant::now() < deadline, "image row never became {what}: {images:?}");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Retry Alice's failed image and check Bob receives and decrypts it.
async fn retry_and_deliver(world: &TestWorld, group_id: &str, message_id: &str) {
    let (alice, bob) = (world.client("alice"), world.client("bob"));
    alice.retry_send(group_id, message_id).await.expect("retry");
    let sent = wait_for_image_row(alice, group_id, "sent", |m| {
        m.status.as_deref() == Some("sent")
    })
    .await;
    assert_eq!(sent.message_id.as_deref(), Some(message_id), "retry keeps the message id");
    assert!(sent.send_error.is_none());

    let deadline = Instant::now() + TIMEOUT;
    let received = loop {
        let _ = bob.poll().await;
        let msgs = bob.get_messages(group_id).await.expect("bob messages");
        if let Some(m) = msgs.into_iter().find(|m| m.attachment.is_some()) {
            break m;
        }
        assert!(Instant::now() < deadline, "Bob never received the retried image");
        tokio::time::sleep(POLL_INTERVAL).await;
    };
    let bytes = bob
        .fetch_image(group_id, received.message_id.as_deref().unwrap())
        .await
        .expect("Bob fetches the image");
    assert!(bytes.starts_with(PNG_MAGIC), "Bob's image decrypts to the PNG");
}

#[tokio::test]
async fn a_failed_upload_is_marked_failed_and_can_be_retried() {
    let (world, group_id) = setup().await;
    let alice = world.client("alice");

    world.toxiproxy.disable_proxy(&world.pds_proxy.name).await.unwrap();
    alice.send_image(&group_id, &make_test_png()).await.expect("send image");

    let failed = wait_for_image_row(alice, &group_id, "failed", |m| {
        m.status.as_deref() == Some("failed")
    })
    .await;
    assert!(
        failed.send_error.as_deref().is_some_and(|e| e.contains("upload")),
        "the failure names its stage: {failed:?}"
    );
    assert!(!failed.content.contains("processing"), "a failed row must not claim to be working");

    world.toxiproxy.enable_proxy(&world.pds_proxy.name).await.unwrap();
    retry_and_deliver(&world, &group_id, failed.message_id.as_deref().unwrap()).await;
}

#[tokio::test]
async fn a_restart_mid_upload_leaves_a_retryable_failure() {
    let (mut world, group_id) = setup().await;
    let proxy = world.pds_proxy.name.clone();

    // Hold every PDS connection open without passing data, so the upload
    // is still in flight when the sender dies.
    world
        .toxiproxy
        .add_toxic(&proxy, "stall", "timeout", 1.0, json!({ "timeout": 0 }))
        .await
        .unwrap();
    let alice = world.client("alice");
    alice.send_image(&group_id, &make_test_png()).await.expect("send image");
    wait_for_image_row(alice, &group_id, "sending", |m| {
        m.status.as_deref() == Some("sending")
    })
    .await;

    world.kill_participant("alice").unwrap();
    world.toxiproxy.remove_toxic(&proxy, "stall").await.unwrap();
    world.restart_participant("alice").await.expect("restart alice");
    let alice = world.client("alice");
    alice.login(ALICE, "any-password").await.expect("alice re-login");

    let failed = wait_for_image_row(alice, &group_id, "failed", |m| {
        m.status.as_deref() == Some("failed")
    })
    .await;
    assert!(!failed.content.contains("processing"), "a failed row must not claim to be working");

    retry_and_deliver(&world, &group_id, failed.message_id.as_deref().unwrap()).await;
}
