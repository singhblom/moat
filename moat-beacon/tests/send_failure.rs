//! A send that cannot finish must end in a visible, retryable failure —
//! never a permanent "sending" row — and a retry must reach the recipient
//! exactly once.
//!
//! Covered:
//!   - image: the upload fails outright (PDS unreachable)
//!   - image: the sender restarts while the upload is in flight
//!   - short text: the publish fails outright
//!   - long text: the blob upload fails outright
//!   - short text: the publish lands but its response is lost, so the
//!     retry republishes a message the recipient already has

use moat_beacon::client::{Message, MoatCliClient};
use moat_beacon::world::TestWorld;
use serde_json::json;
use std::time::{Duration, Instant};

/// Room for the CLI's 30 s HTTP timeout, which the lost-response case
/// waits out, plus any ring tick or device poll caught by the same mute.
const TIMEOUT: Duration = Duration::from_secs(90);
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

fn is_image(m: &Message) -> bool {
    m.content.starts_with("[image")
}

fn has_status(status: &'static str) -> impl Fn(&Message) -> bool {
    move |m| m.status.as_deref() == Some(status)
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

/// The single row `select` picks out, once `done` accepts it.
async fn wait_for_row(
    client: &MoatCliClient,
    group_id: &str,
    what: &str,
    select: impl Fn(&Message) -> bool,
    done: impl Fn(&Message) -> bool,
) -> Message {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let msgs = client.get_messages(group_id).await.expect("get messages");
        let mut rows: Vec<_> = msgs.into_iter().filter(|m| select(m)).collect();
        assert!(rows.len() <= 1, "the message must never be duplicated: {rows:?}");
        if rows.first().is_some_and(&done) {
            return rows.remove(0);
        }
        assert!(Instant::now() < deadline, "row never became {what}: {rows:?}");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Retry Alice's failed row and wait until Bob holds exactly one copy.
async fn retry_and_deliver(
    world: &TestWorld,
    group_id: &str,
    message_id: &str,
    select: impl Fn(&Message) -> bool + Copy,
) -> Message {
    let (alice, bob) = (world.client("alice"), world.client("bob"));
    alice.retry_send(group_id, message_id).await.expect("retry");
    let sent = wait_for_row(alice, group_id, "sent", select, has_status("sent")).await;
    assert_eq!(sent.message_id.as_deref(), Some(message_id), "retry keeps the message id");
    assert!(sent.send_error.is_none());

    let deadline = Instant::now() + TIMEOUT;
    loop {
        let _ = bob.poll().await;
        let msgs = bob.get_messages(group_id).await.expect("bob messages");
        let copies: Vec<_> = msgs.into_iter().filter(|m| !m.is_own && select(m)).collect();
        assert!(copies.len() <= 1, "Bob must hold the message once: {copies:?}");
        if let Some(m) = copies.into_iter().next() {
            assert_eq!(m.message_id.as_deref(), Some(message_id));
            return m;
        }
        assert!(Instant::now() < deadline, "Bob never received the retried message");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Send `text` with the PDS unreachable, then retry it to delivery.
async fn text_failure_then_retry(text: &str, stage: &str) {
    let (world, group_id) = setup().await;
    let alice = world.client("alice");
    let prefix: String = text.chars().take(20).collect();
    let select = |m: &Message| m.content.starts_with(prefix.as_str());

    world.toxiproxy.disable_proxy(&world.pds_proxy.name).await.unwrap();
    alice.send_message(&group_id, text).await.expect("send text");
    let failed = wait_for_row(alice, &group_id, "failed", select, has_status("failed")).await;
    assert!(
        failed.send_error.as_deref().is_some_and(|e| e.contains(stage)),
        "the failure names its stage: {failed:?}"
    );
    assert!(!failed.content.contains("uploading"), "a failed row must not claim to be working");

    world.toxiproxy.enable_proxy(&world.pds_proxy.name).await.unwrap();
    retry_and_deliver(&world, &group_id, failed.message_id.as_deref().unwrap(), select).await;
}

#[tokio::test]
async fn a_failed_image_upload_is_marked_failed_and_can_be_retried() {
    let (world, group_id) = setup().await;
    let alice = world.client("alice");

    world.toxiproxy.disable_proxy(&world.pds_proxy.name).await.unwrap();
    alice.send_image(&group_id, &make_test_png()).await.expect("send image");

    let failed = wait_for_row(alice, &group_id, "failed", is_image, has_status("failed")).await;
    assert!(
        failed.send_error.as_deref().is_some_and(|e| e.contains("upload")),
        "the failure names its stage: {failed:?}"
    );
    assert!(!failed.content.contains("processing"), "a failed row must not claim to be working");

    world.toxiproxy.enable_proxy(&world.pds_proxy.name).await.unwrap();
    let received =
        retry_and_deliver(&world, &group_id, failed.message_id.as_deref().unwrap(), is_image).await;
    let bytes = world
        .client("bob")
        .fetch_image(&group_id, received.message_id.as_deref().unwrap())
        .await
        .expect("Bob fetches the image");
    assert!(bytes.starts_with(PNG_MAGIC), "Bob's image decrypts to the PNG");
}

#[tokio::test]
async fn a_restart_mid_upload_leaves_a_retryable_failure() {
    let (mut world, group_id) = setup().await;
    let proxy = world.pds_proxy.name.clone();

    // Hold every PDS connection open without passing data, so the upload
    // is still in flight when the sender dies.
    world
        .toxiproxy
        .add_toxic(&proxy, "stall", "timeout", "upstream", 1.0, json!({ "timeout": 0 }))
        .await
        .unwrap();
    let alice = world.client("alice");
    alice.send_image(&group_id, &make_test_png()).await.expect("send image");
    wait_for_row(alice, &group_id, "sending", is_image, has_status("sending")).await;

    world.kill_participant("alice").unwrap();
    world.toxiproxy.remove_toxic(&proxy, "stall").await.unwrap();
    world.restart_participant("alice").await.expect("restart alice");
    let alice = world.client("alice");
    alice.login(ALICE, "any-password").await.expect("alice re-login");

    let failed = wait_for_row(alice, &group_id, "failed", is_image, has_status("failed")).await;
    assert!(!failed.content.contains("processing"), "a failed row must not claim to be working");

    retry_and_deliver(&world, &group_id, failed.message_id.as_deref().unwrap(), is_image).await;
}

#[tokio::test]
async fn a_failed_text_publish_can_be_retried() {
    text_failure_then_retry("short text that could not be published", "publish").await;
}

#[tokio::test]
async fn a_failed_long_text_upload_can_be_retried() {
    let text = format!("long text that could not be uploaded {}", "x".repeat(2_000));
    text_failure_then_retry(&text, "upload").await;
}

#[tokio::test]
async fn a_retry_after_a_lost_response_reaches_bob_once() {
    let (world, group_id) = setup().await;
    let alice = world.client("alice");
    let proxy = world.pds_proxy.name.clone();
    let text = "published, but alice never heard back";
    let select = |m: &Message| m.content == text;

    // Requests still reach the PDS but responses are dropped, so the
    // record is written while Alice's publish times out. Unmuted soon
    // after, so the rest of Alice's traffic recovers.
    world
        .toxiproxy
        .add_toxic(&proxy, "mute", "timeout", "downstream", 1.0, json!({ "timeout": 0 }))
        .await
        .unwrap();
    alice.send_message(&group_id, text).await.expect("send text");
    tokio::time::sleep(Duration::from_secs(2)).await;
    world.toxiproxy.remove_toxic(&proxy, "mute").await.unwrap();
    let failed = wait_for_row(alice, &group_id, "failed", select, has_status("failed")).await;

    retry_and_deliver(&world, &group_id, failed.message_id.as_deref().unwrap(), select).await;

    // Both records are on the PDS now; a further poll must not add the other.
    let _ = world.client("bob").poll().await;
    let msgs = world.client("bob").get_messages(&group_id).await.unwrap();
    assert_eq!(msgs.iter().filter(|m| select(m)).count(), 1, "Bob shows it once: {msgs:?}");
}
