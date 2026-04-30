//! FCM dispatch scenario.
//!
//! Verifies that the Drawbridge relay fires FCM push notifications to offline
//! devices and suppresses them while the WebSocket is live.
//!
//! Test flow:
//! 1. Alice and Bob connect to a recording-mode Drawbridge relay.
//! 2. Both send `register_push` automatically on connect (moat-cli behaviour).
//! 3. Bob disconnects; the test waits past the 10 s grace window.
//! 4. Alice sends a message — Drawbridge should FCM-notify Bob's token.
//! 5. Assert push log has exactly one entry for Bob's tag.
//! 6. Negative: Bob reconnects, log is reset, Alice sends again — zero entries.
//! 7. Reconnect-race: Bob disconnects and reconnects within 5 s; Alice sends
//!    in between — zero entries (grace window suppresses).

use std::time::Duration;

use crate::world::TestWorld;

use super::vlog;

pub async fn run(verbose: bool) {
    vlog!(verbose, "=== Scenario: fcm-dispatch ===");

    // ── Setup ─────────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (recording FCM)...");
    let mut world =
        TestWorld::new_with_drawbridge_recording_fcm(&[("alice", "shared"), ("bob", "shared")], ".postern.test")
            .await
            .expect("world setup with recording drawbridge");

    let alice = world.client("alice").clone();
    let bob = world.client("bob").clone();

    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");
    vlog!(verbose, "[setup] both logged in");

    // Wait for both clients to connect to Drawbridge and send register_push.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let a = alice.status().await.expect("alice status");
        let b = bob.status().await.expect("bob status");
        if a.drawbridge_connected && b.drawbridge_connected {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "Drawbridge not connected after 5s (alice={}, bob={})",
                a.drawbridge_connected, b.drawbridge_connected
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    vlog!(verbose, "[setup] Drawbridge connections established; push tokens registered");

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    vlog!(verbose, "[setup] conversation started: {group_id}");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = bob.poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group after prologue poll"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = alice.poll().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — any delivery from here must come through Drawbridge.
    alice.set_poll_interval(0).await.expect("disable alice polling");
    bob.set_poll_interval(0).await.expect("disable bob polling");
    vlog!(verbose, "[setup] polling disabled");

    // ── Positive path: Bob offline → FCM dispatched ───────────────────────────
    vlog!(verbose, "[test 1] killing Bob...");
    world.kill_participant("bob").expect("kill bob");

    // Wait until Drawbridge detects the disconnect (connection count drops to 1),
    // then sleep past the 10 s grace window from that point.
    vlog!(verbose, "[test 1] waiting for Drawbridge to detect disconnect...");
    world.wait_for_drawbridge_connections(1, Duration::from_secs(5)).await;
    vlog!(verbose, "[test 1] disconnect detected; waiting 11 s past grace window...");
    tokio::time::sleep(Duration::from_secs(11)).await;

    world.reset_push_log().await;

    alice
        .send_message(&group_id, "ping-for-bob")
        .await
        .expect("alice send");

    // Give Drawbridge time to process the event_posted and fire FCM.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let log = world.push_log().await;
    assert!(
        !log.is_empty(),
        "expected at least one FCM push when Bob is offline, got zero"
    );
    vlog!(verbose, "[test 1] FCM dispatched: {} push(es) recorded", log.len());

    // ── Negative path: Bob online → FCM suppressed ────────────────────────────
    vlog!(verbose, "[test 2] restarting Bob...");
    world.restart_participant("bob").await.expect("restart bob");

    // Wait for Bob to reconnect to Drawbridge and re-register push token.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if bob.status().await.map(|s| s.drawbridge_connected).unwrap_or(false) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("Bob did not reconnect to Drawbridge within 5s after restart");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    vlog!(verbose, "[test 2] Bob reconnected to Drawbridge");

    world.reset_push_log().await;

    alice
        .send_message(&group_id, "ping-while-bob-online")
        .await
        .expect("alice send");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let log = world.push_log().await;
    assert!(
        log.is_empty(),
        "expected zero FCM pushes when Bob is online, got {}",
        log.len()
    );
    vlog!(verbose, "[test 2] FCM suppressed while Bob is online: ok");

    // ── Reconnect-race path: disconnect then reconnect within grace window ─────
    vlog!(verbose, "[test 3] Bob disconnects (grace window test)...");
    world.kill_participant("bob").expect("kill bob for race test");

    // Wait for Drawbridge to detect the disconnect, then sleep only 5 s —
    // well within the 10 s grace window.
    world.wait_for_drawbridge_connections(1, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    world.reset_push_log().await;

    alice
        .send_message(&group_id, "ping-in-grace-window")
        .await
        .expect("alice send");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let log = world.push_log().await;
    assert!(
        log.is_empty(),
        "expected zero FCM pushes within grace window, got {}",
        log.len()
    );
    vlog!(verbose, "[test 3] FCM suppressed within grace window: ok");

    vlog!(verbose, "");
    vlog!(verbose, "=== PASSED ===");
}
