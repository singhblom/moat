//! Push latency after restart: verifies that Drawbridge push delivery survives
//! a full kill/restart cycle of both participants.
//!
//! 1. Sets up a conversation with push working (same as `push_latency`).
//! 2. Sends one message each way to confirm push works pre-restart.
//! 3. Kills both participants.
//! 4. Restarts both participants, re-logs in, waits for Drawbridge reconnect.
//! 5. Disables polling again.
//! 6. Sends messages each way and asserts push delivery within the deadline.
//!
//! This catches bugs where `DrawbridgeReconnectPartners` fails to re-establish
//! push delivery, tags aren't re-registered, or persisted Drawbridge state is
//! corrupted after restart.

use std::time::{Duration, Instant};

use crate::client::MoatCliClient;
use crate::world::TestWorld;

use super::vlog;

/// Maximum acceptable push delivery time per message.
const MAX_DELIVERY_MS: u64 = 2000;

/// Poll interval when checking for message arrival.
const CHECK_INTERVAL_MS: u64 = 50;

/// Number of messages to send in each direction after restart.
const MESSAGES_PER_DIRECTION: usize = 3;

/// Wait for a specific message to appear in `recipient`'s message list,
/// returning the delivery latency.  Returns `None` if the deadline expires.
async fn wait_for_message(
    recipient: &MoatCliClient,
    group_id: &str,
    expected_content: &str,
    deadline: Duration,
) -> Option<Duration> {
    let start = Instant::now();
    loop {
        let msgs = recipient.get_messages(group_id).await.unwrap_or_default();
        if msgs.iter().any(|m| m.content.contains(expected_content)) {
            return Some(start.elapsed());
        }
        if start.elapsed() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(CHECK_INTERVAL_MS)).await;
    }
}

/// Wait for Drawbridge connection on a participant, with timeout.
async fn wait_for_drawbridge(client: &MoatCliClient, label: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = client.status().await.expect(&format!("{label} status"));
        if status.drawbridge_connected {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{label}: Drawbridge not connected after {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn run(verbose: bool) {
    vlog!(verbose, "=== Scenario: push-latency-restart ===");

    // ── Phase 1: Setup (same as push_latency) ───────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (with Drawbridge)...");
    let mut world = TestWorld::new_with_drawbridge(&[("alice", "alice"), ("bob", "bob")], ".postern.test")
        .await
        .expect("world setup with drawbridge");
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

    wait_for_drawbridge(&alice, "alice", Duration::from_secs(5)).await;
    wait_for_drawbridge(&bob, "bob", Duration::from_secs(5)).await;
    vlog!(verbose, "[setup] both Drawbridge connections established");

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
    vlog!(verbose, "[setup] bob joined group");

    // Give Bob time to send reciprocal DrawbridgeHint, then Alice picks it up.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = alice.poll().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — push only.
    alice.set_poll_interval(0).await.expect("disable alice polling");
    bob.set_poll_interval(0).await.expect("disable bob polling");
    vlog!(verbose, "[setup] polling disabled (push-only mode)");

    // ── Phase 2: Verify push works pre-restart ──────────────────────────────
    vlog!(verbose, "");
    let deadline = Duration::from_millis(MAX_DELIVERY_MS);

    alice
        .send_message(&group_id, "pre-restart-a2b")
        .await
        .expect("alice send pre-restart");
    let lat = wait_for_message(&bob, &group_id, "pre-restart-a2b", deadline)
        .await
        .expect("pre-restart Alice→Bob push failed");
    vlog!(verbose, "[pre-restart] Alice→Bob: {:.0}ms", lat.as_secs_f64() * 1000.0);

    bob.send_message(&group_id, "pre-restart-b2a")
        .await
        .expect("bob send pre-restart");
    let lat = wait_for_message(&alice, &group_id, "pre-restart-b2a", deadline)
        .await
        .expect("pre-restart Bob→Alice push failed");
    vlog!(verbose, "[pre-restart] Bob→Alice: {:.0}ms", lat.as_secs_f64() * 1000.0);

    // ── Phase 3: Kill both participants ─────────────────────────────────────
    vlog!(verbose, "");
    vlog!(verbose, "[restart] killing both participants...");
    world.kill_participant("alice").expect("kill alice");
    world.kill_participant("bob").expect("kill bob");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Phase 4: Restart and re-establish ───────────────────────────────────
    vlog!(verbose, "[restart] restarting both participants...");
    world.restart_participant("alice").await.expect("restart alice");
    world.restart_participant("bob").await.expect("restart bob");

    // Re-login (session doesn't survive restart in test mode).
    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice re-login");
    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob re-login");
    vlog!(verbose, "[restart] both re-logged in");

    // Wait for Drawbridge reconnections.
    wait_for_drawbridge(&alice, "alice (post-restart)", Duration::from_secs(5)).await;
    wait_for_drawbridge(&bob, "bob (post-restart)", Duration::from_secs(5)).await;
    vlog!(verbose, "[restart] Drawbridge connections re-established");

    // Give time for DrawbridgeReconnectPartners to re-establish partner connections.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Disable auto-polling again (restart resets poll interval).
    alice.set_poll_interval(0).await.expect("disable alice polling post-restart");
    bob.set_poll_interval(0).await.expect("disable bob polling post-restart");
    vlog!(verbose, "[restart] polling disabled (push-only mode)");
    vlog!(verbose, "");

    // ── Phase 5: Verify push works post-restart ─────────────────────────────
    let mut latencies: Vec<(String, Duration)> = Vec::new();

    // Alice → Bob
    for i in 0..MESSAGES_PER_DIRECTION {
        let text = format!("post-restart-a2b-{i}");
        alice
            .send_message(&group_id, &text)
            .await
            .expect("alice send post-restart");

        match wait_for_message(&bob, &group_id, &text, deadline).await {
            Some(latency) => {
                vlog!(
                    verbose,
                    "[latency] {text}: {:.0}ms",
                    latency.as_secs_f64() * 1000.0
                );
                latencies.push((text, latency));
            }
            None => {
                panic!(
                    "Post-restart push timeout: {text:?} not delivered to Bob within {MAX_DELIVERY_MS}ms"
                );
            }
        }
    }

    // Bob → Alice
    for i in 0..MESSAGES_PER_DIRECTION {
        let text = format!("post-restart-b2a-{i}");
        bob.send_message(&group_id, &text)
            .await
            .expect("bob send post-restart");

        match wait_for_message(&alice, &group_id, &text, deadline).await {
            Some(latency) => {
                vlog!(
                    verbose,
                    "[latency] {text}: {:.0}ms",
                    latency.as_secs_f64() * 1000.0
                );
                latencies.push((text, latency));
            }
            None => {
                panic!(
                    "Post-restart push timeout: {text:?} not delivered to Alice within {MAX_DELIVERY_MS}ms"
                );
            }
        }
    }

    // ── Summary ─────────────────────────────────────────────────────────────
    let avg_ms = latencies.iter().map(|(_, d)| d.as_millis()).sum::<u128>()
        / latencies.len() as u128;
    let max_ms = latencies.iter().map(|(_, d)| d.as_millis()).max().unwrap();

    vlog!(verbose, "");
    vlog!(
        verbose,
        "[result] {}/{} post-restart messages delivered within {MAX_DELIVERY_MS}ms",
        latencies.len(),
        MESSAGES_PER_DIRECTION * 2
    );
    vlog!(verbose, "[result] avg={avg_ms}ms, max={max_ms}ms");
    vlog!(verbose, "");
    vlog!(verbose, "=== PASSED ===");

    drop(world);
}
