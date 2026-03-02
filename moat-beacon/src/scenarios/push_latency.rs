//! Push latency scenario: asserts that Drawbridge delivers messages within a
//! hard deadline, without any explicit polling.
//!
//! Unlike the property-based push scenarios, this is a deterministic test that
//! sends a fixed number of messages and measures per-message delivery latency.
//! If any message takes longer than `MAX_DELIVERY_MS` to appear in the
//! recipient's message list, the test fails.

use std::time::{Duration, Instant};

use crate::client::MoatCliClient;
use crate::world::TestWorld;

use super::vlog;

/// Maximum acceptable push delivery time per message.
const MAX_DELIVERY_MS: u64 = 2000;

/// Poll interval when checking for message arrival.
const CHECK_INTERVAL_MS: u64 = 50;

/// Number of messages to send in each direction.
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

pub async fn run(verbose: bool) {
    vlog!(verbose, "=== Scenario: push-latency ===");

    // ── Prologue (same as two_party_push) ────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (with Drawbridge)...");
    let world = TestWorld::new_with_drawbridge(&["alice", "bob"], ".postern.test")
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

    // Wait for both participants to connect to their own Drawbridge relay.
    // Instead of a fixed sleep, poll the status endpoint until connected.
    let drawbridge_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let alice_status = alice.status().await.expect("alice status");
        let bob_status = bob.status().await.expect("bob status");
        if alice_status.drawbridge_connected && bob_status.drawbridge_connected {
            vlog!(verbose, "[setup] both Drawbridge connections established");
            break;
        }
        if Instant::now() >= drawbridge_deadline {
            vlog!(
                verbose,
                "[setup] WARNING: Drawbridge not connected after 5s (alice={}, bob={})",
                alice_status.drawbridge_connected,
                bob_status.drawbridge_connected
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    vlog!(verbose, "[setup] conversation started: {group_id}");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bob joins the group and picks up DrawbridgeHint.
    let stats = bob.poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group after prologue poll"
    );
    vlog!(verbose, "[setup] bob joined group");

    // Give Bob time to connect to Drawbridge as recipient and send reciprocal hint.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Alice picks up Bob's reciprocal DrawbridgeHint so she can push to him.
    let _ = alice.poll().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — delivery must come entirely through Drawbridge.
    alice
        .set_poll_interval(0)
        .await
        .expect("disable alice polling");
    bob.set_poll_interval(0)
        .await
        .expect("disable bob polling");
    vlog!(verbose, "[setup] polling disabled (push-only mode)");
    vlog!(verbose, "");

    // ── Latency measurements ─────────────────────────────────────────────────
    let deadline = Duration::from_millis(MAX_DELIVERY_MS);
    let mut latencies: Vec<(String, Duration)> = Vec::new();

    // Alice → Bob
    for i in 0..MESSAGES_PER_DIRECTION {
        let text = format!("alice-to-bob-{i}");
        alice
            .send_message(&group_id, &text)
            .await
            .expect("alice send");

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
                    "Push delivery timeout: {text:?} not delivered to Bob within {MAX_DELIVERY_MS}ms"
                );
            }
        }
    }

    // Bob → Alice
    for i in 0..MESSAGES_PER_DIRECTION {
        let text = format!("bob-to-alice-{i}");
        bob.send_message(&group_id, &text)
            .await
            .expect("bob send");

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
                    "Push delivery timeout: {text:?} not delivered to Alice within {MAX_DELIVERY_MS}ms"
                );
            }
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────────
    let avg_ms = latencies.iter().map(|(_, d)| d.as_millis()).sum::<u128>()
        / latencies.len() as u128;
    let max_ms = latencies.iter().map(|(_, d)| d.as_millis()).max().unwrap();

    vlog!(verbose, "");
    vlog!(
        verbose,
        "[result] {}/{} messages delivered within {MAX_DELIVERY_MS}ms",
        latencies.len(),
        MESSAGES_PER_DIRECTION * 2
    );
    vlog!(verbose, "[result] avg={avg_ms}ms, max={max_ms}ms");
    vlog!(verbose, "");
    vlog!(verbose, "=== PASSED ===");

    drop(world);
}
