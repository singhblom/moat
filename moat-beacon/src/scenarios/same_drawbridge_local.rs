//! Two-party same-Drawbridge local delivery scenario.
//!
//! Both participants connect to a **single shared Drawbridge** relay.  When
//! Alice sends a message, delivery is local within the relay — no relay-to-relay
//! HTTP hop.  This tests the co-located deployment mode where users share a
//! relay (like two users on the same server).
//!
//! After the prologue, auto-polling is disabled; delivery must come via push.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::invariants::{
    check_per_sender_ordering, check_delivery, check_no_duplicates, ScenarioState,
};
use crate::world::TestWorld;

use super::two_party_push::drain_events_push;
use super::{execute_action, format_action, vlog};

pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(actions, verbose))
}

pub async fn run(actions: Vec<Action>, verbose: bool) {
    vlog!(verbose, "=== Scenario: same-drawbridge-local ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (shared Drawbridge)...");
    let mut world = TestWorld::new_with_drawbridge(&[("alice", "shared"), ("bob", "shared")], ".postern.test")
        .await
        .expect("world setup with shared drawbridge");
    let alice = world.client("alice").clone();
    let bob = world.client("bob").clone();

    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    vlog!(verbose, "[setup] login alice... done");

    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");
    vlog!(verbose, "[setup] login bob... done");

    // Wait for both participants to connect to the shared Drawbridge relay.
    let drawbridge_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let a = alice.status().await.expect("alice status");
        let b = bob.status().await.expect("bob status");
        if a.drawbridge_connected && b.drawbridge_connected {
            break;
        }
        if std::time::Instant::now() >= drawbridge_deadline {
            panic!(
                "Drawbridge not connected after 5s (alice={}, bob={})",
                a.drawbridge_connected, b.drawbridge_connected
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    vlog!(verbose, "[setup] Drawbridge connections established (shared relay)");

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    vlog!(verbose, "[setup] bob watches alice... done");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bob joins the group (receives Welcome).
    let stats = bob.poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group after prologue poll"
    );
    vlog!(
        verbose,
        "[setup] alice starts conversation... group={group_id}"
    );
    vlog!(
        verbose,
        "[setup] bob polls to join... done ({} new conversations)",
        stats.new_conversations
    );

    // Give Bob time to publish drawbridge config, then Alice fetches it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = alice.poll().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — delivery must come via local Drawbridge push.
    alice.set_poll_interval(0).await.expect("disable alice polling");
    bob.set_poll_interval(0).await.expect("disable bob polling");
    vlog!(verbose, "[setup] polling disabled (push-only mode via shared relay)");

    // ── Random action sequence ─────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    let mut state = ScenarioState { group_id, sent_messages: vec![] };

    let total = actions.len();
    for (i, action) in actions.iter().enumerate() {
        vlog!(verbose, "[action {}/{}] {}", i + 1, total, format_action(action));
        execute_action(
            action,
            &alice,
            &bob,
            &mut world,
            "alice.postern.test",
            "bob.postern.test",
            true,
            &mut state,
            verbose,
        )
        .await;
    }

    // ── Drain + invariants ─────────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    vlog!(verbose, "[drain] waiting for local push events to propagate...");
    drain_events_push(&alice, &bob).await;

    let confirmed = state.sent_messages.iter().filter(|m| m.message_id.is_some()).count();

    check_delivery(&alice, &bob, &state).await.expect("delivery invariant violated");
    vlog!(verbose, "[check] delivery... ok ({confirmed} messages)");

    check_per_sender_ordering(&alice, &bob, &state)
        .await
        .expect("per-sender ordering invariant violated");
    vlog!(verbose, "[check] per-sender ordering... ok");

    check_no_duplicates(&alice, &bob, &state)
        .await
        .expect("no-duplicates invariant violated");
    vlog!(verbose, "[check] no duplicates... ok");

    if verbose {
        eprintln!();
        eprintln!("=== PASSED ===");
    }
}
