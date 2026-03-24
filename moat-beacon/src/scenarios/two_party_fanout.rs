//! Two-party relay-to-relay fan-out scenario.
//!
//! Each participant gets its own Drawbridge relay instance.  When Alice sends a
//! message, her relay fans out to Bob's relay via `POST /relay/event`, and
//! Bob's relay delivers to Bob over WebSocket.  This verifies that the full
//! federated delivery path works end-to-end.
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
    vlog!(verbose, "=== Scenario: two-party-fanout ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (per-participant Drawbridge)...");
    let mut world = TestWorld::new_with_drawbridge(&[("alice", "alice"), ("bob", "bob")], ".postern.test")
        .await
        .expect("world setup with per-participant drawbridge");
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

    // Wait for both participants to connect to their own Drawbridge relay.
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
    vlog!(verbose, "[setup] Drawbridge connections established (separate relays)");

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    vlog!(verbose, "[setup] bob watches alice... done");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bob joins the group (receives Welcome) and discovers Alice's drawbridge config.
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

    // Both clients need to cache each other's drawbridge config for relay-to-relay
    // fan-out.  The config fetch is async (spawned as a tokio task after Welcome
    // processing / start_conversation).  Give the headless loops time to process
    // the DrawbridgeConfigFetched BgEvents, then trigger explicit polls so each
    // client's headless loop drains any remaining BgEvents.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = alice.poll().await;
    let _ = bob.poll().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — delivery must come entirely through Drawbridge relay-to-relay.
    alice.set_poll_interval(0).await.expect("disable alice polling");
    bob.set_poll_interval(0).await.expect("disable bob polling");
    vlog!(verbose, "[setup] polling disabled (push-only mode via separate relays)");

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
    vlog!(verbose, "[drain] waiting for relay-to-relay push events to propagate...");
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
