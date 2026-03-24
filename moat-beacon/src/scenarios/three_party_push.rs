//! Three-party Drawbridge push delivery scenario.
//!
//! Mirrors `three_party_chat` but uses Drawbridge for push delivery.
//! After the prologue, auto-polling is disabled; delivery must come via push.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::invariants::{
    check_per_sender_ordering_n, check_delivery_n, check_no_duplicates_n, ScenarioState,
};
use crate::world::TestWorld;

use super::two_party_push::drain_events_push;
use super::{execute_action_n, format_action, vlog};

pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(actions, verbose))
}

pub async fn run(actions: Vec<Action>, verbose: bool) {
    vlog!(verbose, "=== Scenario: three-party-push ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (with Drawbridge)...");
    let mut world =
        TestWorld::new_with_drawbridge(&[("alice", "alice"), ("bob", "bob"), ("carol", "carol")], ".postern.test")
            .await
            .expect("world setup with drawbridge");
    let alice = world.client("alice").clone();
    let bob = world.client("bob").clone();
    let carol = world.client("carol").clone();
    let clients = [&alice, &bob, &carol];
    let handles = [
        "alice.postern.test",
        "bob.postern.test",
        "carol.postern.test",
    ];

    // Login all three
    for (client, handle) in clients.iter().zip(handles.iter()) {
        client
            .login(handle, "any-password")
            .await
            .unwrap_or_else(|e| panic!("{handle} login failed: {e}"));
        vlog!(verbose, "[setup] login {handle}... done");
    }

    // Wait for Drawbridge connections
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let a = alice.status().await.expect("alice status");
        let b = bob.status().await.expect("bob status");
        let c = carol.status().await.expect("carol status");
        if a.drawbridge_connected && b.drawbridge_connected && c.drawbridge_connected {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "Drawbridge not connected after 5s (alice={}, bob={}, carol={})",
                a.drawbridge_connected, b.drawbridge_connected, c.drawbridge_connected
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    vlog!(verbose, "[setup] Drawbridge connections established");

    // Bob and Carol watch Alice
    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    carol
        .watch_handle("alice.postern.test")
        .await
        .expect("carol watch alice");

    // Alice starts conversation with Bob
    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = bob.poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group"
    );

    // Alice adds Carol
    alice
        .add_member(&group_id, "carol.postern.test")
        .await
        .expect("alice add carol");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = carol.poll().await.expect("carol join poll");
    assert!(
        stats.new_conversations > 0,
        "Carol should have joined the group"
    );
    let _ = bob.poll().await;

    // Carol gets Alice's and Bob's hints from the Welcome envelope.
    // One poll round picks up Carol's reciprocal hint for Alice and Bob.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for client in &clients {
        let _ = client.poll().await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — delivery must come via Drawbridge push
    for client in &clients {
        client
            .set_poll_interval(0)
            .await
            .expect("disable polling");
    }
    vlog!(verbose, "[setup] polling disabled (push-only mode)");

    // ── Random action sequence ─────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    let mut state = ScenarioState {
        group_id,
        sent_messages: vec![],
    };

    let total = actions.len();
    for (i, action) in actions.iter().enumerate() {
        vlog!(
            verbose,
            "[action {}/{}] {}",
            i + 1,
            total,
            format_action(action)
        );
        execute_action_n(
            action, &clients, &mut world, &handles, true, &mut state, verbose,
        )
        .await;
    }

    // ── Drain + invariants ─────────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    vlog!(verbose, "[drain] waiting for push events to propagate...");
    drain_events_push(&alice, &bob).await;

    let confirmed = state
        .sent_messages
        .iter()
        .filter(|m| m.message_id.is_some())
        .count();

    check_delivery_n(&clients, &state)
        .await
        .expect("delivery invariant violated");
    vlog!(verbose, "[check] delivery... ok ({confirmed} messages)");

    check_per_sender_ordering_n(&clients, &state)
        .await
        .expect("per-sender ordering invariant violated");
    vlog!(verbose, "[check] per-sender ordering... ok");

    check_no_duplicates_n(&clients, &state)
        .await
        .expect("no-duplicates invariant violated");
    vlog!(verbose, "[check] no duplicates... ok");

    if verbose {
        eprintln!();
        eprintln!("=== PASSED ===");
    }
}
