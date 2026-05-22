//! Three-party polling delivery scenario with offline/online cycles.
//!
//! Extends `three_party_chat` with `GoOffline` / `ComeOnline` actions.
//! Verifies that MLS state survives restarts and offline messages are delivered.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::invariants::{
    check_delivery_n, check_consensus_ordering_n, check_no_duplicates_n, drain_events_n,
    ScenarioState,
};
use crate::world::TestWorld;

use super::{ensure_all_online_n, execute_action_n, format_action, vlog, NPartyEnv};

pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(actions, verbose))
}

pub async fn run(actions: Vec<Action>, verbose: bool) {
    vlog!(verbose, "=== Scenario: three-party-restart ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld...");
    let mut world = TestWorld::new(&["alice", "bob", "carol"], ".postern.test")
        .await
        .expect("world setup");
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

    tokio::time::sleep(Duration::from_millis(500)).await;

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
    vlog!(verbose, "[setup] all three joined... group={group_id}");

    // ── Random action sequence ─────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    let mut state = ScenarioState {
        group_id,
        sent_messages: vec![],
        members: None,
    };
    let push_per_participant = [false; 3];
    let env = NPartyEnv {
        clients: &clients,
        handles: &handles,
        push_per_participant: &push_per_participant,
        verbose,
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
        execute_action_n(action, &env, &mut world, &mut state).await;
    }

    // ── Drain + invariants ─────────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }

    vlog!(verbose, "[drain] ensuring all participants are online...");
    ensure_all_online_n(&mut world, &env).await;

    vlog!(verbose, "[drain] waiting for events to propagate...");
    drain_events_n(&clients).await;

    let confirmed = state
        .sent_messages
        .iter()
        .filter(|m| m.message_id.is_some())
        .count();

    check_delivery_n(&clients, &state)
        .await
        .expect("delivery invariant violated");
    vlog!(verbose, "[check] delivery... ok ({confirmed} messages)");

    check_consensus_ordering_n(&clients, &state)
        .await
        .expect("consensus ordering invariant violated");
    vlog!(verbose, "[check] consensus ordering... ok");

    check_no_duplicates_n(&clients, &state)
        .await
        .expect("no-duplicates invariant violated");
    vlog!(verbose, "[check] no duplicates... ok");

    if verbose {
        eprintln!();
        eprintln!("=== PASSED ===");
    }
}
