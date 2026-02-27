//! Two-party polling delivery scenario.
//!
//! Alice and Bob exchange messages via a standard [`TestWorld`] (no Drawbridge).
//! Message delivery relies on explicit polling by participants.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::invariants::{
    check_consensus_ordering, check_delivery, check_no_duplicates, drain_events, ScenarioState,
};
use crate::world::TestWorld;

use super::{execute_action, format_action, vlog};

pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(actions, verbose))
}

pub async fn run(actions: Vec<Action>, verbose: bool) {
    vlog!(verbose, "=== Scenario: two-party-chat ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld...");
    let world = TestWorld::new(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup");
    let alice = world.client("alice");
    let bob = world.client("bob");

    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    vlog!(verbose, "[setup] login alice... done");

    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");
    vlog!(verbose, "[setup] login bob... done");

    // Allow moat-cli to publish key packages and stealth addresses.
    tokio::time::sleep(Duration::from_millis(500)).await;

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    vlog!(verbose, "[setup] bob watches alice... done");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    tokio::time::sleep(Duration::from_millis(500)).await;

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

    // ── Random action sequence ─────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    let mut state = ScenarioState { group_id, sent_messages: vec![] };

    let total = actions.len();
    for (i, action) in actions.iter().enumerate() {
        vlog!(verbose, "[action {}/{}] {}", i + 1, total, format_action(action));
        execute_action(action, alice, bob, &mut state, verbose).await;
    }

    // ── Drain + invariants ─────────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    vlog!(verbose, "[drain] waiting for events to propagate...");
    drain_events(alice, bob).await;

    let confirmed = state.sent_messages.iter().filter(|m| m.message_id.is_some()).count();

    check_delivery(alice, bob, &state).await.expect("delivery invariant violated");
    vlog!(verbose, "[check] delivery... ok ({confirmed} messages)");

    check_consensus_ordering(alice, bob, &state)
        .await
        .expect("consensus ordering invariant violated");
    vlog!(verbose, "[check] consensus ordering... ok");

    check_no_duplicates(alice, bob, &state)
        .await
        .expect("no-duplicates invariant violated");
    vlog!(verbose, "[check] no duplicates... ok");

    if verbose {
        eprintln!();
        eprintln!("=== PASSED ===");
    }
}
