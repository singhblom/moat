//! Cross-implementation two-party polling scenario.
//!
//! Alice runs the Rust CLI (`moat-cli --http`) and Bob runs the Dart headless
//! server (`moat_dart_server --http`).  Tests that both implementations
//! interoperate correctly: MLS Welcome, key packages, stealth addresses, and
//! message delivery all work across the language boundary.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::invariants::{
    check_consensus_ordering, check_delivery, check_no_duplicates, drain_events, ScenarioState,
};
use crate::world::{ParticipantKind, TestWorld};

use super::{execute_action, format_action, vlog, TwoPartyEnv};

pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(actions, verbose))
}

pub async fn run(actions: Vec<Action>, verbose: bool) {
    vlog!(verbose, "=== Scenario: mixed-two-party-chat (Rust ↔ Dart) ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (Rust + Dart)...");
    let mut world = TestWorld::new_with_kinds(
        &["alice", "bob"],
        &[ParticipantKind::RustCli, ParticipantKind::DartServer],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let alice = world.client("alice").clone();
    let bob = world.client("bob").clone();

    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    vlog!(verbose, "[setup] login alice (Rust)... done");

    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");
    vlog!(verbose, "[setup] login bob (Dart)... done");

    // Allow key packages and stealth addresses to be published.
    tokio::time::sleep(Duration::from_millis(500)).await;

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    vlog!(verbose, "[setup] bob (Dart) watches alice (Rust)... done");

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
        "[setup] alice (Rust) starts conversation... group={group_id}"
    );
    vlog!(
        verbose,
        "[setup] bob (Dart) polls to join... done ({} new conversations)",
        stats.new_conversations
    );

    // ── Random action sequence ─────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    let mut state = ScenarioState { group_id, sent_messages: vec![], members: None };
    let env = TwoPartyEnv {
        alice: &alice,
        bob: &bob,
        alice_full_handle: "alice.postern.test",
        bob_full_handle: "bob.postern.test",
        push_mode: false,
        verbose,
    };

    let total = actions.len();
    for (i, action) in actions.iter().enumerate() {
        vlog!(verbose, "[action {}/{}] {}", i + 1, total, format_action(action));
        execute_action(action, &env, &mut world, &mut state).await;
    }

    // ── Drain + invariants ─────────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    vlog!(verbose, "[drain] waiting for events to propagate...");
    drain_events(&alice, &bob).await;

    let confirmed = state.sent_messages.iter().filter(|m| m.message_id.is_some()).count();

    check_delivery(&alice, &bob, &state).await.expect("delivery invariant violated");
    vlog!(verbose, "[check] delivery... ok ({confirmed} messages)");

    check_consensus_ordering(&alice, &bob, &state)
        .await
        .expect("consensus ordering invariant violated");
    vlog!(verbose, "[check] consensus ordering... ok");

    check_no_duplicates(&alice, &bob, &state)
        .await
        .expect("no-duplicates invariant violated");
    vlog!(verbose, "[check] no duplicates... ok");

    if verbose {
        eprintln!();
        eprintln!("=== PASSED ===");
    }
}
