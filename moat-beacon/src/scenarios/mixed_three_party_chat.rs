//! Three-party polling delivery scenario — Alice (Rust CLI), Bob + Carol (Dart server).
//!
//! Verifies interop between Rust and Dart for the add-member flow.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::invariants::{
    check_delivery_n, check_consensus_ordering_n, check_no_duplicates_n, drain_events_n,
    ScenarioState,
};
use crate::world::{ParticipantKind, TestWorld};

use super::{execute_action_n, format_action, vlog};

pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(actions, verbose))
}

pub async fn run(actions: Vec<Action>, verbose: bool) {
    vlog!(verbose, "=== Scenario: mixed-three-party-chat ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld (Rust + Dart × 2)...");
    let mut world = TestWorld::new_with_kinds(
        &["alice", "bob", "carol"],
        &[
            ParticipantKind::RustCli,
            ParticipantKind::DartServer,
            ParticipantKind::DartServer,
        ],
        ".postern.test",
    )
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

    // Bob and Carol watch Alice for invites
    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    carol
        .watch_handle("alice.postern.test")
        .await
        .expect("carol watch alice");
    vlog!(verbose, "[setup] bob + carol watch alice... done");

    // Alice starts conversation with Bob
    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation with bob");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = bob.poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group after prologue poll"
    );
    vlog!(verbose, "[setup] alice starts conv with bob... group={group_id}");

    // Alice adds Carol
    alice
        .add_member(&group_id, "carol.postern.test")
        .await
        .expect("alice add carol");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Carol polls to receive Welcome
    let stats = carol.poll().await.expect("carol join poll");
    assert!(
        stats.new_conversations > 0,
        "Carol should have joined the group after poll"
    );

    // Bob polls to receive the Commit
    let _ = bob.poll().await;
    vlog!(verbose, "[setup] carol joined, bob got commit... done");

    // ── Random action sequence ─────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    let mut state = ScenarioState {
        group_id,
        sent_messages: vec![],
        members: None,
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
            action, &clients, &mut world, &handles, &[false; 3], &mut state, verbose,
        )
        .await;
    }

    // ── Drain + invariants ─────────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
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
