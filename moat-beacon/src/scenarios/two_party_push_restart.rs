//! Two-party Drawbridge push delivery scenario with offline/online cycles.
//!
//! Extends `two_party_push` with `GoOffline` / `ComeOnline` actions so that
//! proptest sequences can kill and restart participant subprocesses.  Verifies
//! that MLS state survives restarts and that messages sent while offline are
//! delivered after reconnecting to Drawbridge.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::invariants::{
    check_per_sender_ordering, check_delivery, check_no_duplicates, ScenarioState,
};
use crate::world::TestWorld;

use super::{ensure_all_online, execute_action, format_action, vlog, TwoPartyEnv};
use super::two_party_push::drain_events_push;

pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(actions, verbose))
}

pub async fn run(actions: Vec<Action>, verbose: bool) {
    vlog!(verbose, "=== Scenario: two-party-push-restart ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
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
    vlog!(verbose, "[setup] login alice... done");

    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");
    vlog!(verbose, "[setup] login bob... done");

    // Wait for both participants to connect to their own Drawbridge relay.
    let drawbridge_deadline =
        std::time::Instant::now() + Duration::from_secs(5);
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
    vlog!(verbose, "[setup] Drawbridge connections established");

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    vlog!(verbose, "[setup] bob watches alice... done");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // One explicit poll: Bob joins the group (receives Welcome) and picks up
    // Alice's DrawbridgeHint so he connects as recipient.
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

    // Give Bob time to send reciprocal DrawbridgeHint, then Alice picks it up.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = alice.poll().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — delivery must come entirely through Drawbridge.
    alice.set_poll_interval(0).await.expect("disable alice polling");
    bob.set_poll_interval(0).await.expect("disable bob polling");
    vlog!(verbose, "[setup] polling disabled (push-only mode)");

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
        push_mode: true,
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

    // Bring any offline participants back online before draining.
    vlog!(verbose, "[drain] ensuring all participants are online...");
    ensure_all_online(&mut world, &env).await;

    vlog!(verbose, "[drain] waiting for push events to propagate...");
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
