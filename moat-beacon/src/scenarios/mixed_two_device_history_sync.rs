//! Two-device history sync scenario — mixed runtime variant.
//!
//! Device 1 and Device 2 run different runtimes (Rust CLI vs Dart headless
//! server). The scenario mirrors `two_device_history_sync` exactly; only the
//! participant kinds differ. Both orderings are tested:
//!   - `dart_d2 = false`: Rust D1, Dart D2  (label "rd")
//!   - `dart_d2 = true`:  Dart D1, Rust D2  (label "dr")
//!
//! Invariants verified:
//! - Both devices share the same ring group.
//! - After sync, device 2 has all messages that device 1 had before sync.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

/// Rust D1, Dart D2.
pub(crate) fn run_rd_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(false, verbose))
}

/// Dart D1, Rust D2.
pub(crate) fn run_dr_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(true, verbose))
}

pub async fn run(dart_d2: bool, verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    let (d1_kind, d2_kind) = if dart_d2 {
        (ParticipantKind::DartServer, ParticipantKind::RustCli)
    } else {
        (ParticipantKind::RustCli, ParticipantKind::DartServer)
    };

    vlog!("=== Scenario: mixed-two-device-history-sync (dart_d2={dart_d2}) ===");

    // ── Prologue: spin up Alice (D1 kind) + Bob (Rust) with Drawbridge ────────
    vlog!("[setup] starting TestWorld with alice ({d1_kind:?}) and bob (RustCli)...");
    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        &[d1_kind, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");

    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();

    vlog!("[setup] logging in alice (d1) and bob...");
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    tokio::time::sleep(Duration::from_millis(800)).await;

    // ── Start a conversation and send messages from D1 ────────────────────────
    vlog!("[setup] alice starts conversation with bob...");
    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");

    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    vlog!("[setup] group_id = {group_id}");

    for _ in 0..5 {
        let s = bob.poll().await.expect("bob poll");
        if s.new_conversations > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let test_messages = ["hello from d1", "second message", "third message"];
    for msg in &test_messages {
        d1.send_message(&group_id, msg).await.expect("d1 send");
        vlog!("[setup] d1 sent: {msg}");
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.poll().await.expect("bob final poll");

    let d1_msgs_before = d1.get_messages(&group_id).await.expect("d1 get_messages");
    vlog!("[check] d1 has {} messages before sync", d1_msgs_before.len());
    assert_eq!(
        d1_msgs_before.len(),
        test_messages.len(),
        "d1 should have {} messages before sync",
        test_messages.len()
    );

    // ── Spawn second device and bootstrap ring ────────────────────────────────
    vlog!("[setup] spawning alice device 2 ({d2_kind:?})...");
    let d2 = world
        .spawn_nth_device("alice-d2", d2_kind)
        .await
        .expect("spawn second device");

    d2.login("alice.postern.test", "any-password").await.expect("d2 login");
    vlog!("[setup] d2 logged in");

    tokio::time::sleep(Duration::from_millis(800)).await;

    for i in 0..6 {
        vlog!("[ring cycle {i}]");
        d1.ring_tick().await.expect("d1 ring_tick");
        d2.ring_tick().await.expect("d2 ring_tick");
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let s1 = d1.ring_status().await.expect("d1 ring_status");
    let s2 = d2.ring_status().await.expect("d2 ring_status");
    vlog!("[check] d1 ring = {:?}", s1.ring_group_id);
    vlog!("[check] d2 ring = {:?}", s2.ring_group_id);

    assert!(s1.ring_group_id.is_some(), "d1 must have a ring group");
    assert_eq!(
        s1.ring_group_id, s2.ring_group_id,
        "both devices must share the ring (dart_d2={dart_d2})"
    );

    // ── Trigger history sync ──────────────────────────────────────────────────
    vlog!("[sync] triggering sync on both devices...");
    d1.sync_start().await.expect("d1 sync_start");
    d2.sync_start().await.expect("d2 sync_start");

    for cycle in 0..10 {
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(300)).await;

        let d2_msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        vlog!("[sync cycle {cycle}] d2 has {} messages", d2_msgs.len());
        if d2_msgs.len() >= test_messages.len() {
            break;
        }
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let d2_msgs = d2.get_messages(&group_id).await.expect("d2 get_messages");
    vlog!("[check] d2 has {} messages after sync", d2_msgs.len());

    assert!(
        d2_msgs.len() >= test_messages.len(),
        "d2 should have all {} messages after sync; got {} (dart_d2={dart_d2})",
        test_messages.len(),
        d2_msgs.len()
    );

    for expected in &test_messages {
        assert!(
            d2_msgs.iter().any(|m| m.content.contains(expected)),
            "d2 missing message {:?} after sync (dart_d2={dart_d2})",
            expected
        );
    }

    vlog!("[check] mixed history sync (dart_d2={dart_d2})... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
