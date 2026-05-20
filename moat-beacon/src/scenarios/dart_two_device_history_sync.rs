//! Two-device history sync scenario — Dart-only variant.
//!
//! All three participants (alice-d1, alice-d2, bob) run the headless Dart
//! server.  Mirrors `two_device_history_sync` exactly; only the kinds differ.
//!
//! Invariants verified:
//! - Both Dart devices share the same ring group.
//! - After sync, device 2 has all messages that device 1 had before sync.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: dart-two-device-history-sync ===");

    vlog!("[setup] starting TestWorld with alice and bob (Dart, Drawbridge)...");
    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "shared"), ("bob", "shared")],
        &[ParticipantKind::DartServer, ParticipantKind::DartServer],
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

    let test_messages = ["hello from dart d1", "second message", "third message"];
    for msg in &test_messages {
        d1.send_message(&group_id, msg).await.expect("d1 send_message");
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

    vlog!("[setup] spawning alice Dart device 2...");
    let d2 = world
        .spawn_nth_device("alice-d2", ParticipantKind::DartServer)
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
    assert_eq!(s1.ring_group_id, s2.ring_group_id, "both Dart devices must share the ring");

    vlog!("[sync] triggering sync...");
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

    let d2_msgs = d2.get_messages(&group_id).await.expect("d2 get_messages");
    vlog!("[check] d2 has {} messages after sync", d2_msgs.len());

    assert!(
        d2_msgs.len() >= test_messages.len(),
        "d2 should have all {} messages after sync; got {}",
        test_messages.len(),
        d2_msgs.len()
    );

    for expected in &test_messages {
        assert!(
            d2_msgs.iter().any(|m| m.content.contains(expected)),
            "d2 missing message {:?} after sync",
            expected
        );
    }

    vlog!("[check] Dart history sync... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
