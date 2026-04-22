//! Two-device history sync scenario.
//!
//! One user (Alice) runs two moat-cli processes — phone and laptop.  Both
//! login and form a device ring.  The phone sends several messages in a
//! conversation with Bob, then the laptop joins the ring and triggers a
//! history sync.  After sync completes the laptop's message list must match
//! the phone's.
//!
//! Invariants verified:
//! - Both devices share the same ring group.
//! - After sync, device 2 has all messages that device 1 had before sync.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::scenarios::Action;
use crate::world::TestWorld;

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

    vlog!("=== Scenario: two-device-history-sync ===");

    // ── Prologue: spin up Alice + Bob ─────────────────────────────────────────
    vlog!("[setup] starting TestWorld with alice and bob...");
    let mut world = TestWorld::new(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup");

    let d1 = world.client("alice").clone(); // Alice device 1 (phone)
    let bob = world.client("bob").clone();

    vlog!("[setup] logging in alice (d1) and bob...");
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    tokio::time::sleep(Duration::from_millis(800)).await;

    // ── Start a conversation and send messages from d1 ────────────────────────
    vlog!("[setup] alice starts conversation with bob...");
    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");

    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    vlog!("[setup] group_id = {group_id}");

    // Bob polls to join.
    for _ in 0..5 {
        let s = bob.poll().await.expect("bob poll");
        if s.new_conversations > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Send a few messages from d1 so there is history to sync.
    let test_messages = ["hello from d1", "second message", "third message"];
    for msg in &test_messages {
        d1.send_message(&group_id, msg).await.expect("d1 send_message");
        vlog!("[setup] d1 sent: {msg}");
    }

    // Let messages propagate.
    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.poll().await.expect("bob final poll");

    // Verify d1 has 3 messages.
    let d1_msgs_before = d1.get_messages(&group_id).await.expect("d1 get_messages");
    vlog!("[check] d1 has {} messages before sync", d1_msgs_before.len());
    assert_eq!(
        d1_msgs_before.len(),
        test_messages.len(),
        "d1 should have {} messages before sync",
        test_messages.len()
    );

    // ── Spawn second device and bootstrap ring ────────────────────────────────
    vlog!("[setup] spawning alice device 2...");
    let d2 = world
        .spawn_second_device("alice-d2")
        .await
        .expect("spawn second device");

    d2.login("alice.postern.test", "any-password").await.expect("d2 login");
    vlog!("[setup] d2 logged in");

    tokio::time::sleep(Duration::from_millis(800)).await;

    // Ring bootstrap cycles.
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
    assert_eq!(s1.ring_group_id, s2.ring_group_id, "both devices must share the ring");

    // ── Trigger history sync ──────────────────────────────────────────────────
    //
    // The device with leaf index 0 (ring creator = d1) sends the SyncOffer via
    // the ring group.  `sync_start` calls `do_ring_tick` which checks the offerer
    // condition internally.  We call it on both devices; only the offerer acts.
    vlog!("[sync] triggering sync on d1...");
    d1.sync_start().await.expect("d1 sync_start");
    d2.sync_start().await.expect("d2 sync_start");

    // Allow time for:
    //   1. SyncOffer coord message to route via PDS
    //   2. d2 to connect pair WS and send Hello
    //   3. Batch exchange to complete
    // Each round trip is: encrypt → publish → poll → decrypt → respond
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
        "d2 should have all {} messages after sync; got {}",
        test_messages.len(),
        d2_msgs.len()
    );

    // All test messages must be present on d2.
    for expected in &test_messages {
        assert!(
            d2_msgs.iter().any(|m| m.content.contains(expected)),
            "d2 missing message {:?} after sync",
            expected
        );
    }

    vlog!("[check] history sync... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
