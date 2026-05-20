//! Three-device history sync scenario.
//!
//! D1 sends messages into an Alice-Bob conversation, then D2 joins the ring
//! and syncs from D1, then D3 joins and must also sync from D1 (leaf-0 is
//! always the offerer).  After both syncs D3 must have every message that D1
//! had before D2 joined.
//!
//! Tested for four runtime combinations (RRR, DDD, DRR, RRD) to cover:
//! - D1 as Dart offerer (DRR, DDD)
//! - D3 as Dart late joiner (RRD, DDD)
//!
//! Invariants verified:
//! - All three devices share the same ring group.
//! - After sync, D3 has all messages that D1 had before D2 joined.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};
use ParticipantKind::{DartServer as D, RustCli as R};

// ── Boxed entry points for the SCENARIOS registry ────────────────────────────

pub(crate) fn run_rrr_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(R, R, R, v))
}
pub(crate) fn run_ddd_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(D, D, D, v))
}
pub(crate) fn run_drr_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(D, R, R, v))
}
pub(crate) fn run_rrd_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(R, R, D, v))
}

// ── Core scenario ─────────────────────────────────────────────────────────────

pub async fn run(
    d1_kind: ParticipantKind,
    d2_kind: ParticipantKind,
    d3_kind: ParticipantKind,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!(
        "=== three-device-history-sync (d1={d1_kind:?} d2={d2_kind:?} d3={d3_kind:?}) ==="
    );

    // ── Prologue: D1 + Bob, Drawbridge required for pair-WS sync ─────────────
    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        &[d1_kind, R],
        ".postern.test",
    )
    .await
    .expect("world setup");

    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();

    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    tokio::time::sleep(Duration::from_millis(800)).await;

    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");

    let group_id = d1.start_conversation("bob.postern.test").await.expect("start conversation");
    vlog!("[setup] group_id = {group_id}");

    for _ in 0..5 {
        let s = bob.poll().await.expect("bob poll");
        if s.new_conversations > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // ── D1 sends messages ─────────────────────────────────────────────────────
    let test_messages = ["msg-alpha", "msg-beta", "msg-gamma"];
    for msg in &test_messages {
        d1.send_message(&group_id, msg).await.expect("d1 send");
        vlog!("[setup] d1 sent: {msg}");
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.poll().await.expect("bob final poll");

    let d1_msgs_before = d1.get_messages(&group_id).await.expect("d1 get_messages");
    assert_eq!(
        d1_msgs_before.len(),
        test_messages.len(),
        "d1 should have {} messages before any device joins",
        test_messages.len()
    );
    vlog!("[check] d1 has {} messages pre-sync", d1_msgs_before.len());

    // ── D2 joins and syncs ────────────────────────────────────────────────────
    let d2 = world
        .spawn_nth_device("alice-d2", d2_kind)
        .await
        .expect("spawn alice-d2");

    d2.login("alice.postern.test", "any-password").await.expect("d2 login");
    tokio::time::sleep(Duration::from_millis(800)).await;

    for i in 0..6 {
        vlog!("[d2-bootstrap {i}]");
        d1.ring_tick().await.expect("d1 ring_tick");
        d2.ring_tick().await.expect("d2 ring_tick");
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    {
        let s1 = d1.ring_status().await.expect("d1 ring_status");
        let s2 = d2.ring_status().await.expect("d2 ring_status");
        assert!(s1.ring_group_id.is_some(), "d1 must have a ring after d2 bootstrap");
        assert_eq!(s1.ring_group_id, s2.ring_group_id, "d1 and d2 must share ring");
    }

    // Add D2 to the Alice-Bob conversation and trigger sync from D1 (leaf-0).
    for _ in 0..12 {
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        if d2.list_conversations().await.unwrap_or_default().iter().any(|c| c.id == group_id) {
            break;
        }
    }

    d1.sync_start().await.expect("d1 sync_start after d2 join");
    d2.sync_start().await.expect("d2 sync_start");

    for cycle in 0..10 {
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let d2_msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        vlog!("[d2-sync cycle {cycle}] d2 has {} messages", d2_msgs.len());
        if d2_msgs.len() >= test_messages.len() {
            break;
        }
    }

    {
        let d2_msgs = d2.get_messages(&group_id).await.expect("d2 get_messages");
        assert!(
            d2_msgs.len() >= test_messages.len(),
            "d2 should have all {} messages after sync; got {}",
            test_messages.len(),
            d2_msgs.len()
        );
        vlog!("[check] d2 synced ok ({} messages)", d2_msgs.len());
    }

    // ── D3 joins and syncs from D1 (leaf-0 remains offerer) ──────────────────
    let d3 = world
        .spawn_nth_device("alice-d3", d3_kind)
        .await
        .expect("spawn alice-d3");

    d3.login("alice.postern.test", "any-password").await.expect("d3 login");
    tokio::time::sleep(Duration::from_millis(800)).await;

    for i in 0..10 {
        vlog!("[d3-join {i}]");
        d1.ring_tick().await.expect("d1 ring_tick");
        d2.ring_tick().await.expect("d2 ring_tick");
        d3.ring_tick().await.expect("d3 ring_tick");
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        d3.poll().await.expect("d3 poll");
        tokio::time::sleep(Duration::from_millis(150)).await;

        let s3 = d3.ring_status().await.unwrap_or_default();
        let d1_sync = d1.sync_status().await.unwrap_or(false);
        let d3_sync = d3.sync_status().await.unwrap_or(false);
        vlog!("[d3-join {i}] ring={:?} d1_sync={d1_sync} d3_sync={d3_sync}", s3.ring_group_id.is_some());
        if s3.ring_group_id.is_some() {
            vlog!("[d3-join] d3 joined ring at cycle {i}");
            break;
        }
    }

    // Wait for D3 to be added to Alice-Bob group.
    for j in 0..12 {
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d3.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        let _ = d3.poll().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let d1_sync = d1.sync_status().await.unwrap_or(false);
        let d3_sync = d3.sync_status().await.unwrap_or(false);
        let d3_in = d3.list_conversations().await.unwrap_or_default().iter().any(|c| c.id == group_id);
        vlog!("[d3-bob-wait {j}] d3_in_conv={d3_in} d1_sync={d1_sync} d3_sync={d3_sync}");
        if d3_in {
            break;
        }
    }

    // Diagnostic: check if D3 is in Alice-Bob before sync
    {
        let d3_convs = d3.list_conversations().await.unwrap_or_default();
        let d3_in_conv = d3_convs.iter().any(|c| c.id == group_id);
        vlog!("[diag] d3 in Alice-Bob conv before sync: {d3_in_conv} (d3 has {} convs)", d3_convs.len());
        let s1 = d1.ring_status().await.unwrap_or_default();
        let s3 = d3.ring_status().await.unwrap_or_default();
        vlog!("[diag] d1 ring={:?} d3 ring={:?}", s1.ring_group_id, s3.ring_group_id);
        let d1_sync = d1.sync_status().await.unwrap_or(false);
        let d3_sync = d3.sync_status().await.unwrap_or(false);
        vlog!("[diag] d1 sync_active={d1_sync} d3 sync_active={d3_sync}");
    }

    // Trigger sync — D1 (leaf-0) sends SyncOffer; D3 joins.
    d1.sync_start().await.expect("d1 sync_start after d3 join");
    d3.sync_start().await.expect("d3 sync_start");

    for cycle in 0..15 {
        d1.ring_tick().await.expect("d1 ring_tick");
        d2.ring_tick().await.expect("d2 ring_tick");
        d3.ring_tick().await.expect("d3 ring_tick");
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        d3.poll().await.expect("d3 poll");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let d3_msgs = d3.get_messages(&group_id).await.unwrap_or_default();
        let d1_sync = d1.sync_status().await.unwrap_or(false);
        let d3_sync = d3.sync_status().await.unwrap_or(false);
        vlog!("[d3-sync cycle {cycle}] d3 has {} messages d1_sync={d1_sync} d3_sync={d3_sync}", d3_msgs.len());
        if d3_msgs.len() >= test_messages.len() {
            break;
        }
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let s1 = d1.ring_status().await.expect("d1 final ring_status");
    let s3 = d3.ring_status().await.expect("d3 final ring_status");

    assert!(s1.ring_group_id.is_some(), "d1 must have a ring");
    assert_eq!(s1.ring_group_id, s3.ring_group_id, "all devices must share the ring");

    let d3_msgs = d3.get_messages(&group_id).await.expect("d3 get_messages");
    vlog!("[check] d3 has {} messages after sync", d3_msgs.len());

    assert!(
        d3_msgs.len() >= test_messages.len(),
        "d3 should have all {} messages after sync; got {}",
        test_messages.len(),
        d3_msgs.len()
    );
    for expected in &test_messages {
        assert!(
            d3_msgs.iter().any(|m| m.content.contains(expected)),
            "d3 missing message {:?} after sync",
            expected
        );
    }

    vlog!("[check] three-device history sync ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
