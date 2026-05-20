//! Three-device staggered-arrival scenario.
//!
//! D1 sets up a conversation with Bob, then D2 joins and sends a message,
//! then D3 joins.  D3 must receive both D1's pre-join history and D2's
//! staggered message via backward sync from D1 (leaf-0 offerer).
//!
//! Tested for four runtime combinations (RRR, DDD, DRR, RRD).
//!
//! Invariants verified:
//! - All three devices share the same ring group.
//! - D3 receives messages sent by both D1 and D2.

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
        "=== three-device-staggered (d1={d1_kind:?} d2={d2_kind:?} d3={d3_kind:?}) ==="
    );

    // ── Prologue: D1 + Bob with Drawbridge ───────────────────────────────────
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

    // D1 sends a message before any other device exists.
    d1.send_message(&group_id, "from-d1-before-d2").await.expect("d1 send");
    tokio::time::sleep(Duration::from_millis(300)).await;
    bob.poll().await.expect("bob poll after d1 msg");

    // ── D2 joins, bootstraps, and sends a message ─────────────────────────────
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
        assert!(s1.ring_group_id.is_some(), "d1 must have ring after d2 bootstrap");
        assert_eq!(s1.ring_group_id, s2.ring_group_id, "d1 and d2 must share ring");
    }

    // Add D2 to the Alice-Bob group.
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

    // Sync D1's history to D2.
    d1.sync_start().await.expect("d1 sync_start");
    d2.sync_start().await.expect("d2 sync_start");

    for cycle in 0..10 {
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let d2_msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        vlog!("[d2-sync {cycle}] d2 has {} messages", d2_msgs.len());
        if d2_msgs.iter().any(|m| m.content.contains("from-d1-before-d2")) {
            break;
        }
    }

    // D2 sends a message after joining.
    d2.send_message(&group_id, "from-d2-after-join").await.expect("d2 send");
    tokio::time::sleep(Duration::from_millis(300)).await;
    d1.poll().await.expect("d1 poll after d2 msg");
    bob.poll().await.expect("bob poll after d2 msg");

    // D1 must see D2's message (via normal polling on alice's PDS).
    for _ in 0..5 {
        let d1_msgs = d1.get_messages(&group_id).await.unwrap_or_default();
        if d1_msgs.iter().any(|m| m.content.contains("from-d2-after-join")) {
            break;
        }
        d1.poll().await.ok();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // ── D3 joins and syncs — must get both D1 and D2's messages ──────────────
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
        if s3.ring_group_id.is_some() {
            vlog!("[d3-join] d3 in ring at cycle {i}");
            break;
        }
    }

    // Add D3 to Alice-Bob group.
    for _ in 0..12 {
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d3.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        let _ = d3.poll().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        if d3.list_conversations().await.unwrap_or_default().iter().any(|c| c.id == group_id) {
            break;
        }
    }

    // Sync: D1 (leaf-0) offers, D3 joins.  D1's local store has both messages.
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
        let has_d1_msg = d3_msgs.iter().any(|m| m.content.contains("from-d1-before-d2"));
        let has_d2_msg = d3_msgs.iter().any(|m| m.content.contains("from-d2-after-join"));
        vlog!("[d3-sync {cycle}] d3 has {} msgs (d1={has_d1_msg} d2={has_d2_msg})", d3_msgs.len());
        if has_d1_msg && has_d2_msg {
            break;
        }
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let s1 = d1.ring_status().await.expect("d1 final ring_status");
    let s3 = d3.ring_status().await.expect("d3 final ring_status");

    assert!(s1.ring_group_id.is_some(), "d1 must have a ring");
    assert_eq!(s1.ring_group_id, s3.ring_group_id, "d1 and d3 must share the ring");

    let d3_msgs = d3.get_messages(&group_id).await.expect("d3 get_messages");
    vlog!("[check] d3 has {} messages after sync", d3_msgs.len());

    assert!(
        d3_msgs.iter().any(|m| m.content.contains("from-d1-before-d2")),
        "d3 must have D1's pre-join message after sync"
    );
    assert!(
        d3_msgs.iter().any(|m| m.content.contains("from-d2-after-join")),
        "d3 must have D2's staggered message after sync"
    );

    vlog!("[check] three-device staggered ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
