//! Three-device bootstrap scenario.
//!
//! One user (Alice) runs three moat-cli processes — simulating a phone,
//! laptop, and tablet.  D1 + D2 form a ring first, then D3 joins the
//! established ring.  Parametrised over all eight (d1, d2, d3) runtime
//! combinations so every cross-runtime coord-group handshake is covered.
//!
//! Invariants verified:
//! - All three devices end up with the same non-null `ring_group_id`.
//! - Each device holds exactly 2 coord groups (one per sibling pair).
//! - Ring and coord groups do **not** appear in any device's conversation list.

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
pub(crate) fn run_rrd_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(R, R, D, v))
}
pub(crate) fn run_rdr_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(R, D, R, v))
}
pub(crate) fn run_drr_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(D, R, R, v))
}
pub(crate) fn run_rdd_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(R, D, D, v))
}
pub(crate) fn run_drd_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(D, R, D, v))
}
pub(crate) fn run_ddr_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(D, D, R, v))
}
pub(crate) fn run_ddd_boxed(_: Vec<Action>, v: bool) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(D, D, D, v))
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
        "=== three-device-bootstrap (d1={d1_kind:?} d2={d2_kind:?} d3={d3_kind:?}) ==="
    );

    // ── Setup ─────────────────────────────────────────────────────────────────
    let mut world = TestWorld::new_with_kinds(&["alice"], &[d1_kind], ".postern.test")
        .await
        .expect("world setup");

    let d1 = world.client("alice").clone();

    let d2 = world
        .spawn_nth_device("alice-d2", d2_kind)
        .await
        .expect("spawn alice-d2");

    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    tokio::time::sleep(Duration::from_millis(800)).await;

    // ── D1 + D2 ring bootstrap ────────────────────────────────────────────────
    for i in 0..6 {
        vlog!("[d1d2-bootstrap {i}]");
        d1.ring_tick().await.expect("d1 ring_tick");
        d2.ring_tick().await.expect("d2 ring_tick");
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    {
        let s1 = d1.ring_status().await.expect("d1 ring_status post d1d2");
        let s2 = d2.ring_status().await.expect("d2 ring_status post d1d2");
        assert!(
            s1.ring_group_id.is_some(),
            "d1 must have a ring after d1+d2 bootstrap; coord_count={}",
            s1.coord_group_count
        );
        assert_eq!(
            s1.ring_group_id, s2.ring_group_id,
            "d1 and d2 must share a ring before d3 joins"
        );
        vlog!("[check] d1+d2 ring ok: {:?}", s1.ring_group_id);
    }

    // ── Spawn D3 and bootstrap into the existing ring ─────────────────────────
    let d3 = world
        .spawn_nth_device("alice-d3", d3_kind)
        .await
        .expect("spawn alice-d3");

    d3.login("alice.postern.test", "any-password").await.expect("d3 login");

    tokio::time::sleep(Duration::from_millis(800)).await;

    // More cycles needed: D3 must exchange coord Hellos with both D1 and D2, then
    // D1 (leaf-0) adds D3 to the ring and stealth-publishes the Welcome.
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
            vlog!("[d3-join] d3 joined ring at cycle {i}");
            break;
        }
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let s1 = d1.ring_status().await.expect("d1 final ring_status");
    let s2 = d2.ring_status().await.expect("d2 final ring_status");
    let s3 = d3.ring_status().await.expect("d3 final ring_status");

    vlog!("[check] d1 ring={:?} coord={}", s1.ring_group_id, s1.coord_group_count);
    vlog!("[check] d2 ring={:?} coord={}", s2.ring_group_id, s2.coord_group_count);
    vlog!("[check] d3 ring={:?} coord={}", s3.ring_group_id, s3.coord_group_count);

    assert!(s1.ring_group_id.is_some(), "d1 must have a ring");
    assert!(s3.ring_group_id.is_some(), "d3 must have joined the ring");
    assert_eq!(s1.ring_group_id, s2.ring_group_id, "d1 and d2 must share the ring");
    assert_eq!(s1.ring_group_id, s3.ring_group_id, "d1 and d3 must share the ring");

    // Coord-group counts are *not* symmetric across all three devices.
    // D3 (the new joiner) independently discovers D1 and D2 from outside
    // any ring, so it always ends up with one coord group per pre-existing
    // device: 2.
    //
    // Among D1 and D2, only the *elected* member (whichever has the
    // smaller device_id and therefore became the original ring's leaf 0)
    // creates a coord group with a brand-new sibling once a ring exists;
    // the other pre-existing member defers to it (see
    // `on_peer_kp_observed`'s leaf-election gate in
    // `crates/moat-core/src/device_ring.rs` — without this gate, both
    // existing ring members would independently race to consume D3's same
    // cross-user-pool KeyPackage, and only one could ever succeed,
    // permanently stalling the other's ring-add path).  So the elected
    // member ends up with 2 coord groups (the original D1-D2 one, plus the
    // new one with D3); the non-elected member stays at 1 (just the
    // original). Device_id assignment is random per run, so either of
    // D1/D2 can be the elected one — assert the *set* of counts, not a
    // fixed assignment.
    assert_eq!(s3.coord_group_count, 2, "d3 must have 2 coord groups (one per pre-existing device)");
    let mut d1_d2_counts = [s1.coord_group_count, s2.coord_group_count];
    d1_d2_counts.sort();
    assert_eq!(
        d1_d2_counts,
        [1, 2],
        "exactly one of d1/d2 (the elected, smaller-device_id member) must have 2 coord groups; \
         the other must have 1 (deferred to the elected member for D3's coord group) — got d1={}, d2={}",
        s1.coord_group_count, s2.coord_group_count
    );

    for (label, client) in [("d1", &d1), ("d2", &d2), ("d3", &d3)] {
        let convs = client
            .list_conversations()
            .await
            .unwrap_or_else(|e| panic!("{label} list_conversations failed: {e}"));
        assert!(
            convs.is_empty(),
            "{label} conversation list must be empty (no ring/coord groups); got {convs:?}"
        );
    }

    vlog!("[check] three-device bootstrap ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
