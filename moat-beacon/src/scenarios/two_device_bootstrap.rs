//! Two-device bootstrap scenario.
//!
//! One user (Alice) runs two moat-cli processes — simulating a phone and a
//! laptop.  Both login with the same credentials, then exchange ring-tick
//! cycles until they form a shared device ring.
//!
//! Invariants verified:
//! - Both devices end up with the same non-null `ring_group_id`.
//! - The ring group does **not** appear in either device's conversation list.

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

    vlog!("=== Scenario: two-device-bootstrap ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    vlog!("[setup] starting TestWorld with one account (alice)...");
    let mut world = TestWorld::new(&["alice"], ".postern.test")
        .await
        .expect("world setup");

    let d1 = world.client("alice").clone();

    vlog!("[setup] spawning second device...");
    let d2 = world
        .spawn_nth_device("alice-d2", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn second device");

    // Login both devices with the same credentials.
    d1.login("alice.postern.test", "any-password")
        .await
        .expect("d1 login");
    vlog!("[setup] d1 logged in");

    d2.login("alice.postern.test", "any-password")
        .await
        .expect("d2 login");
    vlog!("[setup] d2 logged in");

    // Allow both devices to publish their key packages and stealth addresses.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // ── Ring bootstrap cycles ─────────────────────────────────────────────────
    //
    // Sequence per cycle:
    //   ring_tick   — discovers siblings, creates/joins coord groups, bootstraps ring
    //   poll        — routes coord MLS events (Hello, RingInfo) via tag_map
    //
    // We run several cycles to ensure convergence regardless of which device
    // has the smaller device_id (and therefore creates the ring).
    for i in 0..6 {
        vlog!("[cycle {i}] d1.ring_tick…");
        d1.ring_tick().await.expect("d1 ring_tick");
        vlog!("[cycle {i}] d2.ring_tick…");
        d2.ring_tick().await.expect("d2 ring_tick");
        vlog!("[cycle {i}] d1.poll…");
        d1.poll().await.expect("d1 poll");
        vlog!("[cycle {i}] d2.poll…");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let s1 = d1.ring_status().await.expect("d1 ring_status");
    let s2 = d2.ring_status().await.expect("d2 ring_status");

    vlog!("[check] d1 ring_group_id = {:?}", s1.ring_group_id);
    vlog!("[check] d2 ring_group_id = {:?}", s2.ring_group_id);

    assert!(
        s1.ring_group_id.is_some(),
        "d1 should have a ring group; coord_count={}",
        s1.coord_group_count
    );
    assert!(
        s2.ring_group_id.is_some(),
        "d2 should have a ring group; coord_count={}",
        s2.coord_group_count
    );
    assert_eq!(
        s1.ring_group_id, s2.ring_group_id,
        "both devices must be in the same ring"
    );

    // Ring and coord groups must not appear in the conversation list.
    let convs1 = d1.list_conversations().await.expect("d1 list_conversations");
    let convs2 = d2.list_conversations().await.expect("d2 list_conversations");
    assert!(
        convs1.is_empty(),
        "d1 conversation list should be empty (no user conversations); got {convs1:?}"
    );
    assert!(
        convs2.is_empty(),
        "d2 conversation list should be empty (no user conversations); got {convs2:?}"
    );

    vlog!("[check] ring bootstrap... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
