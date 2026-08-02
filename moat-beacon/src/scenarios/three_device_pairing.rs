//! Three-device live QR/text pairing scenario.
//!
//! D1 pairs D2 first (no ring exists yet); D1 then pairs D3 into the
//! now-existing ring. Onboarding goes exclusively through `POST /pair/new`,
//! `POST /pair/confirm`, and `GET /pair/status` — the pairing-based
//! successor to the deleted `three_device_bootstrap` scenario's coord-group
//! handshake.
//!
//! **Intentionally red**, for the same reason as `two_device_pairing`:
//! `/pair/*` doesn't exist on moat-cli's http server yet, and
//! `moat_core::pairing::PairingSession` is unimplemented.
//!
//! Unlike `two_device_pairing`, this scenario doesn't need to thread a ring
//! id anywhere by hand: D1's own persisted ring state already remembers
//! which ring it belongs to, so `pair_confirm` for D3's code re-uses it
//! automatically. Contrast `moat-core/tests/pairing_simulation.rs`'s
//! `three_device_pairing_converges_and_third_device_gets_history`, where
//! the ring id *does* have to be threaded explicitly between calls — each
//! simulated pairing there is a fresh, isolated `PairingSession` pair with
//! no shared host state backing it.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::client::MoatCliClient;
use crate::scenarios::Action;
use crate::world::TestWorld;

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

/// Drive one `/pair/new` (new device) + `/pair/confirm` (existing device)
/// exchange to completion. Bounded so a stuck pairing fails the test
/// instead of hanging it — see `crate::scenarios::two_device_pairing` for
/// the two-device version this mirrors.
pub(crate) async fn pair_devices(
    existing: &MoatCliClient,
    new_device: &MoatCliClient,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }
    const TIMEOUT: Duration = Duration::from_secs(20);
    const POLL_INTERVAL: Duration = Duration::from_millis(200);

    let pair_new = new_device.pair_new().await.expect("new device pair_new");
    vlog!("[pair] code = {}", pair_new.code);
    existing
        .pair_confirm(&pair_new.code)
        .await
        .expect("existing device pair_confirm");

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let existing_status = existing.pair_status().await.expect("existing pair_status");
        let new_status = new_device.pair_status().await.expect("new_device pair_status");
        vlog!(
            "[pair] existing.done={} new_device.done={}",
            existing_status.done, new_status.done
        );
        if existing_status.done && new_status.done {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pairing did not complete within {TIMEOUT:?} \
             (existing.done={}, new_device.done={}); this must fail the \
             test, not hang it",
            existing_status.done,
            new_status.done,
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: three-device-pairing ===");

    let mut world = TestWorld::new(&["alice"], ".postern.test")
        .await
        .expect("world setup");
    let d1 = world.client("alice").clone();
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");

    let d2 = world
        .spawn_nth_device("alice-d2", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2 (first pairing, creates the ring)...");
    pair_devices(&d1, &d2, verbose).await;

    let d3 = world
        .spawn_nth_device("alice-d3", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn d3");
    d3.login("alice.postern.test", "any-password").await.expect("d3 login");

    vlog!("[pair] d1 <- d3 (second pairing, adds to the existing ring)...");
    pair_devices(&d1, &d3, verbose).await;

    // ── Invariants ────────────────────────────────────────────────────────────
    let s1 = d1.ring_status().await.expect("d1 ring_status");
    let s2 = d2.ring_status().await.expect("d2 ring_status");
    let s3 = d3.ring_status().await.expect("d3 ring_status");

    assert!(s1.ring_group_id.is_some(), "d1 must have a ring");
    assert_eq!(s1.ring_group_id, s2.ring_group_id, "d1 and d2 must share the ring");
    assert_eq!(
        s1.ring_group_id, s3.ring_group_id,
        "d1 and d3 must share the *same* ring — d3's pairing must not have created a second one"
    );
    // d2's full MLS view (whether it has actually caught up to the
    // Add(d3) commit — the "everyone converges" half of what this
    // scenario replaces) isn't observable through `RingStatus` today: the
    // DTO only carries `ring_group_id` and the always-0 `coord_group_count`
    // (see `DeviceRingState::coord_group_count`'s doc). Live membership
    // convergence for a bystander sibling is pinned at the moat-core
    // in-process level instead
    // (`pairing_simulation::three_device_pairing_converges_and_third_device_gets_history`),
    // which can call `MoatSession::get_group_members` directly.

    for (label, client) in [("d1", &d1), ("d2", &d2), ("d3", &d3)] {
        let convs = client
            .list_conversations()
            .await
            .unwrap_or_else(|e| panic!("{label} list_conversations failed: {e}"));
        assert!(
            convs.is_empty(),
            "{label} conversation list should be empty; got {convs:?}"
        );
    }

    vlog!("[check] three-device pairing... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
