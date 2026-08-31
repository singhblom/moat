//! Three-device live QR/text pairing scenario.
//!
//! D1 pairs D2 first (no ring exists yet); D1 then pairs D3 into the
//! now-existing ring. Onboarding goes exclusively through `POST /pair/new`,
//! `POST /pair/confirm`, and `GET /pair/status` — the pairing-based
//! successor to the deleted `three_device_bootstrap` scenario's coord-group
//! handshake.
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

/// Drive one `/pair/new` (new device) + `/pair/confirm` (existing device) +
/// `/pair/approve` (existing device, once `awaiting_approval`) exchange to
/// completion. Bounded so a stuck pairing fails the test instead of hanging
/// it — see `crate::scenarios::two_device_pairing` for the two-device
/// version this mirrors. Reused by every scenario that pairs a second or
/// third device into D1's ring: `three_device_pairing_history_sync[_dr]`,
/// `staggered_device_pairing`, `lost_device_pairing`.
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

    wait_for_drawbridge_authenticated(existing, TIMEOUT).await;
    wait_for_drawbridge_authenticated(new_device, TIMEOUT).await;

    let pair_new = new_device.pair_new().await.expect("new device pair_new");
    vlog!("[pair] code = {}", pair_new.code);
    existing
        .pair_confirm(&pair_new.code)
        .await
        .expect("existing device pair_confirm");

    vlog!("[pair] existing device approves...");
    crate::scenarios::wait_for_awaiting_approval_and_approve(existing, TIMEOUT).await;

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let existing_status = existing.pair_status().await.expect("existing pair_status");
        let new_status = new_device.pair_status().await.expect("new_device pair_status");
        vlog!(
            "[pair] existing.done={} new_device.done={}",
            existing_status.is_done(), new_status.is_done()
        );
        if existing_status.is_done() && new_status.is_done() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pairing did not complete within {TIMEOUT:?} \
             (existing.done={}, new_device.done={}); this must fail the \
             test, not hang it",
            existing_status.is_done(),
            new_status.is_done(),
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// A `pair_join` sent before the relay has authenticated the connection is
/// rejected as "token not found", which is connection-fatal and forces a
/// reconnect that can derail whichever round is in flight. Needed per-round,
/// not just at setup: round 2 runs on a long-connected client.
async fn wait_for_drawbridge_authenticated(client: &MoatCliClient, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = client.status().await.expect("status");
        if status.drawbridge_connected {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "client never reported drawbridge_connected within {timeout:?}; \
             this must fail the test, not hang it",
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: three-device-pairing ===");

    // Live pairing rendezvous needs a real Drawbridge relay — see the note
    // in `two_device_pairing.rs`'s prologue.
    let mut world = TestWorld::new_with_drawbridge(&[("alice", "alice")], ".postern.test")
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
    // d1 and d3 both see 3 members synchronously (d1 performed the add;
    // d3 joined via the Welcome), but d2 — the bystander, uninvolved in
    // the d1<->d3 pairing — only converges once it fetches and processes
    // the Add(d3) commit from the PDS on its own next poll (qr-pairing.md
    // §6: "a sibling asleep during a pairing processes the ring Add commit
    // from the PDS on its next poll"). Bounded wait so a dropped commit
    // fails the test instead of hanging it.
    assert_eq!(s1.ring_member_count, 3, "d1 must see all three ring members");
    assert_eq!(s3.ring_member_count, 3, "d3 must see all three ring members via d1's Welcome");

    const D2_CONVERGE_TIMEOUT: Duration = Duration::from_secs(20);
    let deadline = std::time::Instant::now() + D2_CONVERGE_TIMEOUT;
    let mut d2_member_count = s2.ring_member_count;
    while d2_member_count != 3 {
        assert!(
            std::time::Instant::now() < deadline,
            "d2 (bystander to d1<->d3's pairing) never converged to 3 ring members \
             within {D2_CONVERGE_TIMEOUT:?} (stuck at {d2_member_count}); the Add(d3) \
             commit was never delivered — this must fail the test, not hang it"
        );
        // `ring_tick` alone isn't enough: it drives the *stealth-lane*
        // scan (same-user SiblingMsg traffic), not the tag-matched event
        // fetch that discovers a plain published event like the ring Add
        // commit. That fetch is `poll`'s job — without calling it
        // explicitly here, convergence depends entirely on d2's own
        // background adaptive poll (30s while Drawbridge-connected),
        // which can outlast this bounded wait on unlucky timing.
        let _ = d2.ring_tick().await;
        let _ = d2.poll().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        d2_member_count = d2.ring_status().await.expect("d2 ring_status").ring_member_count;
    }

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
