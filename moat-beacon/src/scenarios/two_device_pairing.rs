//! Two-device live QR/text pairing scenario.
//!
//! Alice's second device ("new device") requests a pairing code via
//! `POST /pair/new`; Alice's first device ("existing device") enters it via
//! `POST /pair/confirm`. Both devices then poll `GET /pair/status` until
//! pairing completes — bounded, so a stuck pairing fails the test instead
//! of hanging it.
//!
//! Sets up one user with two `moat-cli` processes under the same
//! credentials, since pairing presupposes a logged-in new device.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use crate::scenarios::Action;
use crate::world::TestWorld;

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

/// Bounded wait budget for the pairing convergence loop. A stuck pairing
/// must fail the test, not hang the suite; this should converge in a
/// handful of poll cycles.
const PAIR_STATUS_TIMEOUT: Duration = Duration::from_secs(20);
const PAIR_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(200);

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: two-device-pairing ===");

    // ── Prologue ──────────────────────────────────────────────────────────────
    //
    // Live pairing rendezvous (`pair_offer`/`pair_join`) needs a real
    // Drawbridge relay — without a label here, `TestWorld` doesn't spawn
    // one and moat-cli falls back to the hardcoded default relay
    // (`DEFAULT_DRAWBRIDGE_URL`), which is a real deployed instance, not a
    // test double.
    vlog!("[setup] starting TestWorld with one account (alice) + drawbridge...");
    let mut world = TestWorld::new_with_drawbridge(&[("alice", "alice")], ".postern.test")
        .await
        .expect("world setup");

    let existing = world.client("alice").clone();

    vlog!("[setup] spawning the new device...");
    let new_device = world
        .spawn_nth_device("alice-d2", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn new device");

    existing
        .login("alice.postern.test", "any-password")
        .await
        .expect("existing device login");
    vlog!("[setup] existing device logged in");

    new_device
        .login("alice.postern.test", "any-password")
        .await
        .expect("new device login");
    vlog!("[setup] new device logged in");

    // Login triggers the main-WS Drawbridge connect in the background; wait
    // for both devices to actually be attached before racing pair_offer /
    // pair_join against it.
    world
        .wait_for_drawbridge_connections(2, Duration::from_secs(5))
        .await;

    // ── Pairing ───────────────────────────────────────────────────────────────
    //
    // The new device generates the code; the existing device enters it and
    // approves. No host auto-approves the resulting `Enroll` anymore — see
    // `crate::scenarios::wait_for_awaiting_approval_and_approve`.
    vlog!("[pair] new device requests a pairing code...");
    let pair_new = new_device.pair_new().await.expect("new device pair_new");
    vlog!("[pair] code = {}", pair_new.code);

    vlog!("[pair] existing device enters the code...");
    existing
        .pair_confirm(&pair_new.code)
        .await
        .expect("existing device pair_confirm");

    vlog!("[pair] existing device approves...");
    crate::scenarios::wait_for_awaiting_approval_and_approve(&existing, PAIR_STATUS_TIMEOUT).await;

    // ── Bounded convergence wait ─────────────────────────────────────────────
    //
    // Assert on the actual response with an explicit deadline, so a stuck
    // pairing fails fast and legibly instead of hanging the suite.
    let deadline = Instant::now() + PAIR_STATUS_TIMEOUT;
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
            Instant::now() < deadline,
            "pairing did not complete within {PAIR_STATUS_TIMEOUT:?} \
             (existing.done={}, new_device.done={}); this must fail the \
             test, not hang it",
            existing_status.is_done(),
            new_status.is_done(),
        );
        tokio::time::sleep(PAIR_STATUS_POLL_INTERVAL).await;
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let s_existing = existing.ring_status().await.expect("existing ring_status");
    let s_new = new_device.ring_status().await.expect("new_device ring_status");

    assert!(
        s_existing.ring_group_id.is_some(),
        "existing device should have a ring group"
    );
    assert!(
        s_new.ring_group_id.is_some(),
        "new device should have a ring group"
    );
    assert_eq!(
        s_existing.ring_group_id, s_new.ring_group_id,
        "both devices must land in the same ring"
    );

    // Ring group must not appear in the conversation list (unchanged
    // invariant from `two_device_bootstrap`).
    let convs_existing = existing
        .list_conversations()
        .await
        .expect("existing list_conversations");
    let convs_new = new_device
        .list_conversations()
        .await
        .expect("new_device list_conversations");
    assert!(
        convs_existing.is_empty(),
        "existing device conversation list should be empty; got {convs_existing:?}"
    );
    assert!(
        convs_new.is_empty(),
        "new device conversation list should be empty; got {convs_new:?}"
    );

    vlog!("[check] two-device pairing... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
