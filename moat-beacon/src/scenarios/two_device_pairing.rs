//! Two-device live QR/text pairing scenario.
//!
//! Alice's second device ("new device") requests a pairing code via
//! `POST /pair/new`; Alice's first device ("existing device") enters it via
//! `POST /pair/confirm`. Both devices then poll `GET /pair/status` until
//! pairing completes — bounded, so a stuck pairing fails the test instead
//! of hanging it.
//!
//! **Intentionally red.** `/pair/new`, `/pair/confirm`, and `/pair/status`
//! don't exist on `moat-cli`'s http server yet, and `moat-core`'s
//! `PairingSession` driver is unimplemented. This scenario documents the
//! target shape of the two-device pairing story and is expected to fail on
//! the very first `pair_new` call until those land.
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
    vlog!("[setup] starting TestWorld with one account (alice)...");
    let mut world = TestWorld::new(&["alice"], ".postern.test")
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

    // ── Pairing ───────────────────────────────────────────────────────────────
    //
    // The new device generates the code; the existing device enters it.
    // Approval is auto-accepted in `--http` mode — interactive UIs gate
    // this on a real user tap.
    vlog!("[pair] new device requests a pairing code...");
    let pair_new = new_device.pair_new().await.expect("new device pair_new");
    vlog!("[pair] code = {}", pair_new.code);

    vlog!("[pair] existing device enters the code...");
    existing
        .pair_confirm(&pair_new.code)
        .await
        .expect("existing device pair_confirm");

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
            existing_status.done, new_status.done
        );

        if existing_status.done && new_status.done {
            break;
        }

        assert!(
            Instant::now() < deadline,
            "pairing did not complete within {PAIR_STATUS_TIMEOUT:?} \
             (existing.done={}, new_device.done={}); this must fail the \
             test, not hang it",
            existing_status.done,
            new_status.done,
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
