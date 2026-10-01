//! Rejected pairing: the existing device declines the new device's `Enroll`.
//!
//! Never executed by any test before pairing-ui-state.md — the `--http`
//! auto-approve fork accepted every `Enroll` on arrival, so no scenario
//! could reach `awaiting_approval`, let alone leave it by rejecting.
//!
//! The invariant: a rejected pairing leaves no ring on either side.

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

const TIMEOUT: Duration = Duration::from_secs(20);

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: pairing-rejected ===");

    // Live pairing rendezvous needs a real Drawbridge relay — see the note
    // in `two_device_pairing.rs`'s prologue.
    let mut world = TestWorld::new_with_drawbridge(&[("alice", "alice")], ".postern.test")
        .await
        .expect("world setup");

    let existing = world.client("alice").clone();
    let new_device = world
        .spawn_nth_device("alice-d2", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn new device");

    existing
        .login("alice.postern.test", "any-password")
        .await
        .expect("existing device login");
    new_device
        .login("alice.postern.test", "any-password")
        .await
        .expect("new device login");
    world
        .wait_for_drawbridge_connections(2, Duration::from_secs(5))
        .await;

    // ── Pair up to the approval prompt, then decline ──────────────────────────
    vlog!("[pair] new device requests a pairing code...");
    let pair_new = new_device.pair_new().await.expect("new device pair_new");
    existing
        .pair_confirm(&pair_new.code, &pair_new.drawbridge_url)
        .await
        .expect("existing device pair_confirm");

    vlog!("[pair] waiting for the approval prompt...");
    crate::scenarios::wait_for_awaiting_approval(&existing, TIMEOUT).await;

    vlog!("[pair] existing device REJECTS...");
    existing.pair_reject().await.expect("pair_reject");

    // ── Invariants ────────────────────────────────────────────────────────────
    let existing_reason = crate::scenarios::wait_for_pair_failed(&existing, TIMEOUT).await;
    assert!(
        !existing_reason.is_empty(),
        "the rejecting device must retain a non-empty reason, not just report 'not done'"
    );
    vlog!("[check] existing device failed with: {existing_reason}");

    // The new device learns via the relay tearing down the pair channel.
    let new_reason = crate::scenarios::wait_for_pair_failed(&new_device, TIMEOUT).await;
    assert!(
        !new_reason.is_empty(),
        "the rejected device must also land in a terminal failed state with a reason"
    );
    vlog!("[check] new device failed with: {new_reason}");

    // The headline invariant: a declined newcomer holds no ring membership,
    // and the approver's own ring state is untouched (here: still none, since
    // this would have been the first pairing and the ring is created *by*
    // approve()).
    let s_existing = existing.ring_status().await.expect("existing ring_status");
    let s_new = new_device.ring_status().await.expect("new_device ring_status");
    assert!(
        s_existing.ring_group_id.is_none(),
        "rejecting the first pairing must not create a ring; got {:?}",
        s_existing.ring_group_id
    );
    assert!(
        s_new.ring_group_id.is_none(),
        "a rejected device must not hold ring membership; got {:?}",
        s_new.ring_group_id
    );

    vlog!("[check] pairing rejected, no ring on either side... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
