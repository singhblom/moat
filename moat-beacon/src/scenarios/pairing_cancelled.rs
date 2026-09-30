//! Cancelled pairing: the new device backs out while showing its code.
//!
//! Unlike reject, this had no *implementation* before pairing-ui-state.md —
//! there was no way to abort a pairing once started, so changing your mind
//! left a session running invisibly until it timed out.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::client::PairingUiState;
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

    vlog!("=== Scenario: pairing-cancelled ===");

    // Only one device here: cancelling while showing a code needs no peer,
    // which is the point — the user backs out before anyone enters it.
    let world = TestWorld::new_with_drawbridge(&[("alice", "alice")], ".postern.test")
        .await
        .expect("world setup");

    let new_device = world.client("alice").clone();
    new_device
        .login("alice.postern.test", "any-password")
        .await
        .expect("new device login");
    world
        .wait_for_drawbridge_connections(1, Duration::from_secs(5))
        .await;

    // ── Show a code, then back out before anyone enters it ────────────────────
    vlog!("[pair] new device requests a pairing code...");
    let pair_new = new_device.pair_new().await.expect("pair_new");

    let initial_state = new_device.pair_status().await.expect("pair_status");
    match &initial_state {
        PairingUiState::ShowingCode { code, drawbridge_url, uri } => {
            assert_eq!(
                code, &pair_new.code,
                "the code in /pair/status must be the one /pair/new handed out"
            );
            assert_eq!(
                drawbridge_url, &pair_new.drawbridge_url,
                "the Drawbridge in /pair/status must be the one /pair/new handed out"
            );
            assert!(
                uri.starts_with("moat-pair:"),
                "the QR form must carry the moat-pair: scheme; got {uri}"
            );
            assert!(
                uri.contains("drawbridge="),
                "the QR form must name the Drawbridge; got {uri}"
            );
        }
        other => panic!("expected showing_code after pair_new, got {other:?}"),
    }

    vlog!("[pair] new device CANCELS while showing the code...");
    new_device.pair_cancel().await.expect("pair_cancel");

    // ── Invariants ────────────────────────────────────────────────────────────
    let reason = crate::scenarios::wait_for_pair_failed(&new_device, TIMEOUT).await;
    assert!(
        !reason.is_empty(),
        "a cancelled pairing must retain a non-empty reason"
    );
    vlog!("[check] cancelled with: {reason}");

    let status = new_device.ring_status().await.expect("ring_status");
    assert!(
        status.ring_group_id.is_none(),
        "cancelling before any Enroll must not create a ring; got {:?}",
        status.ring_group_id
    );

    // A terminal outcome is final.
    assert!(
        new_device.pair_cancel().await.is_err(),
        "cancelling an already-terminal session must be rejected, not silently re-applied"
    );
    let after = new_device.pair_status().await.expect("pair_status");
    match after {
        PairingUiState::Failed { reason: r } => assert_eq!(
            r, reason,
            "a rejected second cancel must leave the original reason intact"
        ),
        other => panic!("expected the session to stay failed, got {other:?}"),
    }

    vlog!("[check] pairing cancelled, no ring, terminal state is final... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
