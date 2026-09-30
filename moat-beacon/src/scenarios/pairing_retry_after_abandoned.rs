//! An abandoned pairing must not poison the next attempt.
//!
//! The user reaches the approval prompt, walks away without deciding, and
//! later starts over with a fresh code. Both devices must pair normally on
//! the second attempt.
//!
//! **Reshaped from pairing-ui-state.md §E's "approve-timeout" cell**, which
//! assumed an unapproved pairing times out into `Failed`. No such timeout
//! exists — the session just rests in `awaiting_approval`, and the only
//! bound is the relay's 5-minute TTL, neither client-side nor short enough
//! for a scenario. This keeps the half that is real: *the next attempt
//! still succeeds*.
//!
//! That is the regression test for the defect this family exposed — an
//! untokened `pair_closed` from a superseded session cancelling its
//! successor. Restarting over an abandoned pairing is the path that broke.

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
const POLL_INTERVAL: Duration = Duration::from_millis(200);

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: pairing-retry-after-abandoned ===");

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

    // ── Attempt 1: reach the prompt, then abandon it undecided ────────────────
    vlog!("[pair] attempt 1: requesting a code...");
    let first = new_device.pair_new().await.expect("first pair_new");
    existing
        .pair_confirm(&first.code, &first.drawbridge_url)
        .await
        .expect("first pair_confirm");

    vlog!("[pair] attempt 1: reached the approval prompt — walking away");
    crate::scenarios::wait_for_awaiting_approval(&existing, TIMEOUT).await;

    // Deliberately no approve, no reject, no cancel: the user just stops.
    // The session stays resting in `awaiting_approval`.
    assert!(
        matches!(
            existing.pair_status().await.expect("pair_status"),
            PairingUiState::AwaitingApproval { .. }
        ),
        "an undecided pairing must rest in awaiting_approval, not resolve itself"
    );

    // ── Attempt 2: fresh code, all the way through ────────────────────────────
    vlog!("[pair] attempt 2: requesting a fresh code (supersedes attempt 1)...");
    let second = new_device.pair_new().await.expect("second pair_new");
    assert_ne!(
        first.code, second.code,
        "each attempt must mint a fresh token+secret, not reuse the abandoned one"
    );

    existing
        .pair_confirm(&second.code, &second.drawbridge_url)
        .await
        .expect("second pair_confirm");
    vlog!("[pair] attempt 2: approving...");
    crate::scenarios::wait_for_awaiting_approval_and_approve(&existing, TIMEOUT).await;

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let e = existing.pair_status().await.expect("existing pair_status");
        let n = new_device.pair_status().await.expect("new_device pair_status");
        vlog!("[pair] existing={:?} new_device={:?}", e, n);
        if e.is_done() && n.is_done() {
            break;
        }
        assert!(
            !e.is_failed() && !n.is_failed(),
            "the retried pairing must not inherit the abandoned attempt's teardown \
             (existing={e:?}, new_device={n:?}) — this is the regression the \
             untokened pair_closed caused",
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the retried pairing did not complete within {TIMEOUT:?} \
             (existing={e:?}, new_device={n:?}); this must fail the test, not hang it",
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let s_existing = existing.ring_status().await.expect("existing ring_status");
    let s_new = new_device.ring_status().await.expect("new_device ring_status");
    assert!(
        s_existing.ring_group_id.is_some(),
        "the retried pairing must have created a ring"
    );
    assert_eq!(
        s_existing.ring_group_id, s_new.ring_group_id,
        "both devices must land in the same ring after the retry"
    );
    assert_eq!(
        s_existing.ring_member_count, 2,
        "the abandoned attempt must not have left a phantom member behind"
    );

    vlog!("[check] abandoned pairing did not poison the retry... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
