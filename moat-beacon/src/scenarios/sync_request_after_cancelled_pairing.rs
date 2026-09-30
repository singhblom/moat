//! A sibling's sync request is ignored while this device is pairing, and
//! prompts again once that pairing has been cancelled.
//!
//! D1 starts adding a third device and the user backs out. The cancelled
//! pairing stays readable as `Failed`, but it must stop counting as "in
//! flight" the moment it ends.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::client::MoatCliClient;
use crate::scenarios::sync_request_history::await_sync_completion;
use crate::scenarios::three_device_pairing::pair_devices;
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::RustCli, "r", verbose))
}

pub(crate) fn run_d_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::DartServer, "d", verbose))
}

const TIMEOUT: Duration = Duration::from_secs(30);
/// How long D1 must stay silent about a request that arrived mid-pairing.
/// Well past the time the prompt takes to appear once D1 is free.
const IGNORE_WINDOW: Duration = Duration::from_secs(6);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

async fn wait_for_prompt(d1: &MoatCliClient, verbose: bool) {
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d1.poll().await;
        let state = d1.sync_request_status().await.expect("d1 sync status");
        if verbose {
            eprintln!("[sync] d1 sees: {state:?}");
        }
        if state.is_awaiting_approval() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d1 never prompted for d2's sync request within {TIMEOUT:?} after \
             its pairing was cancelled (last state: {state:?})"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Both of Alice's devices run `kind`: the rule under test is the donor's.
pub async fn run_with(kind: ParticipantKind, cell: &str, verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: sync-request-after-cancelled-pairing ({cell}) ===");

    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice")],
        &[kind.clone()],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let d1 = world.client("alice").clone();
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");

    let d2 = world.spawn_nth_device("alice-d2", kind).await.expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");
    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;

    // D3 only exists to hand D1 a valid code to start entering.
    let d3 = world
        .spawn_nth_device("alice-d3", ParticipantKind::RustCli)
        .await
        .expect("spawn d3");
    d3.login("alice.postern.test", "any-password").await.expect("d3 login");
    let code = d3.pair_new().await.expect("d3 pair_new").code;

    // ── A request that arrives mid-pairing is ignored ────────────────────────
    vlog!("[pair] d1 starts adding d3...");
    d1.pair_confirm(&code).await.expect("d1 pair_confirm");

    vlog!("[sync] d2 asks while d1 is pairing");
    d2.sync_request().await.expect("d2 first sync_request");
    let deadline = std::time::Instant::now() + IGNORE_WINDOW;
    while std::time::Instant::now() < deadline {
        let _ = d1.poll().await;
        let pairing = d1.pair_status().await.expect("d1 pair_status");
        assert!(
            !pairing.is_done() && !pairing.is_failed(),
            "d1's pairing with d3 must still be in flight, or this half \
             proves nothing; got {pairing:?}"
        );
        let state = d1.sync_request_status().await.expect("d1 sync status");
        assert!(
            !state.is_awaiting_approval(),
            "d1 must ignore a sync request while a pairing is in flight; got {state:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // ── Once cancelled, the next request prompts ─────────────────────────────
    vlog!("[pair] d1 cancels");
    d1.pair_cancel().await.expect("d1 pair_cancel");
    crate::scenarios::wait_for_pair_failed(&d1, TIMEOUT).await;

    vlog!("[sync] d2 asks again");
    d2.sync_request().await.expect("d2 second sync_request");
    wait_for_prompt(&d1, verbose).await;

    vlog!("[sync] d1 approves");
    d1.sync_accept().await.expect("d1 sync_accept");
    await_sync_completion(&d2, "d2").await;
    await_sync_completion(&d1, "d1").await;

    vlog!("[check] sync request after cancelled pairing ({cell})... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
