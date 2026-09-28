//! The offer direction: history pushed rather than pulled.
//!
//! Requested sync asks the user to walk to the device that has the
//! history and approve there. That is the wrong way round whenever the
//! device they are already holding is the one with the history — which is
//! exactly the case right after adding a new phone.
//!
//! So the device with the history offers. The rule that keeps this from
//! becoming an election is **exactly one human approval per session, on
//! the side that can judge**: the offerer's user approves, and the
//! recipient joins without a prompt of its own. A second prompt would be
//! asking someone to approve receiving their own messages from a device
//! that can already read them.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::scenarios::sync_request_history::await_sync_completion;
use crate::scenarios::three_device_pairing::pair_devices;
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

pub(crate) fn run_dr_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::DartServer, ParticipantKind::RustCli, "dr", verbose))
}

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

/// All-Rust cell.
pub async fn run(verbose: bool) {
    run_with(ParticipantKind::RustCli, ParticipantKind::RustCli, "rr", verbose).await
}

/// The scenario body, parameterised by which runtime each device uses.
/// `offerer_kind` is D1, the device that holds the history and offers.
pub async fn run_with(
    offerer_kind: ParticipantKind,
    recipient_kind: ParticipantKind,
    cell: &str,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: sync-offer-history ({cell}) ===");

    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        // Bob is only ever a cross-user counterparty, so he stays Rust.
        &[offerer_kind, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    let d2 = world
        .spawn_nth_device("alice-d2", recipient_kind)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;

    // ── D2 sleeps through a conversation ─────────────────────────────────────
    tokio::time::sleep(Duration::from_millis(100)).await;
    world.kill_participant("alice-d2").expect("kill d2");
    vlog!("[offline] d2 down");

    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");
    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("d1 start conversation with bob");

    let history = ["first", "second", "third"];
    for text in &history {
        d1.send_message(&group_id, text).await.expect("d1 send");
        let _ = bob.poll().await;
    }

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let msgs = d1.get_messages(&group_id).await.expect("d1 messages");
        if msgs.len() == history.len() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d1's own history never settled within {TIMEOUT:?}; \
             this must fail the test, not hang it"
        );
        let _ = d1.poll().await;
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    vlog!("[online] d2 back up");
    world.restart_participant("alice-d2").await.expect("restart d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 re-login");

    // ── The user picks D2 from D1's device list ─────────────────────────────
    //
    // Pick the target as the Devices screen does, from D1's ring members.
    let deadline = std::time::Instant::now() + TIMEOUT;
    let target = loop {
        let _ = d2.ring_tick().await;
        let _ = d1.ring_tick().await;
        let status = d1.ring_status().await.unwrap_or_default();
        if let Some(device) = status.devices.iter().find(|d| !d.is_self) {
            assert!(
                !device.device_name.is_empty(),
                "a linked device must carry the name the Devices screen shows; \
                 got {device:?}"
            );
            break device.device_id.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d1 never listed d2 as a linked device within {TIMEOUT:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    };

    vlog!("[offer] d1 offers history to {target}");

    // ── D1's user approves; D2 joins without being asked ─────────────────────
    d1.sync_offer(&target).await.expect("d1 sync_offer");

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d2.poll().await;
        let _ = d1.poll().await;
        let msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        if msgs.len() >= history.len() {
            let contents: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
            for want in &history {
                assert!(
                    contents.contains(want),
                    "d2 is missing {want:?} after the offer; got {contents:?}"
                );
            }
            break;
        }
        // D2 must never have been prompted: the approval already happened
        // on D1, which is the side that could judge.
        let state = d2.sync_request_status().await.expect("d2 sync status");
        assert!(
            !state.is_awaiting_approval(),
            "d2 must join an offer without prompting — the offerer already \
             approved, and a second prompt asks the user to approve \
             receiving their own messages; got {state:?}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "d2 never received the offered history within {TIMEOUT:?} \
             (has {} of {}); this must fail the test, not hang it",
            msgs.len(),
            history.len()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // The receiver closes the channel once it holds everything; the offerer
    // must read that as a confirmed delivery, not a dropped connection.
    let offerer = await_sync_completion(&d1, "d1").await;
    assert!(
        offerer.sent_messages > 0,
        "the offerer must report what it delivered; got {offerer:?}"
    );

    vlog!("[check] sync offer history ({cell})... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
