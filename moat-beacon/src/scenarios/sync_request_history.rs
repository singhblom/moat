//! User-initiated history sync between two devices already in the ring.
//!
//! The gap this closes: conversation fan-out carries *membership*, not
//! history. A sibling that was offline while a conversation was created
//! and used is later added to it by whichever device is online — it gets
//! a `UserConvWelcome`, joins the MLS group, and sees an empty
//! conversation. Its pairing sync finished long ago, and the channel it
//! ran on cannot be reopened: the pairing secret is ephemeral by design.
//!
//! So the user asks. D2 publishes a `RingMsg::SyncRequest` on the device
//! ring; D1's user approves; the transfer runs over an ordinary
//! ring-encrypted `SyncSession`. The scenario asserts both halves — that
//! the history really is missing beforehand (otherwise the test would
//! pass for the wrong reason, on history that arrived some other way),
//! and that it is complete afterwards.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::client::MoatCliClient;
use crate::scenarios::three_device_pairing::pair_devices;
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

/// All-Rust cell.
pub async fn run(verbose: bool) {
    run_with(ParticipantKind::RustCli, ParticipantKind::RustCli, "rr", verbose).await
}

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

/// Bounded wait for `client` to see `group_id` at all — membership, not
/// history. Drives both tick paths, since a conversation that arrives via
/// `UserConvWelcome` is only discovered by the ring tick's own-PDS stealth
/// scan.
async fn wait_for_membership(
    client: &MoatCliClient,
    other: &MoatCliClient,
    group_id: &str,
    label: &str,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = other.ring_tick().await;
        let _ = client.ring_tick().await;
        let _ = client.poll().await;
        let has_it = client
            .list_conversations()
            .await
            .unwrap_or_default()
            .iter()
            .any(|c| c.id == group_id);
        vlog!("[fanout] {label} has the conversation: {has_it}");
        if has_it {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{label} was never fanned into the conversation within {TIMEOUT:?}; \
             this must fail the test, not hang it"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The scenario body, parameterised by which runtime each of Alice's two
/// devices uses.
///
/// Unlike the pairing cells — which are full copies of one another — the
/// runtime mix here is a parameter, because the two axes that matter
/// (`donor` serves the history, `requester` asks for it) are the *only*
/// difference between the cells, and the assertions around them are
/// long enough that three copies would drift.
pub async fn run_with(
    donor_kind: ParticipantKind,
    requester_kind: ParticipantKind,
    cell: &str,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: sync-request-history ({cell}) ===");

    // Live pairing and the sync rendezvous both need a real Drawbridge
    // relay — see the note in `two_device_pairing.rs`'s prologue.
    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        // Bob is only ever a cross-user counterparty here, so he stays on
        // the Rust CLI regardless of the cell.
        &[donor_kind, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    let d2 = world
        .spawn_nth_device("alice-d2", requester_kind)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;

    // ── D2 sleeps through a whole conversation ───────────────────────────────
    //
    // Killing it (rather than just not polling) is what makes this the real
    // case: D2 is absent for the conversation's creation *and* every message
    // in it, so nothing reaches it through the ordinary PDS path either.
    tokio::time::sleep(Duration::from_millis(100)).await;
    world.kill_participant("alice-d2").expect("kill d2");
    vlog!("[offline] d2 down");

    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");
    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("d1 start conversation with bob");

    let history = ["first", "second", "third", "fourth"];
    for text in &history {
        d1.send_message(&group_id, text).await.expect("d1 send");
        let _ = bob.poll().await;
    }
    let d1_before = d1.get_messages(&group_id).await.expect("d1 messages");
    assert_eq!(
        d1_before.len(),
        history.len(),
        "d1 should hold the whole conversation before d2 returns"
    );

    // ── D2 returns: it gets membership, and nothing else ─────────────────────
    vlog!("[online] d2 back up");
    world.restart_participant("alice-d2").await.expect("restart d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 re-login");

    wait_for_membership(&d2, &d1, &group_id, "d2", verbose).await;

    let d2_after_fanout = d2.get_messages(&group_id).await.unwrap_or_default();
    assert!(
        d2_after_fanout.is_empty(),
        "fan-out carries membership only — d2 must start with no history, \
         or this scenario proves nothing about the sync request; got {} messages",
        d2_after_fanout.len()
    );

    // ── The gesture ──────────────────────────────────────────────────────────
    vlog!("[sync] d2 asks its siblings for history");
    d2.sync_request().await.expect("d2 sync_request");

    // D1's user sees the prompt. The ring message travels as an ordinary
    // event, so drive both devices' polling to deliver it.
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d1.poll().await;
        let state = d1.sync_request_status().await.expect("d1 sync status");
        vlog!("[sync] d1 sees: {state:?}");
        if state.is_awaiting_approval() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d1 never prompted for d2's sync request within {TIMEOUT:?} \
             (last state: {state:?}); this must fail the test, not hang it"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    vlog!("[sync] d1 approves");
    d1.sync_accept().await.expect("d1 sync_accept");

    // ── The history arrives ──────────────────────────────────────────────────
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d2.poll().await;
        let msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        vlog!("[sync] d2 has {}/{} messages", msgs.len(), history.len());
        if msgs.len() >= history.len() {
            let contents: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
            for want in &history {
                assert!(
                    contents.contains(want),
                    "d2's history is missing {want:?}; got {contents:?}"
                );
            }
            assert_eq!(
                msgs.len(),
                history.len(),
                "d2 must hold each message exactly once; got {contents:?}"
            );
            break;
        }
        let state = d2.sync_request_status().await.expect("d2 sync status");
        assert!(
            !state.is_failed(),
            "d2's sync request failed before the history arrived: {state:?}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "d2 never received the history within {TIMEOUT:?} \
             (has {} of {}); this must fail the test, not hang it",
            msgs.len(),
            history.len()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    vlog!("[check] sync request history ({cell})... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
