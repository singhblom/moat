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
//!
//! What makes the offer findable is the advertisement: D1 learns from
//! D2's summary that D2 holds nothing, and that is what it offers to fix.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::scenarios::three_device_pairing::pair_devices;
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

/// All-Rust cell.
pub async fn run(verbose: bool) {
    run_with(ParticipantKind::RustCli, ParticipantKind::RustCli, "rr", verbose).await
}

/// The scenario body, parameterised by which runtime each device uses.
/// `offerer_kind` is D1 — the device that holds the history, is prompted,
/// and offers — so that is the axis worth varying.
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

    // ── D1 is prompted, from D2's own advertisement ──────────────────────────
    //
    // This is what makes the offer findable rather than guessed: without
    // the advertisement, D1 has no way to know which sibling is short.
    // `/sync/offerable` is the prompt condition itself — the app raises a
    // screen on it, and the headless server reports it — so asserting on
    // it is asserting that the user really would be asked.
    let deadline = std::time::Instant::now() + TIMEOUT;
    let target = loop {
        let _ = d2.ring_tick().await;
        let _ = d1.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        let offerable = d1.sync_offerable().await.unwrap_or_default();
        vlog!("[prompt] d1 would offer to: {offerable:?}");
        if let Some(sibling) = offerable.first() {
            // The prompt names the device, so both runtimes have to
            // supply the name here — not merely the id that happens to be
            // enough for this test to drive the offer.
            assert!(
                sibling.device_name.as_deref().is_some_and(|n| !n.is_empty()),
                "an offerable sibling must carry the name the prompt shows; \
                 got {sibling:?}"
            );
            break sibling.device_id.clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d1 was never prompted to offer within {TIMEOUT:?}; a new device \
             with no history is exactly when the user should be asked"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    };

    // ── Declining silences that advertisement, and only that one ─────────────
    //
    // The prompt must not return on the next app open, or people learn to
    // dismiss reflexively and the mechanism defeats itself.
    d1.sync_dismiss(&target).await.expect("d1 sync_dismiss");
    let after_dismiss = d1.sync_offerable().await.expect("d1 offerable");
    assert!(
        !after_dismiss.iter().any(|s| s.device_id == target),
        "a dismissed advertisement must stop prompting; still offered {after_dismiss:?}"
    );
    // The advertisement is still *held* — dismissal answers the prompt,
    // it does not forget what the sibling said.
    let summaries = d1.sync_summaries().await.expect("d1 summaries");
    assert!(
        summaries.iter().any(|s| s.device_id == target),
        "dismissal must silence the prompt, not discard the advertisement"
    );

    vlog!("[offer] d1 offers history to {target}");

    // ── D1's user approves; D2 joins without being asked ─────────────────────
    //
    // Offering works whether or not the prompt was dismissed: dismissal
    // answers the question, and the user can still change their mind from
    // the Devices screen.
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

    vlog!("[check] sync offer history ({cell})... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
