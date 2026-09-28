//! Three-device pairing history-sync scenario.
//!
//! Alice's first device (D1) already has a conversation with Bob, with
//! messages sent before either of Alice's other two devices exist. D2
//! pairs in and must end up with that history; D3 then pairs in
//! (against D1's now-existing ring) and must end up with it too.
//!
//! This is the pairing-based successor to the deleted
//! `two_device_history_sync` / `three_device_history_sync` scenarios, and
//! it is the scenario finding 1 of the Phase 0 review names directly:
//! nothing before this asserted that `PairingCommand::StartSync` actually
//! leads to messages arriving on the new device, only that the command was
//! emitted (`moat-core/tests/pairing_simulation.rs` checks that much at the
//! unit level).
//!
//! The runtime mix is a parameter (see [`run_with`]); the `_dr` and `_rd`
//! cells are thin wrappers over it. `_dr` is the only coverage of
//! `PairingService.dart`'s post-Done history sync as the *receiving* side
//! against a non-empty conversation, `_rd` the only coverage of it as the
//! *serving* side.

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

pub(crate) fn run_dr_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::RustCli, ParticipantKind::DartServer, "dr", verbose))
}

pub(crate) fn run_rd_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::DartServer, ParticipantKind::RustCli, "rd", verbose))
}

/// Bounded wait for `client` to have received at least `expected.len()`
/// messages in `group_id`, polling to drive delivery. A stuck sync must
/// fail the test, not hang it.
async fn wait_for_history(
    client: &crate::client::MoatCliClient,
    group_id: &str,
    expected: &[&str],
    label: &str,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }
    const TIMEOUT: Duration = Duration::from_secs(20);
    const POLL_INTERVAL: Duration = Duration::from_millis(300);
    let deadline = std::time::Instant::now() + TIMEOUT;

    loop {
        let _ = client.poll().await;
        let msgs = client.get_messages(group_id).await.unwrap_or_default();
        vlog!("[history] {label} has {}/{} messages", msgs.len(), expected.len());
        if msgs.len() >= expected.len() {
            let contents: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
            for want in expected {
                assert!(
                    contents.contains(want),
                    "{label} history is missing message {want:?}; got {contents:?}"
                );
            }
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{label} did not receive full history within {TIMEOUT:?} \
             ({}/{} messages); this must fail the test, not hang it",
            msgs.len(),
            expected.len(),
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Bounded wait for `client`'s transfer to finish. History landing is not
/// enough: a transfer that never exchanges `Fin` holds the channel until
/// the relay's TTL, minutes after the last message arrived.
async fn wait_for_transfer_end(client: &crate::client::MoatCliClient, label: &str) {
    const TIMEOUT: Duration = Duration::from_secs(20);
    let deadline = std::time::Instant::now() + TIMEOUT;
    while client.sync_status().await.unwrap_or(true) {
        assert!(
            std::time::Instant::now() < deadline,
            "{label}'s history transfer did not finish within {TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

pub async fn run(verbose: bool) {
    run_with(ParticipantKind::RustCli, ParticipantKind::RustCli, "rr", verbose).await
}

/// The scenario body. `existing` is D1, which holds the history and serves
/// it; `new` is D2 and D3, which pair in and receive it.
pub async fn run_with(
    existing: ParticipantKind,
    new: ParticipantKind,
    cell: &str,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: three-device-pairing-history-sync ({cell}) ===");

    // Live pairing rendezvous needs a real Drawbridge relay — see the note
    // in `two_device_pairing.rs`'s prologue. Alice and Bob get separate
    // relays, matching real-world per-user relay discovery.
    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        &[existing, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();

    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    // ── D1 and Bob have a conversation with history before any pairing ────────
    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");

    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    for _ in 0..5 {
        let s = bob.poll().await.expect("bob poll");
        if s.new_conversations > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let test_messages = ["hello from d1", "second message", "third message"];
    for msg in &test_messages {
        d1.send_message(&group_id, msg).await.expect("d1 send_message");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.poll().await.expect("bob poll");

    let d1_before = d1.get_messages(&group_id).await.expect("d1 get_messages");
    assert_eq!(d1_before.len(), test_messages.len(), "d1 should hold all pre-pairing history");

    // ── D2 pairs in and must sync that history ─────────────────────────────────
    let d2 = world
        .spawn_nth_device("alice-d2", new.clone())
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;
    wait_for_history(&d2, &group_id, &test_messages, "d2", verbose).await;
    wait_for_transfer_end(&d2, "d2").await;
    wait_for_transfer_end(&d1, "d1").await;

    // ── D3 pairs into the now-existing ring and must also sync that history ────
    let d3 = world
        .spawn_nth_device("alice-d3", new)
        .await
        .expect("spawn d3");
    d3.login("alice.postern.test", "any-password").await.expect("d3 login");

    vlog!("[pair] d1 <- d3...");
    pair_devices(&d1, &d3, verbose).await;
    wait_for_history(&d3, &group_id, &test_messages, "d3", verbose).await;
    wait_for_transfer_end(&d3, "d3").await;
    wait_for_transfer_end(&d1, "d1").await;

    vlog!("[check] three-device pairing history sync ({cell})... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
