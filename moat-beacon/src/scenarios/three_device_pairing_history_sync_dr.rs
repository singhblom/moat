//! Three-device pairing history-sync scenario — new devices run the Dart
//! headless server, existing device (D1) runs the Rust CLI.
//!
//! Same story as [`super::three_device_pairing_history_sync`] (D1 already
//! has conversation history with Bob predating D2/D3; both must sync it in
//! via pairing), but D2 and D3 are Dart participants. This is the only
//! coverage exercising `PairingService.dart`'s post-Done history-sync
//! phase (`_startPairingSyncSession`/`_processPairingSyncOutputs`/
//! `_processPairingSyncFrame`, `paired_sync_builder.dart`) against a
//! *non-empty* conversation — the `two_device_pairing_dd`/`_rd`/`_dr` cells
//! all pair into a brand-new, empty ring, so `SyncOutput::Store` never
//! actually fires there.

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

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: three-device-pairing-history-sync-dr (new devices=Dart, D1=Rust) ===");

    // Live pairing rendezvous needs a real Drawbridge relay — see the note
    // in `two_device_pairing.rs`'s prologue. Alice and Bob get separate
    // relays, matching real-world per-user relay discovery.
    let mut world =
        TestWorld::new_with_drawbridge(&[("alice", "alice"), ("bob", "bob")], ".postern.test")
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

    // ── D2 (Dart) pairs in and must sync that history ──────────────────────────
    let d2 = world
        .spawn_nth_device("alice-d2", ParticipantKind::DartServer)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2 (Dart)...");
    pair_devices(&d1, &d2, verbose).await;
    wait_for_history(&d2, &group_id, &test_messages, "d2", verbose).await;

    // ── D3 (Dart) pairs into the now-existing ring and must also sync it ───────
    let d3 = world
        .spawn_nth_device("alice-d3", ParticipantKind::DartServer)
        .await
        .expect("spawn d3");
    d3.login("alice.postern.test", "any-password").await.expect("d3 login");

    vlog!("[pair] d1 <- d3 (Dart)...");
    pair_devices(&d1, &d3, verbose).await;
    wait_for_history(&d3, &group_id, &test_messages, "d3", verbose).await;

    vlog!("[check] three-device pairing history sync (dr)... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
