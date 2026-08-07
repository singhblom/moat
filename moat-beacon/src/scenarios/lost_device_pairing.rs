//! Lost-device pairing scenario — the regression statement of
//! `qr-pairing.md`'s premise.
//!
//! D1 pairs D2 and the two exchange history with Bob. D1 is then killed
//! **permanently** (never restarted) — modelling a lost phone. D2, the
//! sole survivor, later pairs in D3 *as the existing/approving device*.
//! Everything must still work with D1 gone for good: D2 can onboard a
//! third device on its own authority, D3 lands in the very ring D1
//! originally created, and D3 recovers the conversation history that
//! predates D1's loss (via D2, since D1 never gets the chance to help).
//!
//! This is what `qr-pairing.md` §2 promises explicitly: *"History survives
//! device loss only if a second linked device survives"* — this scenario
//! is the positive half of that claim (the negative half, no surviving
//! device at all, has no recovery to test: it's PDS login with no
//! history, by design).
//!
//! There was no prior implementation of this scenario to delete —
//! `ring-inversion.md` §0c proposed `smoke_three_device_lost_device` for
//! the old coord-group design but it was never built — so this is wholly
//! new red coverage, not a rewrite.
//!
//! **Intentionally red**: `/pair/*` doesn't exist yet and `PairingSession`
//! is unimplemented; expect failure on the first `pair_new` call.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::scenarios::three_device_pairing::pair_devices;
use crate::scenarios::Action;
use crate::world::TestWorld;

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: lost-device-pairing ===");

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

    // ── D1 + Bob history, before D2 even exists ────────────────────────────────
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
    let test_messages = ["hello from d1", "d1's last message before it's lost"];
    for msg in &test_messages {
        d1.send_message(&group_id, msg).await.expect("d1 send_message");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.poll().await.expect("bob poll");

    // ── D1 pairs D2 ─────────────────────────────────────────────────────────────
    let d2 = world
        .spawn_nth_device("alice-d2", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;

    let d1_ring = d1
        .ring_status()
        .await
        .expect("d1 ring_status")
        .ring_group_id
        .expect("d1 must have a ring after pairing d2");

    // Give d2 a bounded chance to sync d1/bob's pre-existing history before
    // d1 is gone for good.
    const HISTORY_TIMEOUT: Duration = Duration::from_secs(20);
    let deadline = std::time::Instant::now() + HISTORY_TIMEOUT;
    loop {
        let _ = d2.poll().await;
        let msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        if msgs.len() >= test_messages.len() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d2 did not sync d1's pre-pairing history within {HISTORY_TIMEOUT:?} \
             ({}/{} messages) before d1 is lost; this must fail the test, not hang it",
            msgs.len(),
            test_messages.len(),
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // ── D1 is lost. Permanently. No `restart_participant` call follows. ────────
    tokio::time::sleep(Duration::from_millis(100)).await;
    world.kill_participant("alice").expect("kill d1 (permanently)");
    vlog!("[lost] d1 is gone for good");

    // ── D2, the sole survivor, pairs in D3 on its own authority ────────────────
    let d3 = world
        .spawn_nth_device("alice-d3", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn d3");
    d3.login("alice.postern.test", "any-password").await.expect("d3 login");

    vlog!("[pair] d2 <- d3 (d1 is permanently gone)...");
    pair_devices(&d2, &d3, verbose).await;

    // ── Invariants ────────────────────────────────────────────────────────────
    let s2 = d2.ring_status().await.expect("d2 ring_status");
    let s3 = d3.ring_status().await.expect("d3 ring_status");
    assert_eq!(
        s2.ring_group_id.as_deref(),
        Some(d1_ring.as_str()),
        "d2 must still be in the ring d1 originally created"
    );
    assert_eq!(
        s2.ring_group_id, s3.ring_group_id,
        "d3 must land in that same ring, approved by d2 alone"
    );

    const D3_HISTORY_TIMEOUT: Duration = Duration::from_secs(20);
    let deadline = std::time::Instant::now() + D3_HISTORY_TIMEOUT;
    loop {
        let _ = d3.poll().await;
        let msgs = d3.get_messages(&group_id).await.unwrap_or_default();
        vlog!("[lost] d3 has {}/{} messages", msgs.len(), test_messages.len());
        if msgs.len() >= test_messages.len() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d3 did not recover d1's history via d2 within {D3_HISTORY_TIMEOUT:?} \
             ({}/{} messages), even though d1 is permanently gone; this must \
             fail the test, not hang it — it is the regression this scenario exists to catch",
            msgs.len(),
            test_messages.len(),
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    vlog!("[check] lost-device pairing... ok — history survives d1's loss via d2");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
