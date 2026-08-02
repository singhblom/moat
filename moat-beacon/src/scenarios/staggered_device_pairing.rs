//! Staggered three-device pairing scenario.
//!
//! D1 pairs D2; D2 then goes offline before D1 pairs D3, so D3's ring Add
//! commit lands while one existing sibling isn't there to see it. D2 later
//! comes back online with no re-pairing gesture and must catch up on its
//! own — the "Offline sibling catch-up" path `qr-pairing.md` §6 describes
//! (an ordinary PDS poll, not a special mechanism) — and still end up in a
//! working three-way ring: a conversation D1 starts afterward with Bob
//! must fan out to both D2 and D3.
//!
//! This is the pairing-based successor to the deleted
//! `three_device_staggered` scenario. Unlike that scenario, there is no
//! online-order permutation to sweep: pairing only ever needs the
//! *approving* device (D1) to be live, so "staggered" here means "a
//! bystander sibling is offline during someone else's pairing," not "which
//! device onboards first."
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

    vlog!("=== Scenario: staggered-device-pairing ===");

    let mut world = TestWorld::new(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup");
    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    let d2 = world
        .spawn_nth_device("alice-d2", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;

    // D2 goes offline before D3 ever exists.
    tokio::time::sleep(Duration::from_millis(100)).await;
    world.kill_participant("alice-d2").expect("kill d2");
    vlog!("[stagger] d2 offline");

    let d3 = world
        .spawn_nth_device("alice-d3", crate::world::ParticipantKind::RustCli)
        .await
        .expect("spawn d3");
    d3.login("alice.postern.test", "any-password").await.expect("d3 login");

    vlog!("[pair] d1 <- d3 (d2 still offline)...");
    pair_devices(&d1, &d3, verbose).await;

    let s1 = d1.ring_status().await.expect("d1 ring_status");
    let s3 = d3.ring_status().await.expect("d3 ring_status");
    assert!(s1.ring_group_id.is_some(), "d1 must have a ring");
    assert_eq!(
        s1.ring_group_id, s3.ring_group_id,
        "d1 and d3 must converge on the ring even though d2 was offline for d3's pairing"
    );

    // D2 comes back with no re-pairing gesture and must catch up on its own.
    vlog!("[stagger] d2 back online");
    world.restart_participant("alice-d2").await.expect("restart d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 re-login");

    // ── Convergence check ────────────────────────────────────────────────────
    //
    // A conversation D1 starts now must fan out to both D2 and D3 — proving
    // d2's return actually reintegrated it into a working three-way ring
    // (able to see, and be seen by, the sibling it missed) rather than a
    // stale two-way view that happens to still report the right
    // `ring_group_id`.
    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");
    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("d1 start conversation with bob");

    const TIMEOUT: Duration = Duration::from_secs(20);
    const POLL_INTERVAL: Duration = Duration::from_millis(300);
    let deadline = std::time::Instant::now() + TIMEOUT;
    let (mut d2_has_it, mut d3_has_it) = (false, false);
    loop {
        // `ring_tick` (not `poll`) is what drives `PollForNewDevices` — the
        // fan-out of a new user conversation to confirmed ring siblings.
        let _ = d1.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        let _ = d3.poll().await;

        if !d2_has_it {
            d2_has_it = d2
                .list_conversations()
                .await
                .unwrap_or_default()
                .iter()
                .any(|c| c.id == group_id);
        }
        if !d3_has_it {
            d3_has_it = d3
                .list_conversations()
                .await
                .unwrap_or_default()
                .iter()
                .any(|c| c.id == group_id);
        }
        vlog!("[stagger] d2_has_it={d2_has_it} d3_has_it={d3_has_it}");
        if d2_has_it && d3_has_it {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d1's post-catch-up conversation did not fan out to both siblings \
             within {TIMEOUT:?} (d2_has_it={d2_has_it}, d3_has_it={d3_has_it}); \
             this must fail the test, not hang it"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    vlog!("[check] staggered device pairing... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
