//! One sender sends more messages between membership changes than the
//! recipient's candidate-tag window covers. Every message must arrive by poll,
//! after the recipient restarts, and (Rust recipient) by push alone.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use crate::client::MoatCliClient;
use crate::scenarios::post_fan_out_delivery::wait_for_membership;
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

/// Two and a half windows of `TAG_GAP_LIMIT` (10).
const BURST: usize = 25;
const TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Gap between sends on the push-only phase.
const PUSH_PACE: Duration = Duration::from_millis(200);

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

pub(crate) fn run_dart_recipient_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_dart_recipient(verbose))
}

/// Bob on the Rust CLI: poll, restart, then push alone.
pub async fn run(verbose: bool) {
    run_with(ParticipantKind::RustCli, "sender-exceeds-tag-window", true, verbose).await;
}

/// Bob on the Dart server: poll, then restart.
pub async fn run_dart_recipient(verbose: bool) {
    run_with(ParticipantKind::DartServer, "sender-exceeds-tag-window-d", false, verbose).await;
}

async fn run_with(recipient_kind: ParticipantKind, name: &str, push_phase: bool, verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: {name} ===");

    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "drawbridge"), ("bob", "drawbridge")],
        &[ParticipantKind::RustCli, recipient_kind],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let alice = world.client("alice").clone();
    let bob = world.client("bob").clone();

    alice.login("alice.postern.test", "any-password").await.expect("alice login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    assert!(
        wait_for_membership(&bob, &group_id, "bob", verbose).await,
        "bob never joined the conversation"
    );

    // ── Poll path ────────────────────────────────────────────────────────────
    for n in 1..=BURST {
        alice
            .send_message(&group_id, &format!("polled {n}"))
            .await
            .expect("alice send");
    }
    vlog!("[send] alice sent {BURST} messages");
    let missing = wait_for_all(&bob, &group_id, "polled", true, verbose).await;
    assert!(
        missing.is_empty(),
        "bob, polling, never received {} of {BURST} messages from one sender: {missing:?}",
        missing.len()
    );
    vlog!("[check] poll path: all {BURST} received");

    // ── After a restart ──────────────────────────────────────────────────────
    //
    // A restarted session has no candidate tags until the host repopulates them.
    world.kill_participant("bob").expect("kill bob");
    world.restart_participant("bob").await.expect("restart bob");
    bob.login("bob.postern.test", "any-password").await.expect("bob re-login");
    vlog!("[restart] bob back up");
    for n in 1..=BURST {
        alice
            .send_message(&group_id, &format!("restarted {n}"))
            .await
            .expect("alice send");
    }
    vlog!("[send] alice sent {BURST} messages");
    let missing = wait_for_all(&bob, &group_id, "restarted", true, verbose).await;
    assert!(
        missing.is_empty(),
        "bob, after restarting, never received {} of {BURST} messages from one \
         sender: {missing:?}",
        missing.len()
    );
    vlog!("[check] after restart: all {BURST} received");

    if !push_phase {
        vlog!("\n=== PASSED ===");
        return;
    }

    // ── Push path alone ──────────────────────────────────────────────────────
    world
        .wait_for_drawbridge_connections(2, Duration::from_secs(5))
        .await;
    bob.set_poll_interval(0).await.expect("disable bob's polling");
    // Paced: a burst faster than a watch-list update can outrun push (polling
    // recovers those). Push alone must keep up at human pace.
    for n in 1..=BURST {
        alice
            .send_message(&group_id, &format!("pushed {n}"))
            .await
            .expect("alice send");
        tokio::time::sleep(PUSH_PACE).await;
    }
    vlog!("[send] alice sent {BURST} more, bob not polling");
    let missing = wait_for_all(&bob, &group_id, "pushed", false, verbose).await;
    assert!(
        missing.is_empty(),
        "bob, on Drawbridge push alone, never received {} of {BURST} messages from \
         one sender: {missing:?}",
        missing.len()
    );
    vlog!("[check] push path: all {BURST} received");

    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}

/// Wait until `client` holds `"{prefix} 1"` to `"{prefix} {BURST}"`, polling
/// only when `poll` is set. Returns the numbers still missing at the deadline.
async fn wait_for_all(
    client: &MoatCliClient,
    group_id: &str,
    prefix: &str,
    poll: bool,
    verbose: bool,
) -> Vec<usize> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if poll {
            let _ = client.poll().await;
        }
        let msgs = client.get_messages(group_id).await.unwrap_or_default();
        let missing: Vec<usize> = (1..=BURST)
            .filter(|n| {
                let want = format!("{prefix} {n}");
                !msgs.iter().any(|m| m.content == want)
            })
            .collect();
        if missing.is_empty() || Instant::now() >= deadline {
            if verbose && !missing.is_empty() {
                eprintln!("[wait] still missing {prefix}: {missing:?}");
            }
            return missing;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
