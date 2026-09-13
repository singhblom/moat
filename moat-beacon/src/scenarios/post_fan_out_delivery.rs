//! Delivery after same-user fan-out.
//!
//! Alice's first device (D1) and Bob share a conversation in which both
//! have already sent messages. D2 pairs in, and D1's fan-out adds D2 to the
//! conversation with an MLS commit that D1 applies locally and never
//! re-processes from the PDS. Every message sent after that commit must
//! reach every other member: Bob → D1 and D2, D2 → D1 and Bob, D1 → D2 and
//! Bob.
//!
//! The pairing cells stop at ring formation and the history-sync cells stop
//! once history has arrived; neither sends anything after the fan-out commit
//! lands, which is the window this scenario covers. Bob sends before the
//! pairing so that D1's scanning window for Bob has already moved past
//! counter 0 in the old epoch.
//!
//! All checks run before the scenario fails, so a single run reports every
//! direction that is broken rather than only the first.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use crate::client::MoatCliClient;
use crate::scenarios::three_device_pairing::pair_devices;
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

const TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

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
    Box::pin(run_dr(verbose))
}

pub(crate) fn run_rd_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_rd(verbose))
}

/// Both of Alice's devices run the Rust CLI.
pub async fn run(verbose: bool) {
    run_with(
        ParticipantKind::RustCli,
        ParticipantKind::RustCli,
        "post-fan-out-delivery",
        verbose,
    )
    .await;
}

/// The new device (D2) runs Dart; the existing device (D1) runs Rust.
pub async fn run_dr(verbose: bool) {
    run_with(
        ParticipantKind::RustCli,
        ParticipantKind::DartServer,
        "post-fan-out-delivery-dr",
        verbose,
    )
    .await;
}

/// The new device (D2) runs Rust; the existing device (D1) runs Dart.
pub async fn run_rd(verbose: bool) {
    run_with(
        ParticipantKind::DartServer,
        ParticipantKind::RustCli,
        "post-fan-out-delivery-rd",
        verbose,
    )
    .await;
}

async fn run_with(
    existing_kind: ParticipantKind,
    new_kind: ParticipantKind,
    name: &str,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: {name} ===");

    // Bob always runs Rust: he is the cross-user observer, not the subject.
    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        &[existing_kind, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();

    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");
    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");

    // ── D1 and Bob converse before any pairing ───────────────────────────────
    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    assert!(
        wait_for_membership(&bob, &group_id, "bob", verbose).await,
        "bob never joined the conversation within {TIMEOUT:?}"
    );

    for text in ["bob before 1", "bob before 2"] {
        bob.send_message(&group_id, text).await.expect("bob send_message");
    }
    d1.send_message(&group_id, "d1 before").await.expect("d1 send_message");
    for text in ["bob before 1", "bob before 2"] {
        assert!(
            wait_for_message(&d1, &group_id, text, "d1", verbose).await,
            "d1 never received pre-pairing message {text:?}"
        );
    }
    assert!(
        wait_for_message(&bob, &group_id, "d1 before", "bob", verbose).await,
        "bob never received pre-pairing message \"d1 before\""
    );

    let bob_epoch_before = epoch_of(&bob, &group_id)
        .await
        .expect("bob should report an epoch for the conversation");

    // ── D2 pairs in; D1 fans it out into the conversation ────────────────────
    let d2 = world
        .spawn_nth_device("alice-d2", new_kind)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;

    assert!(
        wait_for_fan_out(&d1, &d2, &group_id, verbose).await,
        "d2 never became a member of the conversation within {TIMEOUT:?}"
    );
    assert!(
        wait_for_epoch_after(&bob, &group_id, bob_epoch_before, verbose).await,
        "bob never processed the fan-out commit (epoch still {bob_epoch_before}) \
         within {TIMEOUT:?}"
    );

    // ── Every direction after the fan-out commit ─────────────────────────────
    let mut failures = Vec::new();

    let checks: [(&MoatCliClient, &str, &str, [(&MoatCliClient, &str); 2]); 3] = [
        (
            &bob,
            "bob",
            "bob after fan-out",
            [(&d1, "d1 (fan-out publisher)"), (&d2, "d2 (new device)")],
        ),
        (
            &d2,
            "d2",
            "d2 after fan-out",
            [(&d1, "d1 (fan-out publisher)"), (&bob, "bob")],
        ),
        (
            &d1,
            "d1",
            "d1 after fan-out",
            [(&d2, "d2 (new device)"), (&bob, "bob")],
        ),
    ];

    for (sender, sender_label, text, recipients) in checks {
        vlog!("[send] {sender_label}: {text:?}");
        if let Err(e) = sender.send_message(&group_id, text).await {
            failures.push(format!("{sender_label} could not send {text:?}: {e}"));
            continue;
        }
        for (recipient, recipient_label) in recipients {
            if !wait_for_message(recipient, &group_id, text, recipient_label, verbose).await {
                failures.push(format!("{recipient_label} never received {text:?}"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "post-fan-out delivery failed ({name}):\n  {}",
        failures.join("\n  ")
    );

    vlog!("[check] {name}... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}

async fn epoch_of(client: &MoatCliClient, group_id: &str) -> Option<u64> {
    client
        .list_conversations()
        .await
        .ok()?
        .into_iter()
        .find(|c| c.id == group_id)
        .map(|c| c.epoch)
}

/// Poll `client` until it holds `group_id` as a member.
async fn wait_for_membership(
    client: &MoatCliClient,
    group_id: &str,
    label: &str,
    verbose: bool,
) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let _ = client.poll().await;
        let convs = client.list_conversations().await.unwrap_or_default();
        if convs.iter().any(|c| c.id == group_id && c.is_member) {
            return true;
        }
        if Instant::now() >= deadline {
            if verbose {
                eprintln!("[wait] {label} is not a member of {group_id}");
            }
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Drive D1's ring tick (which runs the fan-out) and D2's poll until D2 is
/// a member of `group_id`.
async fn wait_for_fan_out(
    d1: &MoatCliClient,
    d2: &MoatCliClient,
    group_id: &str,
    verbose: bool,
) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d2.poll().await;
        let convs = d2.list_conversations().await.unwrap_or_default();
        if convs.iter().any(|c| c.id == group_id && c.is_member) {
            return true;
        }
        if verbose {
            let state = convs
                .iter()
                .find(|c| c.id == group_id)
                .map(|c| if c.is_member { "member" } else { "read-only" })
                .unwrap_or("absent");
            eprintln!("[fan-out] d2 conversation state: {state}");
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_epoch_after(
    client: &MoatCliClient,
    group_id: &str,
    before: u64,
    verbose: bool,
) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let _ = client.poll().await;
        let epoch = epoch_of(client, group_id).await;
        if epoch.is_some_and(|e| e > before) {
            return true;
        }
        if Instant::now() >= deadline {
            if verbose {
                eprintln!("[wait] epoch for {group_id} still {epoch:?} (before: {before})");
            }
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `client` until a message with content `text` appears in `group_id`.
/// Returns `false` on timeout so the caller can record the failure and keep
/// checking the remaining directions.
async fn wait_for_message(
    client: &MoatCliClient,
    group_id: &str,
    text: &str,
    label: &str,
    verbose: bool,
) -> bool {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let _ = client.poll().await;
        let msgs = client.get_messages(group_id).await.unwrap_or_default();
        if msgs.iter().any(|m| m.content == text) {
            if verbose {
                eprintln!("[recv] {label} has {text:?}");
            }
            return true;
        }
        if Instant::now() >= deadline {
            if verbose {
                let contents: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
                eprintln!("[recv] {label} timed out waiting for {text:?}; holds {contents:?}");
            }
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
