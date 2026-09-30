//! A device fetches a watched contact's message before holding the Welcome
//! that makes it readable, and must still receive it after joining.
//!
//! Carol polls manually to force the order: watch Alice (fetch her message),
//! then watch Bob (find his Welcome).

use std::future::Future;
use std::pin::Pin;

use crate::scenarios::post_fan_out_delivery::{
    epoch_of, wait_for_epoch_after, wait_for_membership, wait_for_message,
};
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

pub(crate) fn run_dart_joiner_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_dart_joiner(verbose))
}

/// Carol, the joiner, runs the Rust CLI.
pub async fn run(verbose: bool) {
    run_with(ParticipantKind::RustCli, "watched-before-welcome", verbose).await;
}

/// Carol, the joiner, runs the Dart server; Alice and Bob stay Rust.
pub async fn run_dart_joiner(verbose: bool) {
    run_with(ParticipantKind::DartServer, "watched-before-welcome-d", verbose).await;
}

async fn run_with(joiner_kind: ParticipantKind, name: &str, verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: {name} ===");

    let world = TestWorld::new_with_kinds(
        &["alice", "bob", "carol"],
        &[ParticipantKind::RustCli, ParticipantKind::RustCli, joiner_kind],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let alice = world.client("alice").clone();
    let bob = world.client("bob").clone();
    let carol = world.client("carol").clone();

    for (client, handle) in [
        (&alice, "alice.postern.test"),
        (&bob, "bob.postern.test"),
        (&carol, "carol.postern.test"),
    ] {
        client
            .login(handle, "any-password")
            .await
            .unwrap_or_else(|e| panic!("{handle} login failed: {e}"));
    }
    carol
        .set_poll_interval(0)
        .await
        .expect("disable carol's automatic polling");

    // ── Alice and Bob converse ───────────────────────────────────────────────
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");
    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    assert!(
        wait_for_membership(&bob, &group_id, "bob", verbose).await,
        "bob never joined the conversation"
    );

    // ── Bob adds Carol; Alice speaks once she has the Add ────────────────────
    let alice_epoch = epoch_of(&alice, &group_id)
        .await
        .expect("alice should report an epoch for the conversation");
    bob.add_member(&group_id, "carol.postern.test")
        .await
        .expect("bob adds carol");
    assert!(
        wait_for_epoch_after(&alice, &group_id, alice_epoch, verbose).await,
        "alice never processed bob's Add commit"
    );
    let text = "said after carol was added";
    alice
        .send_message(&group_id, text)
        .await
        .expect("alice send_message");
    vlog!("[send] alice: {text:?}");

    // ── Carol reads Alice before she can read Bob's Welcome ──────────────────
    carol.watch_handle("alice.postern.test").await.expect("carol watch alice");
    carol.poll().await.expect("carol poll with only alice watched");
    let joined_early = carol
        .list_conversations()
        .await
        .unwrap_or_default()
        .iter()
        .any(|c| c.id == group_id);
    assert!(
        !joined_early,
        "carol joined before watching bob — the scenario did not force the order it tests"
    );
    vlog!("[carol] polled alice's PDS while not yet a member");

    carol.watch_handle("bob.postern.test").await.expect("carol watch bob");
    assert!(
        wait_for_membership(&carol, &group_id, "carol", verbose).await,
        "carol never joined from bob's Welcome"
    );
    vlog!("[carol] joined from bob's Welcome");

    assert!(
        wait_for_message(&carol, &group_id, text, "carol", verbose).await,
        "carol never received {text:?}, which she fetched from alice's PDS before \
         she held the Welcome"
    );

    vlog!("[check] {name}... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
