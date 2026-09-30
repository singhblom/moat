//! History arrives before membership does.
//!
//! `handle_hello` plans for every conversation the peer has and this side
//! does not, so a donor will serve history for a group the requester is
//! not yet in. That is deliberate — when the fan-out `Add` lands, the
//! history is already there — but it produces a state the rest of the app
//! has to have an answer for: messages this device can read, in a
//! conversation it cannot send to.
//!
//! Without registration those messages went to storage and appeared
//! nowhere, since the conversation list is built from registered
//! conversations. Now the conversation is registered read-only, and the
//! composer says so until the `Add` arrives.
//!
//! Staging it is the whole trick: fan-out runs from the ring tick, so
//! this scenario simply never drives D1's ring tick between creating the
//! conversation and the sync. Then it drives one, and asserts the state
//! resolves — that "read-only" really is a waypoint and not a dead end.

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

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

async fn conversation_of(client: &MoatCliClient, group_id: &str) -> Option<crate::client::Conversation> {
    client
        .list_conversations()
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.id == group_id)
}

pub async fn run(verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: sync-history-before-membership ===");

    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        &[ParticipantKind::RustCli, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");
    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();
    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    let d2 = world
        .spawn_nth_device("alice-d2", ParticipantKind::RustCli)
        .await
        .expect("spawn d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");

    vlog!("[pair] d1 <- d2...");
    pair_devices(&d1, &d2, verbose).await;

    // ── A conversation D2 is never added to ──────────────────────────────────
    //
    // No `d1.ring_tick()` from here until the sync has run: fan-out rides
    // that tick, and letting it fire would put D2 in the group and make
    // this scenario a duplicate of `sync_request_history`.
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

    assert!(
        conversation_of(&d2, &group_id).await.is_none(),
        "d2 must not know this conversation yet, or the scenario proves \
         nothing about history arriving ahead of membership"
    );

    // ── D2 asks, and gets history for a group it is not in ───────────────────
    vlog!("[sync] d2 asks its siblings for history");
    d2.sync_request().await.expect("d2 sync_request");

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d1.poll().await;
        let state = d1.sync_request_status().await.expect("d1 sync status");
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

    // ── Readable, and visibly not sendable ───────────────────────────────────
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d2.poll().await;
        let msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        if msgs.len() >= history.len() {
            let contents: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
            for want in &history {
                assert!(
                    contents.contains(want),
                    "d2's synced history is missing {want:?}; got {contents:?}"
                );
            }
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d2 never received the history within {TIMEOUT:?} (has {} of {}); \
             this must fail the test, not hang it",
            msgs.len(),
            history.len()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // The point of the scenario: the messages are readable *and* the
    // conversation exists to read them in. Storing them without this is
    // what the old behaviour did, and it left them invisible forever.
    let conv = conversation_of(&d2, &group_id)
        .await
        .expect("the synced conversation must be registered, or its messages are visible nowhere");
    assert!(
        !conv.is_member,
        "d2 holds the history but has had no Add, so the conversation must \
         read as not-yet-joined; got {conv:?}"
    );

    // And it must refuse a send rather than failing obscurely inside MLS.
    let send = d2.send_message(&group_id, "can I talk yet?").await;
    assert!(
        send.is_err(),
        "sending into a group with no local MLS state must be refused, \
         not attempted"
    );

    // ── The Add arrives and the waypoint resolves ────────────────────────────
    //
    // "Waiting to be connected" is only honest if it ends. Driving the
    // ring tick is what fan-out was waiting for.
    vlog!("[fanout] d1 ticks; d2 should be added");
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d2.poll().await;
        if conversation_of(&d2, &group_id)
            .await
            .is_some_and(|c| c.is_member)
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d2 was never added to the conversation within {TIMEOUT:?}, so \
             the read-only state never resolved; this must fail the test, \
             not hang it"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // The history it already held must still be there — the Add must not
    // have replaced the conversation and dropped its messages.
    let msgs = d2.get_messages(&group_id).await.expect("d2 messages");
    assert!(
        msgs.len() >= history.len(),
        "joining the group must not discard the history that arrived first; \
         got {} of {}",
        msgs.len(),
        history.len()
    );

    vlog!("[check] sync history before membership... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
