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
//! ring; D1's user approves; an ordinary `SyncSession` runs on the channel
//! keyed from the request's secret. The scenario asserts both halves — that
//! the history really is missing beforehand (otherwise the test would
//! pass for the wrong reason, on history that arrived some other way),
//! and that it is complete afterwards.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::client::{MoatCliClient, SyncCompletion};
use crate::scenarios::three_device_pairing::pair_devices;
use crate::scenarios::Action;
use crate::world::{ParticipantKind, TestWorld};

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

pub(crate) fn run_dd_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::DartServer, ParticipantKind::DartServer, "dd", verbose))
}

pub(crate) fn run_dr_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::DartServer, ParticipantKind::RustCli, "dr", verbose))
}

pub(crate) fn run_rd_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_with(ParticipantKind::RustCli, ParticipantKind::DartServer, "rd", verbose))
}

pub(crate) fn run_after_idle_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_after_idle(verbose))
}

pub(crate) fn run_after_idle_dd_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run_after_idle_dd(verbose))
}

/// All-Rust cell.
pub async fn run(verbose: bool) {
    run_with(ParticipantKind::RustCli, ParticipantKind::RustCli, "rr", verbose).await
}

/// Ring ticks between pairing and the request: more than one tag window.
const IDLE_TICKS: usize = 12;

/// All-Rust cell, after the ring has sat idle.
pub async fn run_after_idle(verbose: bool) {
    run_with_idle(
        ParticipantKind::RustCli,
        ParticipantKind::RustCli,
        "rr-idle",
        IDLE_TICKS,
        verbose,
    )
    .await
}

/// All-Dart cell, after the ring has sat idle.
pub async fn run_after_idle_dd(verbose: bool) {
    run_with_idle(
        ParticipantKind::DartServer,
        ParticipantKind::DartServer,
        "dd-idle",
        IDLE_TICKS,
        verbose,
    )
    .await
}

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(300);

/// A minimal valid 16x16 RGBA PNG, so the conversation contains a real
/// attachment rather than only text.
fn make_test_png() -> Vec<u8> {
    use image::{DynamicImage, ImageFormat};
    let img = DynamicImage::new_rgba8(16, 16);
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), ImageFormat::Png)
        .expect("encode test png");
    buf
}

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

/// Poll until `client`'s sync request reports completion, failing the test
/// on a reported failure or once [`TIMEOUT`] passes.
pub(crate) async fn await_sync_completion(client: &MoatCliClient, name: &str) -> SyncCompletion {
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = client.poll().await;
        if let Some(c) = client.sync_completion().await.expect("sync completion") {
            return c;
        }
        let state = client.sync_request_status().await.expect("sync status");
        assert!(!state.is_failed(), "{name}'s sync failed: {state:?}");
        assert!(
            std::time::Instant::now() < deadline,
            "{name}'s sync never reported completion within {TIMEOUT:?}; \
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
    run_with_idle(donor_kind, requester_kind, cell, 0, verbose).await
}

/// [`run_with`] after `idle_ticks` ring ticks on both devices: the request
/// must still be recognised once ring traffic has used up a tag window.
pub async fn run_with_idle(
    donor_kind: ParticipantKind,
    requester_kind: ParticipantKind,
    cell: &str,
    idle_ticks: usize,
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

    for tick in 0..idle_ticks {
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        vlog!("[idle] ring tick {}/{idle_ticks}", tick + 1);
    }

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
    // Plus one image, sent by Bob. Sync carries the attachment *reference*
    // — the blob stays on the PDS and is fetched when the user opens it —
    // and a device receiving history from before it joined cannot recover
    // that reference any other way, since the original event is not
    // decryptable to it. Including one is what makes the two runtimes'
    // idea of a `SyncMessage` testable: a text-only scenario passes just
    // as happily when a host silently drops every blob field.
    //
    // Bob's, received by d1 through the ordinary poll path.
    //
    // A *self-sent* image would also be worth covering — it is published
    // behind a blob upload, and only reaches a real rkey because the
    // deferred publish now reuses its optimistic row's message id — but
    // adding a second image reliably trips a separate teardown race (the
    // donor closes the channel on "I have sent everything" rather than on
    // any acknowledgement, so a larger transfer can be truncated). Keeping
    // one image here holds this scenario deterministic; the self-sent path
    // is covered by the keystore unit tests until that race is fixed.
    bob.send_image(&group_id, &make_test_png())
        .await
        .expect("bob send image");
    d1.send_image(&group_id, &make_test_png())
        .await
        .expect("d1 send image");

    // Both sends are non-blocking — the blob has to upload before the
    // message is published at all — so wait until d1 holds two settled
    // attachments. Without this the assertions below could pass vacuously
    // on history that simply hadn't been written yet.
    let expected_total = history.len() + 2;
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let msgs = d1.get_messages(&group_id).await.expect("d1 messages");
        let attachments = msgs.iter().filter(|m| m.attachment.is_some()).count();
        let settled = msgs.len() == expected_total
            && attachments == 2
            && msgs.iter().all(|m| !m.content.contains("processing"));
        if settled {
            break;
        }
        let contents: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
        assert!(
            std::time::Instant::now() < deadline,
            "d1's own history never settled within {TIMEOUT:?} \
             ({attachments} of 1 attachment); a leftover \
             \"processing…\" row means a deferred publish never \
             reconciled with its optimistic row; got {contents:?}"
        );
        let _ = bob.poll().await;
        let _ = d1.poll().await;
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Bob reacts to one of D1's messages. Reactions arrive as their own
    // PDS events, so a device present at the time rebuilds them by
    // replaying — but D2 cannot: those events predate its membership and
    // are not decryptable to it. Sync is their only route, and a drop
    // would be silent and permanent.
    let reacted_to = {
        let deadline = std::time::Instant::now() + TIMEOUT;
        loop {
            let _ = bob.poll().await;
            let msgs = bob.get_messages(&group_id).await.unwrap_or_default();
            if let Some(id) = msgs
                .iter()
                .find(|m| m.content == "first")
                .and_then(|m| m.message_id.clone())
            {
                break id;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "bob never received a message to react to within {TIMEOUT:?}"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    bob.send_reaction(&group_id, &reacted_to, "👍")
        .await
        .expect("bob reacts");

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        let _ = d1.poll().await;
        let msgs = d1.get_messages(&group_id).await.unwrap_or_default();
        if msgs.iter().any(|m| !m.reactions.is_empty()) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "d1 never recorded bob's reaction within {TIMEOUT:?}; it has to \
             be *persisted*, not merely displayed, or there is nothing for \
             sync to serve"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

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
        vlog!("[sync] d2 has {}/{} messages", msgs.len(), expected_total);
        if msgs.len() >= expected_total {
            let contents: Vec<&str> = msgs.iter().map(|m| m.content.as_str()).collect();
            for want in &history {
                assert!(
                    contents.contains(want),
                    "d2's history is missing {want:?}; got {contents:?}"
                );
            }
            assert_eq!(
                msgs.len(),
                expected_total,
                "d2 must hold each message exactly once; got {contents:?}"
            );

            // The attachment reference must survive the transfer, or the
            // image is unopenable on this device: the blob is still on the
            // PDS, but without uri/key/hashes there is no way to ask for
            // it, and the original event predates d2's membership so it
            // cannot be decrypted either.
            let images: Vec<_> = msgs.iter().filter(|m| m.attachment.is_some()).collect();
            assert_eq!(
                images.len(),
                2,
                "d2 must receive both attachments — Bob's (arrived on d1 by \
                 poll) and d1's own (published behind a blob upload, and \
                 skipped entirely while it kept its \"pending\" rkey). \
                 Dropping the blob fields leaves the image unopenable here \
                 too, since the original event predates d2's membership and \
                 cannot be decrypted; got {contents:?}"
            );
            // The reaction must have travelled with the message. Nothing
            // else can deliver it here: the reaction event predates d2's
            // membership, so it cannot be decrypted from the PDS.
            let reacted = msgs.iter().find(|m| m.content == "first");
            assert!(
                reacted.is_some_and(|m| m
                    .reactions
                    .iter()
                    .any(|r| r.emoji == "👍")),
                "d2 must receive the reaction along with the message it is \
                 on; got {:?}",
                reacted.map(|m| &m.reactions)
            );

            let attachment = images[0].attachment.as_ref().expect("checked above");
            assert!(!attachment.uri.is_empty(), "blob URI must survive sync");
            assert!(!attachment.key.is_empty(), "blob key must survive sync");
            assert!(
                !attachment.ciphertext_hash.is_empty(),
                "ciphertext hash must survive sync — without it the fetched \
                 blob cannot be integrity-checked"
            );
            assert!(
                attachment.width.unwrap_or(0) > 0 && attachment.height.unwrap_or(0) > 0,
                "image dimensions must survive sync; got {:?}x{:?}",
                attachment.width,
                attachment.height
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
            expected_total
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // ── The report the user is shown ─────────────────────────────────────────
    //
    // A transfer that moved everything and one that moved nothing look
    // identical without this, and with one donor per gesture that is the
    // difference between "you're done" and "go and ask a different
    // device". So the counts are asserted, not just the messages.
    let completion = await_sync_completion(&d2, "d2").await;
    vlog!("[sync] d2's completion report: {completion:?}");
    assert_eq!(
        completion.messages, expected_total as u64,
        "the report must count every message that arrived, or \"nothing new\" \
         and \"everything arrived\" read alike"
    );
    assert_eq!(
        completion.conversations, 1,
        "one conversation was transferred; got {completion:?}"
    );
    // The donor is named as the ring member with the device id from its
    // `Hello`, so the name is one the ring already knows. Asserted as
    // "present and non-empty" rather than by value: both devices here
    // derive the same hostname-based default name, so no value assertion
    // could tell the donor from the requester. That the name is the *sender's* is covered where it is
    // distinguishable — d1's `awaiting_approval` above carries d2's.
    let name = completion
        .device_name
        .as_deref()
        .expect("a completed transfer always carried a credential to name");
    assert!(
        !name.is_empty(),
        "the report must name the device the history came from; got {completion:?}"
    );

    // ── The donor's report ───────────────────────────────────────────────────
    //
    // The requester closes the channel once it holds everything. The donor
    // must read that close as the end of a delivered transfer, confirmed by
    // the requester's Fin — not as a connection failure.
    let donor = await_sync_completion(&d1, "d1").await;
    vlog!("[sync] d1's completion report: {donor:?}");
    assert_eq!(
        (donor.sent_messages, donor.sent_conversations),
        (expected_total as u64, 1),
        "the donor must report what it delivered; got {donor:?}"
    );

    vlog!("[check] sync request history ({cell})... ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
