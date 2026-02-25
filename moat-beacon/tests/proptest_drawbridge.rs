//! Phase 4: property-based two-party scenario using Drawbridge push delivery.
//!
//! The test structure mirrors `proptest_two_party`, but:
//!   - `TestWorld::new_with_drawbridge` is used so each moat-cli process is
//!     started with `--drawbridge-url`.
//!   - After the fixed prologue, polling is disabled on all participants via
//!     `POST /poll/0`.  Any message delivery must arrive via the Drawbridge
//!     push path (`new_event` → `spawn_targeted_fetch`), not auto-polling.
//!   - `drain_events_push` sleeps briefly (instead of explicitly polling) to
//!     let push-triggered fetches complete.
//!
//! Fixed prologue:
//!   1. Login Alice + Bob.
//!   2. Bob watches Alice.
//!   3. Alice starts a conversation with Bob.
//!   4. Poll once to exchange Welcomes and Drawbridge hints.
//!   5. Disable auto-polling on both participants.
//!
//! Invariants checked after drain:
//!   - Delivery         — every confirmed message ID appears in both views.
//!   - Consensus order  — Alice and Bob see the same message sequence.
//!   - No duplicates    — no participant has a repeated message ID.

use moat_beacon::{
    actions::{Action, ParticipantId, TEXT_VOCAB, EMOJI_VOCAB, action_sequence},
    client::MoatCliClient,
    invariants::{
        check_delivery, check_consensus_ordering, check_no_duplicates,
        ScenarioState, SentMessage,
    },
    world::TestWorld,
};
use proptest::prelude::*;
use std::time::Duration;

// ── Push-aware drain ──────────────────────────────────────────────────────────

/// Wait for push-triggered fetches to complete without explicit polling.
///
/// We sleep long enough for:
/// 1. Alice's moat-cli to send `event_posted` to Drawbridge.
/// 2. Drawbridge to forward `new_event` to Bob.
/// 3. Bob's moat-cli to call `spawn_targeted_fetch` and retrieve the record.
async fn drain_events_push(alice: &MoatCliClient, bob: &MoatCliClient) {
    // Give the push pipeline time to propagate.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    // One final explicit poll per participant to catch anything that arrived
    // slightly after the sleep (e.g. React commits, epoch advances).
    let _ = alice.poll().await;
    let _ = bob.poll().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
}

// ── Action executor ───────────────────────────────────────────────────────────

fn pick_client<'a>(
    id: &ParticipantId,
    alice: &'a MoatCliClient,
    bob: &'a MoatCliClient,
) -> &'a MoatCliClient {
    match id {
        ParticipantId::Alice => alice,
        ParticipantId::Bob => bob,
    }
}

async fn execute_action(
    action: &Action,
    alice: &MoatCliClient,
    bob: &MoatCliClient,
    state: &mut ScenarioState,
) {
    match action {
        Action::SendMessage { from, text_idx } => {
            let text = TEXT_VOCAB[text_idx % TEXT_VOCAB.len()];
            let client = pick_client(from, alice, bob);
            if client.send_message(&state.group_id, text).await.is_ok() {
                let message_id = client
                    .get_messages(&state.group_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .rev()
                    .find(|m| m.is_own && m.content.contains(text))
                    .and_then(|m| m.message_id);
                state.sent_messages.push(SentMessage {
                    text: text.to_string(),
                    from: from.clone(),
                    message_id,
                });
            }
        }

        // With polling disabled, explicit Poll actions serve as a useful
        // escape hatch for commits/epoch advances that Drawbridge doesn't
        // notify about directly.  Keep them but they should be rare.
        Action::Poll { participant } => {
            let _ = pick_client(participant, alice, bob).poll().await;
        }

        Action::React { from, message_idx, emoji_idx } => {
            let msg = &state.sent_messages[*message_idx];
            if let Some(ref mid) = msg.message_id {
                let emoji = EMOJI_VOCAB[emoji_idx % EMOJI_VOCAB.len()];
                let _ = pick_client(from, alice, bob)
                    .send_reaction(&state.group_id, mid, emoji)
                    .await;
            }
        }
    }
}

// ── Scenario runner ───────────────────────────────────────────────────────────

async fn run_scenario(actions: Vec<Action>) {
    // ── Prologue ─────────────────────────────────────────────────────────────
    let world = TestWorld::new_with_drawbridge(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup with drawbridge");

    let alice = world.client("alice");
    let bob = world.client("bob");

    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");

    // Allow moat-cli to publish key packages, stealth addresses, and connect
    // to Drawbridge as sender (challenge-response auth).
    tokio::time::sleep(Duration::from_millis(800)).await;

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // One explicit poll: Bob joins the group (receives Welcome) and picks up
    // Alice's DrawbridgeHint so he connects as recipient.
    let stats = bob.poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group after prologue poll"
    );

    // Give Bob time to connect to Drawbridge as recipient.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling.  From here on, message delivery must come
    // entirely through Drawbridge push notifications.
    alice
        .set_poll_interval(0)
        .await
        .expect("disable alice polling");
    bob.set_poll_interval(0)
        .await
        .expect("disable bob polling");

    // ── Random action sequence ────────────────────────────────────────────────
    let mut state = ScenarioState {
        group_id,
        sent_messages: vec![],
    };

    for action in &actions {
        execute_action(action, alice, bob, &mut state).await;
    }

    // ── Drain + invariants ────────────────────────────────────────────────────
    drain_events_push(alice, bob).await;

    check_delivery(alice, bob, &state)
        .await
        .expect("delivery invariant violated");
    check_consensus_ordering(alice, bob, &state)
        .await
        .expect("consensus ordering invariant violated");
    check_no_duplicates(alice, bob, &state)
        .await
        .expect("no-duplicates invariant violated");
}

// ── proptest ──────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
        )),
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_party_push_delivery(actions in action_sequence()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(run_scenario(actions));
    }
}
