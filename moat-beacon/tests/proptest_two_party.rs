//! Phase 3: property-based two-party scenario.
//!
//! `proptest` generates random action sequences of length 1–10 using the
//! `prop_flat_map` fold strategy in `actions::action_sequence()`.  Reactions
//! are only generated after at least one `SendMessage`, and `message_idx` is
//! always in-bounds by construction.
//!
//! Fixed prologue (not randomised):
//!   1. Login Alice + Bob.
//!   2. Bob watches Alice.
//!   3. Alice starts a conversation with Bob.
//!   4. Bob polls to join (receives the MLS Welcome).
//!
//! After the action sequence, `drain_events` lets everything propagate and
//! three invariants are checked:
//!   - Delivery         — every sent message appears in both participants' lists.
//!   - Consensus order  — Alice and Bob see the same message sequence (global order).
//!   - No duplicates    — no participant has a repeated message ID.

use moat_beacon::{
    actions::{Action, ParticipantId, TEXT_VOCAB, EMOJI_VOCAB, action_sequence},
    client::MoatCliClient,
    invariants::{
        drain_events, check_delivery, check_consensus_ordering, check_no_duplicates,
        ScenarioState, SentMessage,
    },
    world::TestWorld,
};
use proptest::prelude::*;

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
                // Read back the sender's own message to capture its ID.
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

        Action::Poll { participant } => {
            let _ = pick_client(participant, alice, bob).poll().await;
        }

        // message_idx is always valid (0..num_prior_sends) by construction.
        // The reaction API is fire-and-forget here: we execute it but don't
        // verify delivery, since MessageDto doesn't yet expose reactions.
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
    let world = TestWorld::new(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup");
    let alice = world.client("alice");
    let bob = world.client("bob");

    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");

    // Allow moat-cli to publish key packages and stealth addresses.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");

    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Bob joins the group by receiving Alice's Welcome.
    let stats = bob.poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group after prologue poll"
    );

    // ── Random action sequence ────────────────────────────────────────────────
    let mut state = ScenarioState {
        group_id,
        sent_messages: vec![],
    };

    for action in &actions {
        execute_action(action, alice, bob, &mut state).await;
    }

    // ── Drain + invariants ────────────────────────────────────────────────────
    drain_events(alice, bob).await;

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
    fn two_party_random_actions(actions in action_sequence()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(run_scenario(actions));
    }
}
