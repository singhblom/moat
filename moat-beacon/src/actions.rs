//! `Action` enum and proptest generation strategy.
//!
//! Sequences are built with a `prop_flat_map` fold that threads a generation-time
//! model (number of `SendMessage` actions so far) through each step.  This
//! ensures `React` is only generated when there are messages to target, and
//! `message_idx` is always a valid index by construction — no runtime guards
//! needed.

use proptest::prelude::*;

// ── Vocabulary ────────────────────────────────────────────────────────────────

pub const TEXT_VOCAB: &[&str] = &["hi", "hello", "yes", "no", "ok", "bye", "?"];
pub const EMOJI_VOCAB: &[&str] = &["👍", "❤️", "😂", "🎉", "🔥"];

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParticipantId {
    Alice,
    Bob,
}

#[derive(Debug, Clone)]
pub enum Action {
    SendMessage {
        from: ParticipantId,
        /// Index into [`TEXT_VOCAB`].
        text_idx: usize,
    },
    Poll {
        participant: ParticipantId,
    },
    /// `message_idx` is always in `0..num_prior_sends` — valid by construction.
    React {
        from: ParticipantId,
        /// Index into the list of `SendMessage` actions that precede this one.
        message_idx: usize,
        /// Index into [`EMOJI_VOCAB`].
        emoji_idx: usize,
    },
}

// ── Strategies ────────────────────────────────────────────────────────────────

fn arb_participant() -> impl Strategy<Value = ParticipantId> {
    prop_oneof![Just(ParticipantId::Alice), Just(ParticipantId::Bob)]
}

/// Generate one action, given how many `SendMessage` actions have already been
/// generated in the current sequence.  React is only possible when
/// `num_messages > 0`.
fn arb_action(num_messages: usize) -> BoxedStrategy<Action> {
    let send_or_poll = prop_oneof![
        (arb_participant(), 0..TEXT_VOCAB.len())
            .prop_map(|(from, text_idx)| Action::SendMessage { from, text_idx }),
        arb_participant().prop_map(|participant| Action::Poll { participant }),
    ];

    if num_messages == 0 {
        send_or_poll.boxed()
    } else {
        prop_oneof![
            3 => send_or_poll,
            1 => (arb_participant(), 0..num_messages, 0..EMOJI_VOCAB.len())
                .prop_map(|(from, message_idx, emoji_idx)| Action::React {
                    from,
                    message_idx,
                    emoji_idx,
                }),
        ]
        .boxed()
    }
}

/// Strategy that produces a valid action sequence of length 1–10.
///
/// Each step is generated via `prop_flat_map`, threading the running count of
/// `SendMessage` actions so that `React.message_idx` is always in-bounds.
pub fn action_sequence() -> impl Strategy<Value = Vec<Action>> {
    (1usize..=10).prop_flat_map(|len| {
        (0..len).fold(Just(vec![]).boxed(), |acc, _| {
            acc.prop_flat_map(|actions| {
                let n = actions
                    .iter()
                    .filter(|a| matches!(a, Action::SendMessage { .. }))
                    .count();
                arb_action(n).prop_map(move |a| {
                    let mut v = actions.clone();
                    v.push(a);
                    v
                })
            })
            .boxed()
        })
    })
}
