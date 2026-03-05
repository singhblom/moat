//! `Action` enum and proptest generation strategy.
//!
//! Sequences are built with a `prop_flat_map` fold that threads a generation-time
//! model (number of `SendMessage` actions so far) through each step.  This
//! ensures `React` is only generated when there are messages to target, and
//! `message_idx` is always a valid index by construction — no runtime guards
//! needed.

use proptest::prelude::*;
use proptest::strategy::Union;

// ── Vocabulary ────────────────────────────────────────────────────────────────

pub const TEXT_VOCAB: &[&str] = &["hi", "hello", "yes", "no", "ok", "bye", "?"];
pub const EMOJI_VOCAB: &[&str] = &["👍", "❤️", "😂", "🎉", "🔥"];

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParticipantId(pub usize);

impl ParticipantId {
    pub const ALICE: Self = Self(0);
    pub const BOB: Self = Self(1);
    pub const CAROL: Self = Self(2);

    /// Index into a slice keyed by participant.
    pub fn ordinal(&self) -> usize {
        self.0
    }

    /// Short lowercase name for this participant.
    pub fn short_name(&self) -> &'static str {
        const NAMES: &[&str] = &["alice", "bob", "carol", "dave", "eve"];
        NAMES.get(self.0).copied().unwrap_or("unknown")
    }
}

impl std::fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short_name())
    }
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
    GoOffline {
        participant: ParticipantId,
    },
    ComeOnline {
        participant: ParticipantId,
    },
}

// ── Strategies ────────────────────────────────────────────────────────────────

fn arb_participant() -> impl Strategy<Value = ParticipantId> {
    arb_participant_n(2)
}

fn arb_participant_n(n: usize) -> impl Strategy<Value = ParticipantId> {
    (0..n).prop_map(ParticipantId)
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

// ── Offline fold state ────────────────────────────────────────────────────────

/// Generation-time model for sequences that include `GoOffline`/`ComeOnline`.
#[derive(Clone, Debug)]
struct OfflineFoldState {
    /// Number of `SendMessage` actions generated so far.
    num_messages: usize,
    /// `online[i]` is `true` iff participant `i` is currently online.
    online: Vec<bool>,
}

/// Generate one action given the current offline fold state.
///
/// Generation rules:
/// - Online participants may `SendMessage`, `Poll`, `React` (if messages exist), or `GoOffline`.
/// - Offline participants may only `ComeOnline`.
fn arb_action_with_offline_n(state: OfflineFoldState) -> BoxedStrategy<Action> {
    let mut choices: Vec<BoxedStrategy<Action>> = vec![];
    let n = state.online.len();

    for i in 0..n {
        let id = ParticipantId(i);
        if state.online[i] {
            choices.push(
                (0..TEXT_VOCAB.len())
                    .prop_map({
                        let id = id.clone();
                        move |text_idx| Action::SendMessage { from: id.clone(), text_idx }
                    })
                    .boxed(),
            );
            choices.push(Just(Action::Poll { participant: id.clone() }).boxed());
            if state.num_messages > 0 {
                choices.push(
                    (0..state.num_messages, 0..EMOJI_VOCAB.len())
                        .prop_map({
                            let id = id.clone();
                            move |(message_idx, emoji_idx)| Action::React {
                                from: id.clone(),
                                message_idx,
                                emoji_idx,
                            }
                        })
                        .boxed(),
                );
            }
            choices.push(Just(Action::GoOffline { participant: id.clone() }).boxed());
        } else {
            choices.push(Just(Action::ComeOnline { participant: id.clone() }).boxed());
        }
    }

    Union::new(choices).boxed()
}

/// Update the fold state after generating an action.
fn update_offline_state(state: &OfflineFoldState, action: &Action) -> OfflineFoldState {
    let mut new_state = state.clone();
    match action {
        Action::SendMessage { .. } => new_state.num_messages += 1,
        Action::GoOffline { participant } => new_state.online[participant.ordinal()] = false,
        Action::ComeOnline { participant } => new_state.online[participant.ordinal()] = true,
        _ => {}
    }
    new_state
}

// `online` is now `Vec<bool>`, so indexing by `ordinal()` works unchanged.

/// Strategy that produces a valid action sequence of length 1–10, including
/// `GoOffline` / `ComeOnline` transitions.
///
/// Extends [`action_sequence`] with an online-mask threaded through the fold,
/// so that offline participants can only come online, and online participants
/// can go offline.
pub fn action_sequence_with_offline() -> impl Strategy<Value = Vec<Action>> {
    action_sequence_with_offline_n(2)
}

fn action_sequence_with_offline_n(n: usize) -> impl Strategy<Value = Vec<Action>> {
    let init = OfflineFoldState {
        num_messages: 0,
        online: vec![true; n],
    };
    (1usize..=10).prop_flat_map(move |len| {
        let init = init.clone();
        (0..len)
            .fold(Just((vec![], init)).boxed(), |acc, _| {
                acc.prop_flat_map(|(actions, state): (Vec<Action>, OfflineFoldState)| {
                    arb_action_with_offline_n(state.clone()).prop_map(move |a| {
                        let mut v = actions.clone();
                        let new_state = update_offline_state(&state, &a);
                        v.push(a);
                        (v, new_state)
                    })
                })
                .boxed()
            })
            .prop_map(|(actions, _state)| actions)
    })
}

// ── 3-party strategies ───────────────────────────────────────────────────────

/// Strategy that produces a valid action sequence for 3 participants.
pub fn action_sequence_3p() -> impl Strategy<Value = Vec<Action>> {
    action_sequence_n(3)
}

fn action_sequence_n(n: usize) -> impl Strategy<Value = Vec<Action>> {
    (1usize..=10).prop_flat_map(move |len| {
        (0..len).fold(Just(vec![]).boxed(), move |acc, _| {
            acc.prop_flat_map(move |actions| {
                let num_messages = actions
                    .iter()
                    .filter(|a| matches!(a, Action::SendMessage { .. }))
                    .count();
                arb_action_n(num_messages, n).prop_map(move |a| {
                    let mut v = actions.clone();
                    v.push(a);
                    v
                })
            })
            .boxed()
        })
    })
}

fn arb_action_n(num_messages: usize, n: usize) -> BoxedStrategy<Action> {
    let send_or_poll = prop_oneof![
        (arb_participant_n(n), 0..TEXT_VOCAB.len())
            .prop_map(|(from, text_idx)| Action::SendMessage { from, text_idx }),
        arb_participant_n(n).prop_map(|participant| Action::Poll { participant }),
    ];

    if num_messages == 0 {
        send_or_poll.boxed()
    } else {
        prop_oneof![
            3 => send_or_poll,
            1 => (arb_participant_n(n), 0..num_messages, 0..EMOJI_VOCAB.len())
                .prop_map(|(from, message_idx, emoji_idx)| Action::React {
                    from,
                    message_idx,
                    emoji_idx,
                }),
        ]
        .boxed()
    }
}

/// Strategy that produces a valid action sequence for 3 participants with
/// `GoOffline` / `ComeOnline` transitions.
pub fn action_sequence_3p_with_offline() -> impl Strategy<Value = Vec<Action>> {
    action_sequence_with_offline_n(3)
}
