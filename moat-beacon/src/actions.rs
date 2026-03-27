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
    /// Add a participant to the group.  Only generated when `new_participant`
    /// exists in the config but isn't in the group yet.
    AddMember {
        adder: ParticipantId,
        new_participant: ParticipantId,
    },
    /// Remove a participant from the group.  Only generated when the target is
    /// in the group, is not the remover, and at least 2 members remain.
    RemoveMember {
        remover: ParticipantId,
        target: ParticipantId,
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

pub fn action_sequence_with_offline_n(n: usize) -> impl Strategy<Value = Vec<Action>> {
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

pub fn action_sequence_n(n: usize) -> impl Strategy<Value = Vec<Action>> {
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

// ── Membership-aware strategies ─────────────────────────────────────────────

/// Generation-time model for sequences that include `AddMember`/`RemoveMember`.
#[derive(Clone, Debug)]
struct MembershipFoldState {
    /// Number of `SendMessage` actions generated so far.
    num_messages: usize,
    /// Total number of participants available in the config.
    total_participants: usize,
    /// Set of participant indices currently in the group.
    members: Vec<bool>,
}

/// Generate one action given the current membership fold state.
///
/// Generation rules:
/// - Members may `SendMessage`, `Poll`, `React` (if messages exist).
/// - If a non-member exists in config, any member may `AddMember`.
/// - If group has 3+ members, any member may `RemoveMember` another.
fn arb_action_with_membership(state: MembershipFoldState) -> BoxedStrategy<Action> {
    let mut choices: Vec<BoxedStrategy<Action>> = vec![];
    let n = state.total_participants;

    // Collect indices of current members and non-members
    let member_indices: Vec<usize> = (0..n).filter(|&i| state.members[i]).collect();
    let non_member_indices: Vec<usize> = (0..n).filter(|&i| !state.members[i]).collect();

    // Members can send messages and poll
    for &i in &member_indices {
        let id = ParticipantId(i);
        choices.push(
            (0..TEXT_VOCAB.len())
                .prop_map({
                    let id = id.clone();
                    move |text_idx| Action::SendMessage {
                        from: id.clone(),
                        text_idx,
                    }
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
    }

    // Any member can add a non-member
    if !non_member_indices.is_empty() {
        for &adder_idx in &member_indices {
            for &new_idx in &non_member_indices {
                choices.push(
                    Just(Action::AddMember {
                        adder: ParticipantId(adder_idx),
                        new_participant: ParticipantId(new_idx),
                    })
                    .boxed(),
                );
            }
        }
    }

    // Any member can remove another member (if 3+ members remain)
    if member_indices.len() >= 3 {
        for &remover_idx in &member_indices {
            for &target_idx in &member_indices {
                if remover_idx != target_idx {
                    choices.push(
                        Just(Action::RemoveMember {
                            remover: ParticipantId(remover_idx),
                            target: ParticipantId(target_idx),
                        })
                        .boxed(),
                    );
                }
            }
        }
    }

    Union::new(choices).boxed()
}

/// Update the membership fold state after generating an action.
fn update_membership_state(state: &MembershipFoldState, action: &Action) -> MembershipFoldState {
    let mut new_state = state.clone();
    match action {
        Action::SendMessage { .. } => new_state.num_messages += 1,
        Action::AddMember { new_participant, .. } => {
            new_state.members[new_participant.ordinal()] = true;
        }
        Action::RemoveMember { target, .. } => {
            new_state.members[target.ordinal()] = false;
        }
        _ => {}
    }
    new_state
}

/// Strategy that produces a valid action sequence for `total_participants`
/// participants where `initial_members` are in the group at the start.
///
/// Membership actions (`AddMember`, `RemoveMember`) are generated alongside
/// regular messaging actions. Membership changes are **not shrinkable** —
/// proptest may shrink messaging actions but the membership sequence stays
/// fixed.
///
/// Use [`action_sequence_with_membership_and_offline`] to also include
/// `GoOffline`/`ComeOnline` transitions.
pub fn action_sequence_with_membership(
    total_participants: usize,
    initial_members: &[usize],
) -> BoxedStrategy<Vec<Action>> {
    let mut members = vec![false; total_participants];
    for &i in initial_members {
        members[i] = true;
    }
    let init = MembershipFoldState {
        num_messages: 0,
        total_participants,
        members,
    };
    (1usize..=10)
        .prop_flat_map(move |len| {
            let init = init.clone();
            (0..len)
                .fold(Just((vec![], init)).boxed(), |acc, _| {
                    acc.prop_flat_map(
                        |(actions, state): (Vec<Action>, MembershipFoldState)| {
                            arb_action_with_membership(state.clone()).prop_map(move |a| {
                                let new_state = update_membership_state(&state, &a);
                                let mut v = actions.clone();
                                v.push(a);
                                (v, new_state)
                            })
                        },
                    )
                    .boxed()
                })
                .prop_map(|(actions, _state)| actions)
        })
        .boxed()
}

// ── Combined membership + offline strategies ─────────────────────────────────

/// Generation-time model that tracks both group membership and online/offline
/// status for each participant.
#[derive(Clone, Debug)]
struct CombinedFoldState {
    num_messages: usize,
    total_participants: usize,
    /// `members[i]` — participant `i` is currently in the group.
    members: Vec<bool>,
    /// `online[i]` — participant `i` is currently online.
    online: Vec<bool>,
}

/// Generate one action given the current combined fold state.
///
/// Generation rules:
/// - Online members: `SendMessage`, `Poll`, `React`, `GoOffline`,
///   `AddMember` (any non-member), `RemoveMember` (if 3+ total members).
/// - Online non-members: `Poll`, `GoOffline`.
/// - Offline participants (member or not): `ComeOnline` only.
fn arb_action_combined(state: CombinedFoldState) -> BoxedStrategy<Action> {
    let mut choices: Vec<BoxedStrategy<Action>> = vec![];
    let n = state.total_participants;

    let member_count = state.members.iter().filter(|&&m| m).count();
    let non_member_indices: Vec<usize> = (0..n).filter(|&i| !state.members[i]).collect();

    for i in 0..n {
        let id = ParticipantId(i);
        if state.online[i] {
            choices.push(Just(Action::Poll { participant: id.clone() }).boxed());
            choices.push(Just(Action::GoOffline { participant: id.clone() }).boxed());

            if state.members[i] {
                // Send messages
                choices.push(
                    (0..TEXT_VOCAB.len())
                        .prop_map({
                            let id = id.clone();
                            move |text_idx| Action::SendMessage { from: id.clone(), text_idx }
                        })
                        .boxed(),
                );
                // React (only when messages exist)
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
                // Add any non-member
                for &j in &non_member_indices {
                    choices.push(
                        Just(Action::AddMember {
                            adder: id.clone(),
                            new_participant: ParticipantId(j),
                        })
                        .boxed(),
                    );
                }
                // Remove another member (only when 3+ total members so 2 remain)
                if member_count >= 3 {
                    for j in 0..n {
                        if j != i && state.members[j] {
                            choices.push(
                                Just(Action::RemoveMember {
                                    remover: id.clone(),
                                    target: ParticipantId(j),
                                })
                                .boxed(),
                            );
                        }
                    }
                }
            }
        } else {
            choices.push(Just(Action::ComeOnline { participant: id.clone() }).boxed());
        }
    }

    Union::new(choices).boxed()
}

fn update_combined_state(state: &CombinedFoldState, action: &Action) -> CombinedFoldState {
    let mut s = state.clone();
    match action {
        Action::SendMessage { .. } => s.num_messages += 1,
        Action::GoOffline { participant } => s.online[participant.ordinal()] = false,
        Action::ComeOnline { participant } => s.online[participant.ordinal()] = true,
        Action::AddMember { new_participant, .. } => {
            s.members[new_participant.ordinal()] = true;
        }
        Action::RemoveMember { target, .. } => {
            s.members[target.ordinal()] = false;
        }
        _ => {}
    }
    s
}

/// Strategy that produces a valid action sequence combining membership changes
/// (`AddMember`, `RemoveMember`) and online/offline transitions
/// (`GoOffline`, `ComeOnline`).
///
/// `initial_members` lists participant indices that start in the group.
/// All participants start online.
pub fn action_sequence_with_membership_and_offline(
    total_participants: usize,
    initial_members: &[usize],
) -> BoxedStrategy<Vec<Action>> {
    let mut members = vec![false; total_participants];
    for &i in initial_members {
        members[i] = true;
    }
    let init = CombinedFoldState {
        num_messages: 0,
        total_participants,
        members,
        online: vec![true; total_participants],
    };
    (1usize..=10)
        .prop_flat_map(move |len| {
            let init = init.clone();
            (0..len)
                .fold(Just((vec![], init)).boxed(), |acc, _| {
                    acc.prop_flat_map(|(actions, state): (Vec<Action>, CombinedFoldState)| {
                        arb_action_combined(state.clone()).prop_map(move |a| {
                            let new_state = update_combined_state(&state, &a);
                            let mut v = actions.clone();
                            v.push(a);
                            (v, new_state)
                        })
                    })
                    .boxed()
                })
                .prop_map(|(actions, _state)| actions)
        })
        .boxed()
}
