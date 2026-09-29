//! Scenario registry, shared helpers, and seed utilities for the `beacon` binary.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::{Config, RngAlgorithm, TestRng, TestRunner},
};

use crate::actions::{
    action_sequence, action_sequence_3p, action_sequence_3p_with_offline,
    action_sequence_with_offline, Action, ParticipantId, EMOJI_VOCAB, TEXT_VOCAB,
};
use crate::client::MoatCliClient;
use crate::invariants::{ScenarioState, SentMessage};
use crate::world::TestWorld;

pub mod dart_push_latency;
pub mod fcm_dispatch;
pub mod lost_device_pairing;
pub mod multi_device_chat;
pub mod dart_three_party_chat;
pub mod dart_two_party_chat;
pub mod mixed_push_latency;
pub mod mixed_three_party_chat;
pub mod mixed_two_party_chat;
pub mod pairing_cancelled;
pub mod pairing_rejected;
pub mod pairing_retry_after_abandoned;
pub mod post_fan_out_delivery;
pub mod push_latency;
pub mod push_latency_restart;
pub mod same_drawbridge_local;
pub mod sender_exceeds_tag_window;
pub mod staggered_device_pairing;
pub mod sync_history_before_membership;
pub mod sync_offer_history;
pub mod sync_request_after_cancelled_pairing;
pub mod sync_request_history;
pub mod three_device_pairing;
pub mod three_device_pairing_history_sync;
pub mod three_party_chat;
pub mod three_party_push;
pub mod three_party_restart;
pub mod three_party_smoke;
pub mod two_device_pairing;
pub mod two_party_chat;
pub mod two_party_fanout;
pub mod two_party_push;
pub mod two_party_push_restart;
pub mod two_party_restart;
pub mod two_party_smoke;
pub mod watched_before_welcome;

// ── Verbose logging ───────────────────────────────────────────────────────────

macro_rules! vlog {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose { eprintln!($($arg)*); }
    };
}
pub(crate) use vlog;

// ── Shared helpers ────────────────────────────────────────────────────────────

pub fn pick_client<'a>(
    id: &ParticipantId,
    alice: &'a MoatCliClient,
    bob: &'a MoatCliClient,
) -> &'a MoatCliClient {
    match id.ordinal() {
        0 => alice,
        1 => bob,
        _ => panic!("pick_client: only supports 2 participants, got {:?}", id),
    }
}

fn short_name(id: &ParticipantId) -> &'static str {
    id.short_name()
}

fn pick_handle<'a>(
    id: &ParticipantId,
    alice_handle: &'a str,
    bob_handle: &'a str,
) -> &'a str {
    match id.ordinal() {
        0 => alice_handle,
        1 => bob_handle,
        _ => panic!("pick_handle: only supports 2 participants, got {:?}", id),
    }
}

/// Per-scenario configuration that stays constant across all calls to
/// [`execute_action`] / [`ensure_all_online`] within a single scenario run.
///
/// Bundling these lets the per-step calls take just the action + mutable state,
/// keeping scenario loops readable.
pub struct TwoPartyEnv<'a> {
    pub alice: &'a MoatCliClient,
    pub bob: &'a MoatCliClient,
    pub alice_full_handle: &'a str,
    pub bob_full_handle: &'a str,
    pub push_mode: bool,
    pub verbose: bool,
}

pub async fn execute_action(
    action: &Action,
    env: &TwoPartyEnv<'_>,
    world: &mut TestWorld,
    state: &mut ScenarioState,
) {
    let &TwoPartyEnv {
        alice,
        bob,
        alice_full_handle,
        bob_full_handle,
        push_mode,
        verbose,
    } = env;
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
                vlog!(verbose, "  → sent {:?} (id={:?})", text, message_id);
                state.sent_messages.push(SentMessage {
                    text: text.to_string(),
                    from: from.clone(),
                    message_id,
                    members_at_send: None,
                });
            }
        }

        Action::Poll { participant } => {
            let result = pick_client(participant, alice, bob).poll().await;
            vlog!(
                verbose,
                "  → poll: new_messages={}, new_conversations={}",
                result.as_ref().map(|s| s.new_messages).unwrap_or(0),
                result.as_ref().map(|s| s.new_conversations).unwrap_or(0),
            );
        }

        Action::React { from, message_idx, emoji_idx } => {
            if *message_idx >= state.sent_messages.len() {
                // A prior SendMessage may have failed, leaving sent_messages shorter
                // than the strategy expected.  Skip rather than panic.
                vlog!(verbose, "  → react skipped (message_idx={} out of range)", message_idx);
            } else {
                let msg = &state.sent_messages[*message_idx];
                if let Some(ref mid) = msg.message_id {
                    let emoji = EMOJI_VOCAB[emoji_idx % EMOJI_VOCAB.len()];
                    let _ = pick_client(from, alice, bob)
                        .send_reaction(&state.group_id, mid, emoji)
                        .await;
                    vlog!(verbose, "  → reacted {:?} to message {}", emoji, message_idx);
                }
            }
        }

        Action::GoOffline { participant } => {
            // Brief pause before kill: `send_message` spawns the ATProto
            // publish as a background task and returns immediately.  If
            // GoOffline follows a SendMessage for the same participant, the
            // SIGKILL can race the in-flight localhost POST to Postern.
            // 100 ms is ample time for a loopback HTTP round-trip to complete.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            world
                .kill_participant(short_name(participant))
                .expect("kill participant");
            vlog!(verbose, "  → {:?} went offline", participant);
        }

        Action::ComeOnline { participant } => {
            let short = short_name(participant);
            let full = pick_handle(participant, alice_full_handle, bob_full_handle);
            let other_full = match participant.ordinal() {
                0 => bob_full_handle,
                _ => alice_full_handle,
            };
            let client = pick_client(participant, alice, bob);
            world
                .restart_participant(short)
                .await
                .expect("restart participant");
            client
                .login(full, "any-password")
                .await
                .expect("re-login after restart");
            client
                .watch_handle(other_full)
                .await
                .expect("re-watch after restart");
            // Catch up messages missed while offline.
            let _ = client.poll().await;
            if push_mode {
                client
                    .set_poll_interval(0)
                    .await
                    .expect("disable polling after restart");
            }
            vlog!(verbose, "  → {:?} came online", participant);
        }

        Action::AddMember { .. } | Action::RemoveMember { .. } => {
            panic!("AddMember/RemoveMember not supported in 2-party execute_action; use execute_action_n");
        }
    }
}

/// Bring all offline participants back online.
///
/// For each participant that is currently offline, restarts the process,
/// re-logs in, re-watches the other party, runs a catch-up poll, and
/// (if `push_mode`) disables auto-polling again.
pub async fn ensure_all_online(world: &mut TestWorld, env: &TwoPartyEnv<'_>) {
    let &TwoPartyEnv {
        alice,
        bob,
        alice_full_handle,
        bob_full_handle,
        push_mode,
        ..
    } = env;
    let participants = [
        ("alice", alice_full_handle, alice, bob_full_handle),
        ("bob", bob_full_handle, bob, alice_full_handle),
    ];
    for (handle, full_handle, client, other_full) in participants {
        if !world.participant_is_online(handle) {
            world
                .restart_participant(handle)
                .await
                .expect("restart participant");
            client
                .login(full_handle, "any-password")
                .await
                .expect("re-login");
            client
                .watch_handle(other_full)
                .await
                .expect("re-watch");
            let _ = client.poll().await;
            if push_mode {
                client
                    .set_poll_interval(0)
                    .await
                    .expect("disable polling after bring-online");
            }
        }
    }
}

// ── N-participant helpers ─────────────────────────────────────────────────────

/// Per-scenario configuration for N-participant scenarios — the indexed
/// generalization of [`TwoPartyEnv`].  Constructed once per scenario run.
///
/// `push_per_participant[i]` is `true` when participant `i` has a Drawbridge
/// relay and should have polling disabled after a restart.  Pass an all-`false`
/// slice for polling-only scenarios.
pub struct NPartyEnv<'a> {
    pub clients: &'a [&'a MoatCliClient],
    pub handles: &'a [&'a str],
    pub push_per_participant: &'a [bool],
    pub verbose: bool,
}

/// Execute an action using indexed participant slices (N-participant generalization).
pub async fn execute_action_n(
    action: &Action,
    env: &NPartyEnv<'_>,
    world: &mut TestWorld,
    state: &mut ScenarioState,
) {
    let &NPartyEnv {
        clients,
        handles,
        push_per_participant,
        verbose,
    } = env;
    match action {
        Action::SendMessage { from, text_idx } => {
            let text = TEXT_VOCAB[text_idx % TEXT_VOCAB.len()];
            let client = &clients[from.ordinal()];
            if client.send_message(&state.group_id, text).await.is_ok() {
                let message_id = client
                    .get_messages(&state.group_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .rev()
                    .find(|m| m.is_own && m.content.contains(text))
                    .and_then(|m| m.message_id);
                vlog!(verbose, "  → sent {:?} (id={:?})", text, message_id);
                state.sent_messages.push(SentMessage {
                    text: text.to_string(),
                    from: from.clone(),
                    message_id,
                    members_at_send: state.members.clone(),
                });
            }
        }

        Action::Poll { participant } => {
            let result = clients[participant.ordinal()].poll().await;
            vlog!(
                verbose,
                "  → poll: new_messages={}, new_conversations={}",
                result.as_ref().map(|s| s.new_messages).unwrap_or(0),
                result.as_ref().map(|s| s.new_conversations).unwrap_or(0),
            );
        }

        Action::React {
            from,
            message_idx,
            emoji_idx,
        } => {
            if *message_idx >= state.sent_messages.len() {
                vlog!(verbose, "  → react skipped (message_idx={} out of range)", message_idx);
            } else {
                let msg = &state.sent_messages[*message_idx];
                if let Some(ref mid) = msg.message_id {
                    let emoji = EMOJI_VOCAB[emoji_idx % EMOJI_VOCAB.len()];
                    let _ = clients[from.ordinal()]
                        .send_reaction(&state.group_id, mid, emoji)
                        .await;
                    vlog!(
                        verbose,
                        "  → reacted {:?} to message {}",
                        emoji,
                        message_idx
                    );
                }
            }
        }

        Action::GoOffline { participant } => {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let name = participant.short_name();
            world.kill_participant(name).expect("kill participant");
            vlog!(verbose, "  → {} went offline", name);
        }

        Action::ComeOnline { participant } => {
            let name = participant.short_name();
            let full = handles[participant.ordinal()];
            let client = &clients[participant.ordinal()];
            world
                .restart_participant(name)
                .await
                .expect("restart participant");
            client
                .login(full, "any-password")
                .await
                .expect("re-login after restart");
            // Re-watch all other participants' handles
            for (i, other_handle) in handles.iter().enumerate() {
                if i != participant.ordinal() {
                    client
                        .watch_handle(other_handle)
                        .await
                        .expect("re-watch after restart");
                }
            }
            let _ = client.poll().await;
            if push_per_participant.get(participant.ordinal()).copied().unwrap_or(false) {
                client
                    .set_poll_interval(0)
                    .await
                    .expect("disable polling after restart");
            }
            vlog!(verbose, "  → {} came online", name);
        }

        Action::AddMember {
            adder,
            new_participant,
        } => {
            let adder_client = &clients[adder.ordinal()];
            let new_handle = handles[new_participant.ordinal()];
            let new_client = &clients[new_participant.ordinal()];

            // The new participant must watch the adder's DID so their poll
            // discovers the stealth-encrypted Welcome.  If they are currently
            // offline their HTTP server is unreachable — that is fine: the
            // ComeOnline handler re-watches all handles on restart, so they
            // will find the Welcome when they come back online.
            let adder_handle = handles[adder.ordinal()];
            let _ = new_client.watch_handle(adder_handle).await;

            adder_client
                .add_member(&state.group_id, new_handle)
                .await
                .unwrap_or_else(|e| panic!("add_member {} failed: {e}", new_handle));

            // Poll the new member until they join (retry up to 10 times).
            // Use explicit polls only — do NOT re-enable auto-polling, as it
            // races with explicit polls and can consume the Welcome before the
            // explicit poll checks for it.
            //
            // If the new participant is currently offline their HTTP server is
            // unreachable.  That is fine: when they come back online they will
            // watch all handles and poll (see ComeOnline), at which point they
            // will find the Welcome and join.  Skip the join assertion in that
            // case — the final drain + invariant check covers delivery.
            let mut joined = false;
            let mut new_member_offline = false;
            for attempt in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let join_stats = match new_client.poll().await {
                    Ok(s) => s,
                    Err(_) => {
                        new_member_offline = true;
                        vlog!(
                            verbose,
                            "  [add_member] {} is offline — will join on ComeOnline",
                            new_handle
                        );
                        break;
                    }
                };
                vlog!(
                    verbose,
                    "  [add_member poll {}/10] new_messages={}, new_conversations={}",
                    attempt + 1,
                    join_stats.new_messages,
                    join_stats.new_conversations
                );
                if join_stats.new_conversations > 0 {
                    joined = true;
                    break;
                }
                // Also check if the conversation already exists (e.g. from a
                // prior auto-poll or Drawbridge push that raced with us).
                let convs = new_client
                    .list_conversations()
                    .await
                    .unwrap_or_default();
                if convs.iter().any(|c| c.id == state.group_id) {
                    vlog!(
                        verbose,
                        "  [add_member] {} already has the group (raced with auto-poll/push)",
                        new_handle
                    );
                    joined = true;
                    break;
                }
            }
            if !new_member_offline {
                assert!(
                    joined,
                    "{} should have joined the group after add_member",
                    new_handle
                );
            }

            // Existing members pick up the epoch commit
            for (i, client) in clients.iter().enumerate() {
                if i != new_participant.ordinal() {
                    let _ = client.poll().await;
                }
            }

            // Exchange DrawbridgeHints
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            for client in clients.iter() {
                let _ = client.poll().await;
            }

            // Update membership tracking.  If this participant was
            // previously removed and is being re-added, they won't have
            // pre-removal messages — clear them from members_at_send of all
            // existing messages so the delivery check doesn't expect them.
            if let Some(ref mut members) = state.members {
                if !members.contains(new_participant) {
                    // Remove from members_at_send of all prior messages
                    for sent in &mut state.sent_messages {
                        if let Some(ref mut m) = sent.members_at_send {
                            m.retain(|p| p != new_participant);
                        }
                    }
                    members.push(new_participant.clone());
                }
            }

            vlog!(
                verbose,
                "  → {} added {} to group",
                adder.short_name(),
                new_participant.short_name()
            );
        }

        Action::RemoveMember { remover, target } => {
            let remover_client = &clients[remover.ordinal()];
            let target_handle = handles[target.ordinal()];

            // Flush pending commits to all current members before kicking.
            // The remover must have processed every epoch-advancing commit
            // (e.g. a prior AddMember) so they know the target is actually
            // in the group. Without this, kick_member panics with "not a member".
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if let Some(ref members) = state.members {
                for m in members.iter() {
                    let _ = clients[m.ordinal()].poll().await;
                }
            }

            remover_client
                .kick_member(&state.group_id, target_handle)
                .await
                .unwrap_or_else(|e| panic!("kick_member {} failed: {e}", target_handle));

            // Let the commit propagate; remaining members pick up the epoch
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            for (i, client) in clients.iter().enumerate() {
                if i != target.ordinal() {
                    let _ = client.poll().await;
                }
            }

            // Update membership tracking
            if let Some(ref mut members) = state.members {
                members.retain(|m| m != target);
            }

            vlog!(
                verbose,
                "  → {} removed {} from group",
                remover.short_name(),
                target.short_name()
            );
        }
    }
}

/// Bring all offline participants back online (N-participant version).
pub async fn ensure_all_online_n(world: &mut TestWorld, env: &NPartyEnv<'_>) {
    let &NPartyEnv {
        clients,
        handles,
        push_per_participant,
        ..
    } = env;
    let names: Vec<String> = handles
        .iter()
        .map(|h| h.split('.').next().unwrap().to_string())
        .collect();

    for (i, name) in names.iter().enumerate() {
        if !world.participant_is_online(name) {
            world
                .restart_participant(name)
                .await
                .expect("restart participant");
            clients[i]
                .login(handles[i], "any-password")
                .await
                .expect("re-login");
            for (j, other_handle) in handles.iter().enumerate() {
                if j != i {
                    clients[i]
                        .watch_handle(other_handle)
                        .await
                        .expect("re-watch");
                }
            }
            let _ = clients[i].poll().await;
            if push_per_participant.get(i).copied().unwrap_or(false) {
                clients[i]
                    .set_poll_interval(0)
                    .await
                    .expect("disable polling after bring-online");
            }
        }
    }
}

/// Existing device only: wait for `client`'s pairing state to reach
/// `awaiting_approval` — the state a peer's `Enroll` puts it in, where a
/// real user would be looking at the approve/reject prompt.
///
/// Bounded so a peer that never sends `Enroll` fails the test instead of
/// hanging it.
pub async fn wait_for_awaiting_approval(client: &MoatCliClient, timeout: std::time::Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = client.pair_status().await.expect("pair_status");
        if matches!(status, crate::client::PairingUiState::AwaitingApproval { .. }) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pairing never reached awaiting_approval within {timeout:?} \
             (status={status:?}); this must fail the test, not hang it",
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Existing device only: wait for `awaiting_approval`, then approve — the
/// explicit step that replaces the deleted `event_broadcast.is_some()`
/// auto-approve fork in `moat-cli` (and the `autoApprove` flag it mirrored
/// in `moat_dart_server`; see pairing-ui-state.md §B/§D). No host
/// auto-approves an incoming `Enroll` anymore, in any mode, so every
/// pairing scenario must perform this step itself once it has confirmed a
/// code.
pub async fn wait_for_awaiting_approval_and_approve(
    client: &MoatCliClient,
    timeout: std::time::Duration,
) {
    wait_for_awaiting_approval(client, timeout).await;
    client.pair_approve().await.expect("pair_approve");
}

/// Wait for `client`'s pairing state to reach the terminal `failed` phase,
/// returning the reason. Bounded so a session that silently stalls in a
/// non-terminal state fails the test instead of hanging it — the whole
/// point of retaining `Failed { reason }` on the session is that a failed
/// pairing is distinguishable from a slow one.
pub async fn wait_for_pair_failed(
    client: &MoatCliClient,
    timeout: std::time::Duration,
) -> String {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = client.pair_status().await.expect("pair_status");
        if let crate::client::PairingUiState::Failed { reason } = status {
            return reason;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pairing never reached a terminal failed state within {timeout:?} \
             (status={status:?}); this must fail the test, not hang it",
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Format an action for human-readable display.
pub fn format_action(action: &Action) -> String {
    match action {
        Action::SendMessage { from, text_idx } => {
            let text = TEXT_VOCAB[text_idx % TEXT_VOCAB.len()];
            format!("SendMessage {{ from: {:?}, text: {:?} }}", from, text)
        }
        Action::Poll { participant } => {
            format!("Poll {{ participant: {:?} }}", participant)
        }
        Action::React { from, message_idx, emoji_idx } => {
            let emoji = EMOJI_VOCAB[emoji_idx % EMOJI_VOCAB.len()];
            format!(
                "React {{ from: {:?}, msg_idx: {}, emoji: {:?} }}",
                from, message_idx, emoji
            )
        }
        Action::GoOffline { participant } => {
            format!("GoOffline {{ participant: {:?} }}", participant)
        }
        Action::ComeOnline { participant } => {
            format!("ComeOnline {{ participant: {:?} }}", participant)
        }
        Action::AddMember {
            adder,
            new_participant,
        } => {
            format!(
                "AddMember {{ adder: {:?}, new_participant: {:?} }}",
                adder, new_participant
            )
        }
        Action::RemoveMember { remover, target } => {
            format!(
                "RemoveMember {{ remover: {:?}, target: {:?} }}",
                remover, target
            )
        }
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

type ScenarioRunFn = fn(Vec<Action>, bool) -> Pin<Box<dyn Future<Output = ()> + Send>>;

pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    run_fn: ScenarioRunFn,
    gen_fn: fn() -> Vec<Action>,
    seed_fn: fn(&str) -> Result<Vec<Action>>,
}

impl Scenario {
    pub fn run(
        &self,
        actions: Vec<Action>,
        verbose: bool,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        (self.run_fn)(actions, verbose)
    }

    /// Generate a random action sequence appropriate for this scenario.
    pub fn generate_actions(&self) -> Vec<Action> {
        (self.gen_fn)()
    }

    /// Reproduce an action sequence from a proptest seed string.
    pub fn actions_from_seed(&self, seed_str: &str) -> Result<Vec<Action>> {
        (self.seed_fn)(seed_str)
    }
}

pub static SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "two-party-chat",
        description: "Alice + Bob, polling delivery",
        run_fn: two_party_chat::run_boxed,
        gen_fn: generate_random_actions,
        seed_fn: actions_from_seed,
    },
    Scenario {
        name: "two-party-push",
        description: "Alice + Bob, Drawbridge push delivery",
        run_fn: two_party_push::run_boxed,
        gen_fn: generate_random_actions,
        seed_fn: actions_from_seed,
    },
    Scenario {
        name: "two-party-restart",
        description: "Alice + Bob, polling delivery with offline/online cycles",
        run_fn: two_party_restart::run_boxed,
        gen_fn: generate_random_actions_offline,
        seed_fn: actions_from_seed_offline,
    },
    Scenario {
        name: "two-party-push-restart",
        description: "Alice + Bob, Drawbridge push delivery with offline/online cycles",
        run_fn: two_party_push_restart::run_boxed,
        gen_fn: generate_random_actions_offline,
        seed_fn: actions_from_seed_offline,
    },
    Scenario {
        name: "three-party-chat",
        description: "Alice + Bob + Carol, polling delivery",
        run_fn: three_party_chat::run_boxed,
        gen_fn: generate_random_actions_3p,
        seed_fn: actions_from_seed_3p,
    },
    Scenario {
        name: "three-party-push",
        description: "Alice + Bob + Carol, Drawbridge push delivery",
        run_fn: three_party_push::run_boxed,
        gen_fn: generate_random_actions_3p,
        seed_fn: actions_from_seed_3p,
    },
    Scenario {
        name: "three-party-restart",
        description: "Alice + Bob + Carol, polling with offline/online cycles",
        run_fn: three_party_restart::run_boxed,
        gen_fn: generate_random_actions_3p_offline,
        seed_fn: actions_from_seed_3p_offline,
    },
    Scenario {
        name: "dart-two-party-chat",
        description: "Alice (Dart) + Bob (Dart), polling delivery",
        run_fn: dart_two_party_chat::run_boxed,
        gen_fn: generate_random_actions,
        seed_fn: actions_from_seed,
    },
    Scenario {
        name: "mixed-two-party-chat",
        description: "Alice (Rust) + Bob (Dart), polling delivery",
        run_fn: mixed_two_party_chat::run_boxed,
        gen_fn: generate_random_actions,
        seed_fn: actions_from_seed,
    },
    Scenario {
        name: "two-party-fanout",
        description: "Alice + Bob on separate relays, relay-to-relay fan-out",
        run_fn: two_party_fanout::run_boxed,
        gen_fn: generate_random_actions,
        seed_fn: actions_from_seed,
    },
    Scenario {
        name: "same-drawbridge-local",
        description: "Alice + Bob on shared relay, local delivery",
        run_fn: same_drawbridge_local::run_boxed,
        gen_fn: generate_random_actions,
        seed_fn: actions_from_seed,
    },
    Scenario {
        name: "dart-three-party-chat",
        description: "Alice + Bob + Carol (all Dart), polling delivery",
        run_fn: dart_three_party_chat::run_boxed,
        gen_fn: generate_random_actions_3p,
        seed_fn: actions_from_seed_3p,
    },
    Scenario {
        name: "mixed-three-party-chat",
        description: "Alice (Rust) + Bob + Carol (Dart), polling delivery",
        run_fn: mixed_three_party_chat::run_boxed,
        gen_fn: generate_random_actions_3p,
        seed_fn: actions_from_seed_3p,
    },
    Scenario {
        name: "two-device-pairing",
        description: "One user, two devices (Rust + Rust) — live QR/text pairing",
        run_fn: two_device_pairing::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "two-device-pairing-dd",
        description: "One user, two devices (Dart + Dart) — live QR/text pairing",
        run_fn: two_device_pairing::run_dd_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "two-device-pairing-rd",
        description: "One user, two devices (new=Rust, existing=Dart) — live QR/text pairing",
        run_fn: two_device_pairing::run_rd_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "two-device-pairing-dr",
        description: "One user, two devices (new=Dart, existing=Rust) — live QR/text pairing",
        run_fn: two_device_pairing::run_dr_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "three-device-pairing",
        description: "One user, three devices — D1 pairs D2 then D3 into the same ring",
        run_fn: three_device_pairing::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "three-device-pairing-history-sync",
        description: "D1 has pre-existing history with Bob; D2 then D3 pair in and must sync it",
        run_fn: three_device_pairing_history_sync::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "three-device-pairing-history-sync-dr",
        description: "Same as three-device-pairing-history-sync, but D2/D3 (new devices) run Dart, D1 stays Rust",
        run_fn: three_device_pairing_history_sync::run_dr_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "three-device-pairing-history-sync-rd",
        description: "Same as three-device-pairing-history-sync, but D1 (the history donor) runs Dart, D2/D3 stay Rust",
        run_fn: three_device_pairing_history_sync::run_rd_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "post-fan-out-delivery",
        description: "D1 and Bob converse, D2 pairs in; every direction must deliver after D1's fan-out commit",
        run_fn: post_fan_out_delivery::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "post-fan-out-delivery-dr",
        description: "Same as post-fan-out-delivery, but D2 (new device) runs Dart, D1 stays Rust",
        run_fn: post_fan_out_delivery::run_dr_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "post-fan-out-delivery-rd",
        description: "Same as post-fan-out-delivery, but D1 (existing device) runs Dart, D2 runs Rust",
        run_fn: post_fan_out_delivery::run_rd_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "watched-before-welcome",
        description: "Carol reads Alice's post-Add message from a watch before holding Bob's Welcome; she must still get it",
        run_fn: watched_before_welcome::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "watched-before-welcome-d",
        description: "Same as watched-before-welcome, but Carol (the joiner) runs Dart",
        run_fn: watched_before_welcome::run_dart_joiner_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sender-exceeds-tag-window",
        description: "Alice sends Bob (Rust) several tag windows of messages; all must arrive by poll, after Bob restarts, then by push alone",
        run_fn: sender_exceeds_tag_window::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sender-exceeds-tag-window-d",
        description: "Same as sender-exceeds-tag-window with a Dart recipient, poll path and restart only",
        run_fn: sender_exceeds_tag_window::run_dart_recipient_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-after-idle",
        description: "sync-request-history after the ring sat idle for more than a tag window of ticks (all Rust)",
        run_fn: sync_request_history::run_after_idle_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-after-idle-dd",
        description: "Same as sync-request-after-idle, both of Alice's devices on Dart",
        run_fn: sync_request_history::run_after_idle_dd_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "staggered-device-pairing",
        description: "D2 is offline while D1 pairs D3; D2 must catch up on its own",
        run_fn: staggered_device_pairing::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-offer-history",
        description: "D1 sees D2 has no history and offers it; D2 joins without being prompted",
        run_fn: sync_offer_history::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-offer-history-dr",
        description: "Same as sync-offer-history, but the offering device is Dart",
        run_fn: sync_offer_history::run_dr_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-history-before-membership",
        description: "D2 is served history for a conversation it has not been added to yet",
        run_fn: sync_history_before_membership::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-history",
        description: "D2 sleeps through a conversation, is fanned in with no history, and asks D1 for it",
        run_fn: sync_request_history::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-history-dd",
        description: "Same as sync-request-history, but both devices Dart",
        run_fn: sync_request_history::run_dd_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-history-rd",
        description: "Same as sync-request-history, but Dart requester, Rust donor",
        run_fn: sync_request_history::run_rd_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-history-dr",
        description: "Same as sync-request-history, but Rust requester, Dart donor",
        run_fn: sync_request_history::run_dr_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "lost-device-pairing",
        description: "D1 is permanently lost after pairing D2; D2 alone pairs D3 and history survives",
        run_fn: lost_device_pairing::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "pairing-rejected",
        description: "Existing device declines the Enroll — both sides fail, no ring is created",
        run_fn: pairing_rejected::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "pairing-cancelled",
        description: "New device backs out while showing its code — terminal failure, no ring",
        run_fn: pairing_cancelled::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-after-cancelled-pairing",
        description: "D1 ignores D2's sync request mid-pairing, then prompts for the next one once the pairing is cancelled",
        run_fn: sync_request_after_cancelled_pairing::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "sync-request-after-cancelled-pairing-d",
        description: "Same as sync-request-after-cancelled-pairing, both devices Dart",
        run_fn: sync_request_after_cancelled_pairing::run_d_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
    Scenario {
        name: "pairing-retry-after-abandoned",
        description: "A pairing abandoned at the approval prompt must not poison a fresh retry",
        run_fn: pairing_retry_after_abandoned::run_boxed,
        gen_fn: || vec![],
        seed_fn: |_| Ok(vec![]),
    },
];

pub fn get_scenario(name: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.name == name)
}

// ── Seed utilities ────────────────────────────────────────────────────────────

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => anyhow::bail!("invalid hex char: {}", b as char),
    }
}

/// Parse `"cc <64-hex>"` (proptest regression format) or bare `"<64-hex>"` into
/// 32 seed bytes.
pub fn parse_seed(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let hex = s.strip_prefix("cc ").map(str::trim).unwrap_or(s);
    if hex.len() != 64 {
        anyhow::bail!("expected 64 hex chars, got {} in {:?}", hex.len(), hex);
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(bytes)
}

/// Generate one action sequence from a proptest seed string (standard strategy).
pub fn actions_from_seed(seed_str: &str) -> Result<Vec<Action>> {
    let seed = parse_seed(seed_str)?;
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
    let mut runner = TestRunner::new_with_rng(Config::default(), rng);
    action_sequence()
        .new_tree(&mut runner)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .map(|t| t.current())
}

/// Generate one random action sequence (standard strategy, for `beacon run`).
pub fn generate_random_actions() -> Vec<Action> {
    let mut runner = TestRunner::default();
    action_sequence().new_tree(&mut runner).unwrap().current()
}

/// Generate one action sequence from a proptest seed string (offline strategy).
pub fn actions_from_seed_offline(seed_str: &str) -> Result<Vec<Action>> {
    let seed = parse_seed(seed_str)?;
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
    let mut runner = TestRunner::new_with_rng(Config::default(), rng);
    action_sequence_with_offline()
        .new_tree(&mut runner)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .map(|t| t.current())
}

/// Generate one random action sequence using the offline strategy (for `beacon run`).
pub fn generate_random_actions_offline() -> Vec<Action> {
    let mut runner = TestRunner::default();
    action_sequence_with_offline()
        .new_tree(&mut runner)
        .unwrap()
        .current()
}

/// Generate one action sequence from a proptest seed string (3-party strategy).
pub fn actions_from_seed_3p(seed_str: &str) -> Result<Vec<Action>> {
    let seed = parse_seed(seed_str)?;
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
    let mut runner = TestRunner::new_with_rng(Config::default(), rng);
    action_sequence_3p()
        .new_tree(&mut runner)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .map(|t| t.current())
}

/// Generate one random action sequence (3-party strategy, for `beacon run`).
pub fn generate_random_actions_3p() -> Vec<Action> {
    let mut runner = TestRunner::default();
    action_sequence_3p().new_tree(&mut runner).unwrap().current()
}

/// Generate one action sequence from a proptest seed string (3-party offline strategy).
pub fn actions_from_seed_3p_offline(seed_str: &str) -> Result<Vec<Action>> {
    let seed = parse_seed(seed_str)?;
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
    let mut runner = TestRunner::new_with_rng(Config::default(), rng);
    action_sequence_3p_with_offline()
        .new_tree(&mut runner)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .map(|t| t.current())
}

/// Generate one random action sequence (3-party offline strategy, for `beacon run`).
pub fn generate_random_actions_3p_offline() -> Vec<Action> {
    let mut runner = TestRunner::default();
    action_sequence_3p_with_offline()
        .new_tree(&mut runner)
        .unwrap()
        .current()
}
