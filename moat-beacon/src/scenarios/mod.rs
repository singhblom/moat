//! Scenario registry, shared helpers, and seed utilities for the `beacon` binary.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::{Config, RngAlgorithm, TestRng, TestRunner},
};

use crate::actions::{
    action_sequence, action_sequence_with_offline, Action, ParticipantId, EMOJI_VOCAB, TEXT_VOCAB,
};
use crate::client::MoatCliClient;
use crate::invariants::{ScenarioState, SentMessage};
use crate::world::TestWorld;

pub mod two_party_chat;
pub mod two_party_push;
pub mod two_party_push_restart;
pub mod two_party_restart;

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
    match id {
        ParticipantId::Alice => alice,
        ParticipantId::Bob => bob,
    }
}

fn short_name(id: &ParticipantId) -> &'static str {
    match id {
        ParticipantId::Alice => "alice",
        ParticipantId::Bob => "bob",
    }
}

fn pick_handle<'a>(
    id: &ParticipantId,
    alice_handle: &'a str,
    bob_handle: &'a str,
) -> &'a str {
    match id {
        ParticipantId::Alice => alice_handle,
        ParticipantId::Bob => bob_handle,
    }
}

pub async fn execute_action(
    action: &Action,
    alice: &MoatCliClient,
    bob: &MoatCliClient,
    world: &mut TestWorld,
    alice_full_handle: &str,
    bob_full_handle: &str,
    push_mode: bool,
    state: &mut ScenarioState,
    verbose: bool,
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
                vlog!(verbose, "  → sent {:?} (id={:?})", text, message_id);
                state.sent_messages.push(SentMessage {
                    text: text.to_string(),
                    from: from.clone(),
                    message_id,
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
            let msg = &state.sent_messages[*message_idx];
            if let Some(ref mid) = msg.message_id {
                let emoji = EMOJI_VOCAB[emoji_idx % EMOJI_VOCAB.len()];
                let _ = pick_client(from, alice, bob)
                    .send_reaction(&state.group_id, mid, emoji)
                    .await;
                vlog!(verbose, "  → reacted {:?} to message {}", emoji, message_idx);
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
            let other_participant = match participant {
                ParticipantId::Alice => &ParticipantId::Bob,
                ParticipantId::Bob => &ParticipantId::Alice,
            };
            let other_full = pick_handle(other_participant, alice_full_handle, bob_full_handle);
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
    }
}

/// Bring all offline participants back online.
///
/// For each participant that is currently offline, restarts the process,
/// re-logs in, re-watches the other party, runs a catch-up poll, and
/// (if `push_mode`) disables auto-polling again.
pub async fn ensure_all_online(
    world: &mut TestWorld,
    alice: &MoatCliClient,
    bob: &MoatCliClient,
    alice_full_handle: &str,
    bob_full_handle: &str,
    push_mode: bool,
) {
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
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    run_fn: fn(Vec<Action>, bool) -> Pin<Box<dyn Future<Output = ()> + Send>>,
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
