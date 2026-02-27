//! Scenario registry, shared helpers, and seed utilities for the `beacon` binary.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::{Config, RngAlgorithm, TestRng, TestRunner},
};

use crate::actions::{action_sequence, Action, ParticipantId, EMOJI_VOCAB, TEXT_VOCAB};
use crate::client::MoatCliClient;
use crate::invariants::{ScenarioState, SentMessage};

pub mod two_party_chat;
pub mod two_party_push;

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

pub async fn execute_action(
    action: &Action,
    alice: &MoatCliClient,
    bob: &MoatCliClient,
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
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    run_fn: fn(Vec<Action>, bool) -> Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Scenario {
    pub fn run(
        &self,
        actions: Vec<Action>,
        verbose: bool,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        (self.run_fn)(actions, verbose)
    }
}

pub static SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "two-party-chat",
        description: "Alice + Bob, polling delivery",
        run_fn: two_party_chat::run_boxed,
    },
    Scenario {
        name: "two-party-push",
        description: "Alice + Bob, Drawbridge push delivery",
        run_fn: two_party_push::run_boxed,
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

/// Generate one action sequence from a proptest seed string.
pub fn actions_from_seed(seed_str: &str) -> Result<Vec<Action>> {
    let seed = parse_seed(seed_str)?;
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
    let mut runner = TestRunner::new_with_rng(Config::default(), rng);
    action_sequence()
        .new_tree(&mut runner)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .map(|t| t.current())
}

/// Generate one random action sequence (for `beacon run`).
pub fn generate_random_actions() -> Vec<Action> {
    let mut runner = TestRunner::default();
    action_sequence().new_tree(&mut runner).unwrap().current()
}
