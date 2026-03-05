//! Ground-truth state and invariant checkers for beacon scenarios.
//!
//! `ScenarioState` is accumulated during action execution and used by the
//! invariant checkers after all participants have been drained.

use crate::actions::ParticipantId;
use crate::client::MoatCliClient;
use anyhow::Result;
use std::time::Duration;

// ── Ground-truth state ────────────────────────────────────────────────────────

/// A message that was successfully sent during the scenario.
pub struct SentMessage {
    pub text: String,
    pub from: ParticipantId,
    /// Confirmed message ID (hex-encoded), present when the sender could read it
    /// back from their own message list immediately after sending.
    pub message_id: Option<String>,
}

/// Accumulated ground-truth for one scenario run.
pub struct ScenarioState {
    pub group_id: String,
    /// Messages appended in the order they were sent.
    pub sent_messages: Vec<SentMessage>,
}

// ── Drain ─────────────────────────────────────────────────────────────────────

/// Let pending events propagate: sleep briefly, then poll each participant
/// twice so in-flight ATProto records reach both sides.
pub async fn drain_events(alice: &MoatCliClient, bob: &MoatCliClient) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..2 {
        let _ = alice.poll().await;
        let _ = bob.poll().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Invariant checkers ────────────────────────────────────────────────────────

/// Every sent message with a confirmed ID appears in both participants' lists.
pub async fn check_delivery(
    alice: &MoatCliClient,
    bob: &MoatCliClient,
    state: &ScenarioState,
) -> Result<()> {
    let alice_msgs = alice.get_messages(&state.group_id).await?;
    let bob_msgs = bob.get_messages(&state.group_id).await?;

    for sent in &state.sent_messages {
        let Some(ref mid) = sent.message_id else {
            continue;
        };
        let in_alice = alice_msgs.iter().any(|m| m.message_id.as_deref() == Some(mid));
        let in_bob = bob_msgs.iter().any(|m| m.message_id.as_deref() == Some(mid));

        if !in_alice {
            anyhow::bail!(
                "Delivery: {:?} (id={mid}) missing from Alice's view",
                sent.text
            );
        }
        if !in_bob {
            anyhow::bail!(
                "Delivery: {:?} (id={mid}) missing from Bob's view",
                sent.text
            );
        }
    }
    Ok(())
}

/// After drain, Alice and Bob see the same sequence of message contents.
///
/// moat-cli sorts its message cache by `StoredMessage::timestamp` before
/// returning, giving a globally consistent view.  Own messages are stamped at
/// send time; received messages carry the publisher's `created_at`.  Because
/// test actions are sequential the timestamps are strictly monotonic, so both
/// participants converge on the same total order after drain.
pub async fn check_consensus_ordering(
    alice: &MoatCliClient,
    bob: &MoatCliClient,
    state: &ScenarioState,
) -> Result<()> {
    let alice_msgs = alice.get_messages(&state.group_id).await?;
    let bob_msgs = bob.get_messages(&state.group_id).await?;

    let alice_contents: Vec<&str> = alice_msgs.iter().map(|m| m.content.as_str()).collect();
    let bob_contents: Vec<&str> = bob_msgs.iter().map(|m| m.content.as_str()).collect();

    if alice_contents != bob_contents {
        anyhow::bail!(
            "Consensus ordering violated:\n  Alice: {:?}\n  Bob:   {:?}",
            alice_contents,
            bob_contents,
        );
    }
    Ok(())
}

/// For each sender, their messages appear in the same relative order in both
/// participants' views, and that order matches the order they were sent.
///
/// This is a weaker version of [`check_consensus_ordering`] that doesn't
/// require a globally consistent interleaving across senders.
pub async fn check_per_sender_ordering(
    alice: &MoatCliClient,
    bob: &MoatCliClient,
    state: &ScenarioState,
) -> Result<()> {
    let alice_msgs = alice.get_messages(&state.group_id).await?;
    let bob_msgs = bob.get_messages(&state.group_id).await?;

    for sender in [ParticipantId::ALICE, ParticipantId::BOB] {
        // Ground-truth: IDs of confirmed messages from this sender, in send order.
        let sent_ids: Vec<String> = state
            .sent_messages
            .iter()
            .filter(|m| m.from == sender)
            .filter_map(|m| m.message_id.clone())
            .collect();

        if sent_ids.is_empty() {
            continue;
        }

        // Relative order of this sender's messages in each participant's view.
        let alice_order: Vec<&str> = alice_msgs
            .iter()
            .filter_map(|m| m.message_id.as_deref())
            .filter(|id| sent_ids.iter().any(|s| s == id))
            .collect();

        let bob_order: Vec<&str> = bob_msgs
            .iter()
            .filter_map(|m| m.message_id.as_deref())
            .filter(|id| sent_ids.iter().any(|s| s == id))
            .collect();

        // Both views must agree on this sender's message order.
        if alice_order != bob_order {
            anyhow::bail!(
                "Per-sender ordering violated for {:?}:\n  Alice sees: {:?}\n  Bob sees:   {:?}",
                sender,
                alice_order,
                bob_order,
            );
        }

        // The agreed order must also match the original send order.
        let sent_refs: Vec<&str> = sent_ids.iter().map(|s| s.as_str()).collect();
        if alice_order != sent_refs {
            anyhow::bail!(
                "Send order violated for {:?}:\n  Send order: {:?}\n  Both see:   {:?}",
                sender,
                sent_refs,
                alice_order,
            );
        }
    }
    Ok(())
}

/// No participant's message list contains the same message ID more than once.
pub async fn check_no_duplicates(
    alice: &MoatCliClient,
    bob: &MoatCliClient,
    state: &ScenarioState,
) -> Result<()> {
    for (name, client) in [("Alice", alice), ("Bob", bob)] {
        let msgs = client.get_messages(&state.group_id).await?;
        let mut seen = std::collections::HashSet::new();
        for msg in &msgs {
            if let Some(ref mid) = msg.message_id {
                if !seen.insert(mid.clone()) {
                    anyhow::bail!("No-duplicates: {name} has duplicate message_id {mid}");
                }
            }
        }
    }
    Ok(())
}

// ── N-participant invariant checkers ─────────────────────────────────────────

/// Let pending events propagate across N participants.
pub async fn drain_events_n(clients: &[&MoatCliClient]) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..2 {
        for client in clients {
            let _ = client.poll().await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Every sent message with a confirmed ID appears in all participants' lists.
pub async fn check_delivery_n(
    clients: &[&MoatCliClient],
    state: &ScenarioState,
) -> Result<()> {
    let mut all_msgs = Vec::new();
    for (i, client) in clients.iter().enumerate() {
        let msgs = client.get_messages(&state.group_id).await?;
        all_msgs.push((i, msgs));
    }

    for sent in &state.sent_messages {
        let Some(ref mid) = sent.message_id else {
            continue;
        };
        for (i, msgs) in &all_msgs {
            let found = msgs.iter().any(|m| m.message_id.as_deref() == Some(mid));
            if !found {
                anyhow::bail!(
                    "Delivery: {:?} (id={mid}) missing from participant {i}'s view",
                    sent.text
                );
            }
        }
    }
    Ok(())
}

/// After drain, all participants see the same sequence of message contents.
pub async fn check_consensus_ordering_n(
    clients: &[&MoatCliClient],
    state: &ScenarioState,
) -> Result<()> {
    let mut contents_per_client: Vec<Vec<String>> = Vec::new();
    for client in clients {
        let msgs = client.get_messages(&state.group_id).await?;
        contents_per_client.push(msgs.into_iter().map(|m| m.content).collect());
    }

    let first = &contents_per_client[0];
    for (i, contents) in contents_per_client.iter().enumerate().skip(1) {
        if contents != first {
            anyhow::bail!(
                "Consensus ordering violated between participant 0 and {i}:\n  0: {:?}\n  {i}: {:?}",
                first,
                contents,
            );
        }
    }
    Ok(())
}

/// No participant's message list contains the same message ID more than once.
pub async fn check_no_duplicates_n(
    clients: &[&MoatCliClient],
    state: &ScenarioState,
) -> Result<()> {
    for (i, client) in clients.iter().enumerate() {
        let msgs = client.get_messages(&state.group_id).await?;
        let mut seen = std::collections::HashSet::new();
        for msg in &msgs {
            if let Some(ref mid) = msg.message_id {
                if !seen.insert(mid.clone()) {
                    anyhow::bail!("No-duplicates: participant {i} has duplicate message_id {mid}");
                }
            }
        }
    }
    Ok(())
}
