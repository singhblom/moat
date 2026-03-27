//! Ground-truth state and invariant checkers for beacon scenarios.
//!
//! `ScenarioState` is accumulated during action execution and used by the
//! invariant checkers after all participants have been drained.

use crate::actions::ParticipantId;
use crate::client::{Message, MoatCliClient};
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
    /// Participants who were group members at the time this message was sent.
    /// Used for membership-aware delivery checks.  `None` means "all
    /// participants" (backwards-compatible with scenarios that don't track
    /// membership).
    pub members_at_send: Option<Vec<ParticipantId>>,
}

/// Accumulated ground-truth for one scenario run.
pub struct ScenarioState {
    pub group_id: String,
    /// Messages appended in the order they were sent.
    pub sent_messages: Vec<SentMessage>,
    /// Current group members (indices into the client slice).  `None` means
    /// membership is not tracked and all clients are assumed to be members.
    pub members: Option<Vec<ParticipantId>>,
}

// ── Drain ─────────────────────────────────────────────────────────────────────

/// Let pending events propagate: sleep briefly, then poll each participant
/// twice so in-flight ATProto records reach both sides.
pub async fn drain_events(alice: &MoatCliClient, bob: &MoatCliClient) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..2 {
        let _ = tokio::join!(alice.poll(), bob.poll());
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
    let (alice_msgs, bob_msgs) = tokio::try_join!(
        alice.get_messages(&state.group_id),
        bob.get_messages(&state.group_id)
    )?;

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
    let (alice_msgs, bob_msgs) = tokio::try_join!(
        alice.get_messages(&state.group_id),
        bob.get_messages(&state.group_id)
    )?;

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
    let (alice_msgs, bob_msgs) = tokio::try_join!(
        alice.get_messages(&state.group_id),
        bob.get_messages(&state.group_id)
    )?;

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
    let (alice_msgs, bob_msgs) = tokio::try_join!(
        alice.get_messages(&state.group_id),
        bob.get_messages(&state.group_id)
    )?;
    for (name, msgs) in [("Alice", alice_msgs), ("Bob", bob_msgs)] {
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

/// Fetch messages for all N clients concurrently.
///
/// Returns a `Vec<(index, messages)>` sorted by index so callers can index
/// by participant position.
async fn fetch_all_messages(
    clients: &[&MoatCliClient],
    group_id: &str,
) -> Result<Vec<(usize, Vec<Message>)>> {
    let mut join_set: tokio::task::JoinSet<Result<(usize, Vec<Message>)>> =
        tokio::task::JoinSet::new();
    for (i, &client) in clients.iter().enumerate() {
        let client = client.clone();
        let group_id = group_id.to_string();
        join_set.spawn(async move {
            let msgs = client.get_messages(&group_id).await?;
            Ok((i, msgs))
        });
    }
    let mut results = Vec::with_capacity(clients.len());
    while let Some(res) = join_set.join_next().await {
        results.push(res??);
    }
    results.sort_by_key(|(i, _)| *i);
    Ok(results)
}

/// Let pending events propagate across N participants.
pub async fn drain_events_n(clients: &[&MoatCliClient]) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..2 {
        let mut join_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        for &client in clients {
            let client = client.clone();
            join_set.spawn(async move { let _ = client.poll().await; });
        }
        while join_set.join_next().await.is_some() {}
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Every sent message with a confirmed ID appears in the message lists of all
/// participants who were group members when it was sent.
///
/// If `members_at_send` is `None` on a message, all participants are checked
/// (backwards-compatible with scenarios that don't track membership).
pub async fn check_delivery_n(
    clients: &[&MoatCliClient],
    state: &ScenarioState,
) -> Result<()> {
    let all_msgs = fetch_all_messages(clients, &state.group_id).await?;

    // When membership is tracked, only check delivery for current members.
    // Removed participants may not have received messages even if they were
    // members at send time (e.g. removed before draining).
    let current_members: Option<Vec<usize>> = state
        .members
        .as_ref()
        .map(|ms| ms.iter().map(|m| m.ordinal()).collect());

    for sent in &state.sent_messages {
        let Some(ref mid) = sent.message_id else {
            continue;
        };
        for (i, msgs) in &all_msgs {
            // Skip participants who aren't current members.
            if let Some(ref current) = current_members {
                if !current.contains(i) {
                    continue;
                }
            }
            // Skip participants who weren't members when this message was sent.
            if let Some(ref members) = sent.members_at_send {
                if !members.iter().any(|m| m.ordinal() == *i) {
                    continue;
                }
            }
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
///
/// When membership tracking is active (`members_at_send` present), only
/// messages that ALL current members witnessed are compared for ordering.
/// Messages from before a participant joined or after they were removed are
/// excluded from the consensus check.
pub async fn check_consensus_ordering_n(
    clients: &[&MoatCliClient],
    state: &ScenarioState,
) -> Result<()> {
    // Determine which participants to check (current members, or all if not tracking)
    let check_indices: Vec<usize> = match &state.members {
        Some(members) => members.iter().map(|m| m.ordinal()).collect(),
        None => (0..clients.len()).collect(),
    };

    if check_indices.len() < 2 {
        return Ok(()); // Need at least 2 members to compare ordering
    }

    // Collect message IDs that ALL checked participants should have seen
    let common_mids: Vec<&str> = state
        .sent_messages
        .iter()
        .filter_map(|sent| {
            let mid = sent.message_id.as_deref()?;
            // If membership is tracked, only include messages where all
            // checked participants were members at send time.
            if let Some(ref members) = sent.members_at_send {
                let all_present = check_indices
                    .iter()
                    .all(|&idx| members.iter().any(|m| m.ordinal() == idx));
                if !all_present {
                    return None;
                }
            }
            Some(mid)
        })
        .collect();

    if common_mids.is_empty() {
        return Ok(()); // No common messages to compare
    }

    // For each checked participant, extract the relative order of common messages
    let all_msgs = fetch_all_messages(clients, &state.group_id).await?;
    let mut orders: Vec<Vec<String>> = Vec::new();
    for &idx in &check_indices {
        let msgs = &all_msgs[idx].1;
        let order: Vec<String> = msgs
            .iter()
            .filter_map(|m| m.message_id.as_deref())
            .filter(|mid| common_mids.contains(mid))
            .map(|s| s.to_string())
            .collect();
        orders.push(order);
    }

    let first = &orders[0];
    for (pos, order) in orders.iter().enumerate().skip(1) {
        if order != first {
            anyhow::bail!(
                "Consensus ordering violated between participant {} and {}:\n  {}: {:?}\n  {}: {:?}",
                check_indices[0],
                check_indices[pos],
                check_indices[0],
                first,
                check_indices[pos],
                order,
            );
        }
    }
    Ok(())
}

/// For each sender, their messages appear in the same relative order in all
/// participants' views, and that order matches the original send order.
///
/// N-participant version of [`check_per_sender_ordering`].
pub async fn check_per_sender_ordering_n(
    clients: &[&MoatCliClient],
    state: &ScenarioState,
) -> Result<()> {
    let all_msgs_indexed = fetch_all_messages(clients, &state.group_id).await?;
    let all_msgs: Vec<&Vec<Message>> = all_msgs_indexed.iter().map(|(_, m)| m).collect();

    // Check ordering for each sender
    let max_participant = clients.len();
    for sender_idx in 0..max_participant {
        let sender = ParticipantId(sender_idx);
        let sent_ids: Vec<String> = state
            .sent_messages
            .iter()
            .filter(|m| m.from == sender)
            .filter_map(|m| m.message_id.clone())
            .collect();

        if sent_ids.is_empty() {
            continue;
        }

        let sent_refs: Vec<&str> = sent_ids.iter().map(|s| s.as_str()).collect();

        // Collect each participant's view of this sender's messages
        let mut orders: Vec<Vec<&str>> = Vec::new();
        for msgs in &all_msgs {
            let order: Vec<&str> = msgs
                .iter()
                .filter_map(|m| m.message_id.as_deref())
                .filter(|id| sent_ids.iter().any(|s| s == id))
                .collect();
            orders.push(order);
        }

        // All views must agree
        for (i, order) in orders.iter().enumerate().skip(1) {
            if order != &orders[0] {
                anyhow::bail!(
                    "Per-sender ordering violated for sender {sender_idx}:\n  Participant 0: {:?}\n  Participant {i}: {:?}",
                    orders[0],
                    order,
                );
            }
        }

        // The agreed order must match send order
        if orders[0] != sent_refs {
            anyhow::bail!(
                "Send order violated for sender {sender_idx}:\n  Send order: {:?}\n  All see:    {:?}",
                sent_refs,
                orders[0],
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
    let all_msgs = fetch_all_messages(clients, &state.group_id).await?;
    for (i, msgs) in &all_msgs {
        let mut seen = std::collections::HashSet::new();
        for msg in msgs {
            if let Some(ref mid) = msg.message_id {
                if !seen.insert(mid.clone()) {
                    anyhow::bail!("No-duplicates: participant {i} has duplicate message_id {mid}");
                }
            }
        }
    }
    Ok(())
}
