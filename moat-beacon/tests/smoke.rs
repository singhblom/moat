//! Phase 1 smoke test: Alice sends a message, Bob polls and receives it.
//!
//! This test exercises the full stack:
//!   Postern (in-process PDS) → moat-cli --http (Alice) → moat-cli --http (Bob)
//!
//! No Drawbridge or Toxiproxy is involved at this phase.

use moat_beacon::world::TestWorld;

/// Alice starts a conversation with Bob, sends a message, and Bob
/// receives it after a poll.
#[tokio::test]
async fn alice_sends_bob_receives() {
    // Spin up Postern + two moat-cli --http processes.
    let world = TestWorld::new(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup");

    let alice = world.client("alice");
    let bob = world.client("bob");

    // --- Login ---------------------------------------------------------------
    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");

    // After login, moat-cli generates a key package and stealth address and
    // publishes them to Postern. Wait briefly for that to complete.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // --- Bob watches Alice so her events are included in polls ---------------
    // Without this Bob's poll fetches nothing (he has no conversations yet and
    // hasn't subscribed to Alice's event feed).
    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");

    // --- Alice starts conversation with Bob ----------------------------------
    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");

    // Wait briefly for Alice's Welcome + Commit to propagate to Postern.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // --- Bob polls to receive the Welcome ------------------------------------
    let stats = bob.poll().await.expect("bob first poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have received Alice's Welcome (got {stats:?})"
    );

    // --- Alice sends a message -----------------------------------------------
    alice
        .send_message(&group_id, "hello from alice")
        .await
        .expect("alice send message");

    // --- Bob polls to receive the message ------------------------------------
    let stats = bob.poll().await.expect("bob second poll");
    assert!(
        stats.new_messages > 0,
        "Bob should have received Alice's message (got {stats:?})"
    );

    // --- Verify Bob can read the message ------------------------------------
    let bobs_convs = bob.list_conversations().await.expect("bob list convos");
    let bob_conv = bobs_convs
        .iter()
        .find(|c| c.id == group_id)
        .expect("Bob should have the conversation");

    let messages = bob
        .get_messages(&bob_conv.id)
        .await
        .expect("bob get messages");

    let found = messages.iter().any(|m| m.content.contains("hello from alice"));
    assert!(found, "Bob's messages should contain Alice's text; got: {messages:?}");
}
