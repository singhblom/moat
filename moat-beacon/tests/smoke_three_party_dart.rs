//! 3-party smoke test with all participants running the Dart server.
//!
//! Mirrors `smoke_three_party.rs` but uses `ParticipantKind::DartServer` for all three.

use moat_beacon::world::{ParticipantKind, TestWorld};
use std::time::Duration;

#[tokio::test]
async fn three_party_conversation_dart() {
    let world = TestWorld::new_with_kinds(
        &["alice", "bob", "carol"],
        &[
            ParticipantKind::DartServer,
            ParticipantKind::DartServer,
            ParticipantKind::DartServer,
        ],
        ".postern.test",
    )
    .await
    .expect("world setup");

    let alice = world.client("alice");
    let bob = world.client("bob");
    let carol = world.client("carol");

    // --- Login all three ---
    alice
        .login("alice.postern.test", "any-password")
        .await
        .expect("alice login");
    bob.login("bob.postern.test", "any-password")
        .await
        .expect("bob login");
    carol
        .login("carol.postern.test", "any-password")
        .await
        .expect("carol login");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Bob and Carol watch Alice for invites ---
    bob.watch_handle("alice.postern.test")
        .await
        .expect("bob watch alice");
    carol
        .watch_handle("alice.postern.test")
        .await
        .expect("carol watch alice");

    // --- Alice starts conversation with Bob ---
    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation with bob");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bob polls to receive the Welcome
    let stats = bob.poll().await.expect("bob first poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have received Alice's Welcome (got {stats:?})"
    );

    // --- Alice adds Carol to the group ---
    alice
        .add_member(&group_id, "carol.postern.test")
        .await
        .expect("alice add carol");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Carol polls to receive the Welcome
    let stats = carol.poll().await.expect("carol first poll");
    assert!(
        stats.new_conversations > 0,
        "Carol should have received Alice's Welcome (got {stats:?})"
    );

    // Bob polls to receive the Commit (epoch advance)
    let _stats = bob.poll().await.expect("bob second poll");

    // --- Verify member lists ---
    let carol_convs = carol
        .list_conversations()
        .await
        .expect("carol list convos");
    let carol_conv = carol_convs
        .iter()
        .find(|c| c.id == group_id)
        .expect("Carol should have the conversation");
    assert!(
        carol_conv.participant_dids.len() >= 2,
        "Carol should see at least 2 participants (Alice + Bob), got {:?}",
        carol_conv.participant_dids
    );

    let bob_convs = bob.list_conversations().await.expect("bob list convos");
    let bob_conv = bob_convs
        .iter()
        .find(|c| c.id == group_id)
        .expect("Bob should have the conversation");
    assert!(
        bob_conv.participant_dids.len() >= 2,
        "Bob should see at least 2 participants (Alice + Carol), got {:?}",
        bob_conv.participant_dids
    );

    // --- Verify conversation names contain all member handles ---
    let alice_convs = alice
        .list_conversations()
        .await
        .expect("alice list convos");
    let alice_conv = alice_convs
        .iter()
        .find(|c| c.id == group_id)
        .expect("Alice should have the conversation");
    assert!(
        alice_conv.name.contains("bob") && alice_conv.name.contains("carol"),
        "Alice's conversation name should contain both 'bob' and 'carol', got: {:?}",
        alice_conv.name
    );

    assert!(
        bob_conv.name.contains("alice") && bob_conv.name.contains("carol"),
        "Bob's conversation name should contain both 'alice' and 'carol', got: {:?}",
        bob_conv.name
    );

    assert!(
        carol_conv.name.contains("alice") && carol_conv.name.contains("bob"),
        "Carol's conversation name should contain both 'alice' and 'bob', got: {:?}",
        carol_conv.name
    );

    // --- All three send messages ---
    alice
        .send_message(&group_id, "hello from alice")
        .await
        .expect("alice send");

    tokio::time::sleep(Duration::from_millis(200)).await;
    bob.poll().await.expect("bob poll alice msg");
    carol.poll().await.expect("carol poll alice msg");

    let bob_msgs = bob.get_messages(&group_id).await.expect("bob get msgs");
    assert!(
        bob_msgs.iter().any(|m| m.content.contains("hello from alice")),
        "Bob should see Alice's message; got: {bob_msgs:?}"
    );

    let carol_msgs = carol
        .get_messages(&group_id)
        .await
        .expect("carol get msgs");
    assert!(
        carol_msgs
            .iter()
            .any(|m| m.content.contains("hello from alice")),
        "Carol should see Alice's message; got: {carol_msgs:?}"
    );

    bob.send_message(&group_id, "hey from bob")
        .await
        .expect("bob send");

    tokio::time::sleep(Duration::from_millis(200)).await;
    alice.poll().await.expect("alice poll bob msg");
    carol.poll().await.expect("carol poll bob msg");

    let alice_msgs = alice
        .get_messages(&group_id)
        .await
        .expect("alice get msgs");
    assert!(
        alice_msgs
            .iter()
            .any(|m| m.content.contains("hey from bob")),
        "Alice should see Bob's message; got: {alice_msgs:?}"
    );
    let carol_msgs = carol
        .get_messages(&group_id)
        .await
        .expect("carol get msgs after bob");
    assert!(
        carol_msgs
            .iter()
            .any(|m| m.content.contains("hey from bob")),
        "Carol should see Bob's message; got: {carol_msgs:?}"
    );

    carol
        .send_message(&group_id, "hi from carol")
        .await
        .expect("carol send");

    tokio::time::sleep(Duration::from_millis(200)).await;
    alice.poll().await.expect("alice poll carol msg");
    bob.poll().await.expect("bob poll carol msg");

    let alice_msgs = alice
        .get_messages(&group_id)
        .await
        .expect("alice get msgs after carol");
    assert!(
        alice_msgs
            .iter()
            .any(|m| m.content.contains("hi from carol")),
        "Alice should see Carol's message; got: {alice_msgs:?}"
    );
    let bob_msgs = bob
        .get_messages(&group_id)
        .await
        .expect("bob get msgs after carol");
    assert!(
        bob_msgs
            .iter()
            .any(|m| m.content.contains("hi from carol")),
        "Bob should see Carol's message; got: {bob_msgs:?}"
    );
}
