//! 3-party smoke test with mixed participants: Alice (Rust CLI), Bob + Carol (Dart server).
//!
//! Verifies that the Rust CLI's add-member flow is compatible with Dart participants
//! receiving Welcomes and Commits.

use moat_beacon::world::{ParticipantKind, TestWorld};
use std::time::Duration;

#[tokio::test]
async fn three_party_conversation_mixed() {
    let world = TestWorld::new_with_kinds(
        &["alice", "bob", "carol"],
        &[
            ParticipantKind::RustCli,
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

    // --- Alice (Rust) starts conversation with Bob (Dart) ---
    let group_id = alice
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation with bob");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = bob.poll().await.expect("bob first poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have received Alice's Welcome (got {stats:?})"
    );

    // --- Alice (Rust) adds Carol (Dart) to the group ---
    alice
        .add_member(&group_id, "carol.postern.test")
        .await
        .expect("alice add carol");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = carol.poll().await.expect("carol first poll");
    assert!(
        stats.new_conversations > 0,
        "Carol should have received Alice's Welcome (got {stats:?})"
    );

    // Bob polls to receive the Commit
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
        "Carol should see at least 2 participants, got {:?}",
        carol_conv.participant_dids
    );

    let bob_convs = bob.list_conversations().await.expect("bob list convos");
    let bob_conv = bob_convs
        .iter()
        .find(|c| c.id == group_id)
        .expect("Bob should have the conversation");
    assert!(
        bob_conv.participant_dids.len() >= 2,
        "Bob should see at least 2 participants, got {:?}",
        bob_conv.participant_dids
    );

    // --- Verify display names ---
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
        "Alice's conv name should contain 'bob' and 'carol', got: {:?}",
        alice_conv.name
    );
    assert!(
        bob_conv.name.contains("alice") && bob_conv.name.contains("carol"),
        "Bob's conv name should contain 'alice' and 'carol', got: {:?}",
        bob_conv.name
    );
    assert!(
        carol_conv.name.contains("alice") && carol_conv.name.contains("bob"),
        "Carol's conv name should contain 'alice' and 'bob', got: {:?}",
        carol_conv.name
    );

    // --- All three send messages ---
    alice
        .send_message(&group_id, "hello from alice")
        .await
        .expect("alice send");

    tokio::time::sleep(Duration::from_millis(200)).await;
    bob.poll().await.expect("bob poll");
    carol.poll().await.expect("carol poll");

    let bob_msgs = bob.get_messages(&group_id).await.expect("bob msgs");
    assert!(
        bob_msgs.iter().any(|m| m.content.contains("hello from alice")),
        "Bob should see Alice's message; got: {bob_msgs:?}"
    );
    let carol_msgs = carol.get_messages(&group_id).await.expect("carol msgs");
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
    alice.poll().await.expect("alice poll");
    carol.poll().await.expect("carol poll");

    let alice_msgs = alice.get_messages(&group_id).await.expect("alice msgs");
    assert!(
        alice_msgs.iter().any(|m| m.content.contains("hey from bob")),
        "Alice should see Bob's message; got: {alice_msgs:?}"
    );

    carol
        .send_message(&group_id, "hi from carol")
        .await
        .expect("carol send");

    tokio::time::sleep(Duration::from_millis(200)).await;
    alice.poll().await.expect("alice poll carol");
    bob.poll().await.expect("bob poll carol");

    let alice_msgs = alice.get_messages(&group_id).await.expect("alice msgs");
    assert!(
        alice_msgs.iter().any(|m| m.content.contains("hi from carol")),
        "Alice should see Carol's message; got: {alice_msgs:?}"
    );
    let bob_msgs = bob.get_messages(&group_id).await.expect("bob msgs");
    assert!(
        bob_msgs.iter().any(|m| m.content.contains("hi from carol")),
        "Bob should see Carol's message; got: {bob_msgs:?}"
    );
}
