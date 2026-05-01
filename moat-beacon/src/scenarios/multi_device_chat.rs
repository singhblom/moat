//! Multi-device random-action scenario.
//!
//! Alice has two devices (D1, D2) that bootstrap a device ring and then
//! receive a random sequence of actions. Bob is a fixed second user present
//! to provide a real user conversation. The scenario ends with a convergence
//! drain and invariant checks.
//!
//! Parametrised over d1_kind × d2_kind so the same logic covers all four
//! runtime cells (RR, RD, DR, DD).
//!
//! Invariants verified after the epilogue drain:
//! - D1 and D2 share the same non-null ring group ID.
//! - Ring and coord groups do not appear in either device's conversation list.
//! - Every message with a confirmed message_id is visible on both D1 and D2.

use std::time::Duration;

use crate::actions::{MultiDeviceAction, TEXT_VOCAB};
use crate::world::{ParticipantKind, TestWorld};

struct SentMsg {
    message_id: Option<String>,
}

pub async fn run(
    d1_kind: ParticipantKind,
    d2_kind: ParticipantKind,
    actions: Vec<MultiDeviceAction>,
    verbose: bool,
) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!(
        "=== multi-device-chat (d1={d1_kind:?} d2={d2_kind:?}, {} actions) ===",
        actions.len()
    );

    // ── Prologue ──────────────────────────────────────────────────────────────
    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "alice"), ("bob", "bob")],
        &[d1_kind, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");

    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();

    d1.login("alice.postern.test", "any-password").await.expect("d1 login");
    bob.login("bob.postern.test", "any-password").await.expect("bob login");

    tokio::time::sleep(Duration::from_millis(800)).await;

    d1.watch_handle("bob.postern.test").await.expect("d1 watch bob");
    bob.watch_handle("alice.postern.test").await.expect("bob watch alice");

    let group_id = d1
        .start_conversation("bob.postern.test")
        .await
        .expect("start conversation");
    vlog!("[setup] group_id = {group_id}");

    for _ in 0..5 {
        let s = bob.poll().await.expect("bob poll");
        if s.new_conversations > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Spawn D2 and login.
    let d2 = world
        .spawn_second_device("alice-d2", d2_kind)
        .await
        .expect("spawn alice-d2");
    d2.login("alice.postern.test", "any-password").await.expect("d2 login");
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Ring bootstrap.
    for i in 0..6 {
        vlog!("[bootstrap {i}]");
        d1.ring_tick().await.expect("d1 ring_tick");
        d2.ring_tick().await.expect("d2 ring_tick");
        d1.poll().await.expect("d1 poll");
        d2.poll().await.expect("d2 poll");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    {
        let s1 = d1.ring_status().await.expect("d1 ring_status post-bootstrap");
        let s2 = d2.ring_status().await.expect("d2 ring_status post-bootstrap");
        assert!(
            s1.ring_group_id.is_some(),
            "d1 must have a ring after bootstrap (coord_count={})",
            s1.coord_group_count
        );
        assert_eq!(
            s1.ring_group_id, s2.ring_group_id,
            "ring must match after bootstrap"
        );
    }

    // ── Random actions ────────────────────────────────────────────────────────
    let mut online = [true, true]; // [D1, D2]
    let mut sent: Vec<SentMsg> = vec![];

    for action in &actions {
        vlog!("  {action:?}");
        match action {
            MultiDeviceAction::SendUserMessage { device, text_idx } => {
                let d = *device;
                if !online[d] {
                    continue;
                }
                let text = TEXT_VOCAB[text_idx % TEXT_VOCAB.len()];
                let client = if d == 0 { &d1 } else { &d2 };
                if client.send_message(&group_id, text).await.is_ok() {
                    let message_id = client
                        .get_messages(&group_id)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .rev()
                        .find(|m| m.is_own && m.content.contains(text))
                        .and_then(|m| m.message_id);
                    sent.push(SentMsg { message_id });
                }
            }
            MultiDeviceAction::Poll { device } => {
                if online[*device] {
                    let client = if *device == 0 { &d1 } else { &d2 };
                    let _ = client.poll().await;
                }
            }
            MultiDeviceAction::RingTick { device } => {
                if online[*device] {
                    let client = if *device == 0 { &d1 } else { &d2 };
                    let _ = client.ring_tick().await;
                }
            }
            MultiDeviceAction::GoOffline { device } => {
                let d = *device;
                if online[d] {
                    // Brief pause so any in-flight PDS publish can complete.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let name = if d == 0 { "alice" } else { "alice-d2" };
                    world.kill_participant(name).expect("kill participant");
                    online[d] = false;
                    vlog!("  device {d} offline");
                }
            }
            MultiDeviceAction::ComeOnline { device } => {
                let d = *device;
                if !online[d] {
                    let name = if d == 0 { "alice" } else { "alice-d2" };
                    world.restart_participant(name).await.expect("restart participant");
                    let client = if d == 0 { &d1 } else { &d2 };
                    client
                        .login("alice.postern.test", "any-password")
                        .await
                        .expect("re-login");
                    client.watch_handle("bob.postern.test").await.ok();
                    let _ = client.poll().await;
                    online[d] = true;
                    vlog!("  device {d} online");
                }
            }
            MultiDeviceAction::WaitMs { ms } => {
                tokio::time::sleep(Duration::from_millis(*ms)).await;
            }
        }
    }

    // ── Epilogue: bring both devices online ───────────────────────────────────
    for d in 0..2usize {
        if !online[d] {
            let name = if d == 0 { "alice" } else { "alice-d2" };
            world
                .restart_participant(name)
                .await
                .expect("restart for epilogue");
            let client = if d == 0 { &d1 } else { &d2 };
            client
                .login("alice.postern.test", "any-password")
                .await
                .expect("re-login epilogue");
            client.watch_handle("bob.postern.test").await.ok();
            let _ = client.poll().await;
        }
    }

    // Ring drain + add-device propagation.
    for i in 0..8 {
        vlog!("[drain {i}]");
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        let _ = bob.poll().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Trigger history sync and allow the batch exchange to complete.
    let _ = d1.sync_start().await;
    let _ = d2.sync_start().await;

    let confirmed: Vec<String> = sent
        .iter()
        .filter_map(|s| s.message_id.clone())
        .collect();

    for cycle in 0..12 {
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        if confirmed.is_empty() {
            break;
        }
        let d2_msgs = d2.get_messages(&group_id).await.unwrap_or_default();
        let all_present = confirmed.iter().all(|mid| {
            d2_msgs.iter().any(|m| m.message_id.as_deref() == Some(mid.as_str()))
        });
        if all_present {
            vlog!("[sync cycle {cycle}] d2 has all messages");
            break;
        }
        vlog!("[sync cycle {cycle}] d2 has {}/{}", d2_msgs.len(), confirmed.len());
    }

    // ── Invariants ────────────────────────────────────────────────────────────
    let s1 = d1.ring_status().await.expect("d1 final ring_status");
    let s2 = d2.ring_status().await.expect("d2 final ring_status");

    assert!(
        s1.ring_group_id.is_some(),
        "d1 must have a ring group after drain"
    );
    assert_eq!(
        s1.ring_group_id, s2.ring_group_id,
        "d1 and d2 must share the same ring group"
    );

    let convs1 = d1.list_conversations().await.expect("d1 list_conversations");
    let convs2 = d2.list_conversations().await.expect("d2 list_conversations");
    assert!(
        convs1.len() <= 1,
        "d1 conversation list must not contain ring/coord groups; got {convs1:?}"
    );
    assert!(
        convs2.len() <= 1,
        "d2 conversation list must not contain ring/coord groups; got {convs2:?}"
    );

    if !confirmed.is_empty() {
        let d1_msgs = d1.get_messages(&group_id).await.expect("d1 get_messages");
        let d2_msgs = d2.get_messages(&group_id).await.expect("d2 get_messages");

        for mid in &confirmed {
            assert!(
                d1_msgs.iter().any(|m| m.message_id.as_deref() == Some(mid.as_str())),
                "d1 missing message {mid} after drain"
            );
            assert!(
                d2_msgs.iter().any(|m| m.message_id.as_deref() == Some(mid.as_str())),
                "d2 missing message {mid} after drain"
            );
        }
        vlog!("[check] {} confirmed messages on both devices", confirmed.len());
    }

    vlog!("[check] ring convergence ok");
    if verbose {
        eprintln!("\n=== PASSED ===");
    }
}
