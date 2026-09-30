//! A user whose two devices sit on different relays hears every event on
//! both, by push alone.
//!
//! Alice's devices sit on two Drawbridges (D2 on a2, having paired across them)
//! and Bob on a third. With polling off everywhere, Bob's message must reach
//! both of Alice's devices, and each of Alice's devices must reach the other.
//!
//! Parametrised over d1_kind × d2_kind (Bob is the Rust CLI).

use std::time::{Duration, Instant};

use crate::client::MoatCliClient;
use crate::scenarios::push_latency::wait_for_message;
use crate::world::{ParticipantKind, TestWorld};

const ALICE_HANDLE: &str = "alice.postern.test";
const BOB_HANDLE: &str = "bob.postern.test";
const ALICE_DID: &str = "did:plc:alice";
const PUSH_DEADLINE: Duration = Duration::from_secs(10);
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

pub async fn run(d1_kind: ParticipantKind, d2_kind: ParticipantKind, cell: &str, verbose: bool) {
    macro_rules! vlog {
        ($($t:tt)*) => { if verbose { eprintln!($($t)*); } }
    }

    vlog!("=== Scenario: multi-drawbridge-push ({cell}) ===");

    let mut world = TestWorld::new_with_kinds_and_drawbridge(
        &[("alice", "a1"), ("bob", "b")],
        &[d1_kind, ParticipantKind::RustCli],
        ".postern.test",
    )
    .await
    .expect("world setup");
    world.add_drawbridge("a2").await.expect("add Drawbridge a2");

    let d1 = world.client("alice").clone();
    let bob = world.client("bob").clone();
    let d2 = world
        .spawn_nth_device_on_drawbridge("alice-d2", d2_kind, "a2")
        .await
        .expect("spawn alice-d2");

    d1.login(ALICE_HANDLE, "any-password").await.expect("d1 login");
    d2.login(ALICE_HANDLE, "any-password").await.expect("d2 login");
    bob.login(BOB_HANDLE, "any-password").await.expect("bob login");

    // D2 shows its code and D1 goes to D2's Drawbridge, a2.
    vlog!("[setup] pairing d2 into d1's ring across a1 and a2...");
    crate::scenarios::three_device_pairing::pair_devices(&d1, &d2, verbose).await;

    // The conversation reads each device's Drawbridge when it starts, so D2's
    // record must be there first.
    wait_for_drawbridge_records(&world, &["a1", "a2"]).await;

    d1.watch_handle(BOB_HANDLE).await.expect("d1 watch bob");
    bob.watch_handle(ALICE_HANDLE).await.expect("bob watch alice");
    let group_id = d1.start_conversation(BOB_HANDLE).await.expect("start conversation");
    vlog!("[setup] group_id = {group_id}");

    wait_until("bob receives the Welcome", || async {
        let _ = bob.poll().await;
        !bob.list_conversations().await.unwrap_or_default().is_empty()
    })
    .await;
    wait_until("d2 joins the conversation", || async {
        let _ = d1.ring_tick().await;
        let _ = d2.ring_tick().await;
        let _ = d1.poll().await;
        let _ = d2.poll().await;
        let _ = bob.poll().await;
        d2.list_conversations()
            .await
            .unwrap_or_default()
            .iter()
            .any(|c| c.id == group_id)
    })
    .await;

    // Bob takes the Commit that added D2 before he writes, or his message is
    // from an epoch D2 never held.
    let _ = bob.poll().await;

    // Push alone from here on.
    for c in [&d1, &d2, &bob] {
        c.set_poll_interval(0).await.expect("disable polling");
    }
    wait_until("all three on their relays", || async {
        for c in [&d1, &d2, &bob] {
            if !c.status().await.map(|s| s.drawbridge_connected).unwrap_or(false) {
                return false;
            }
        }
        true
    })
    .await;

    vlog!("[check] bob -> alice's two devices");
    assert_delivered(&bob, &[&d1, &d2], &group_id, "from bob").await;
    vlog!("[check] d1 -> d2");
    assert_delivered(&d1, &[&d2, &bob], &group_id, "from d1").await;
    vlog!("[check] d2 -> d1");
    assert_delivered(&d2, &[&d1, &bob], &group_id, "from d2").await;

    vlog!("\n=== PASSED ===");
}

/// `sender` sends `text`; every one of `receivers` must show it by push.
async fn assert_delivered(
    sender: &MoatCliClient,
    receivers: &[&MoatCliClient],
    group_id: &str,
    text: &str,
) {
    sender.send_message(group_id, text).await.expect("send");
    for (i, r) in receivers.iter().enumerate() {
        assert!(
            wait_for_message(r, group_id, text, PUSH_DEADLINE).await.is_some(),
            "receiver {i} never got {text:?} by push within {PUSH_DEADLINE:?}"
        );
    }
}

/// Wait until Alice's `drawbridgeConfig` records name exactly the relays
/// labelled `labels`.
async fn wait_for_drawbridge_records(world: &TestWorld, labels: &[&str]) {
    let mut want: Vec<String> = labels.iter().map(|l| world.drawbridge_endpoint(l).to_string()).collect();
    want.sort();
    let url = format!(
        "{}/xrpc/com.atproto.repo.listRecords?repo={ALICE_DID}&collection=social.moat.drawbridgeConfig",
        world.postern_url()
    );
    wait_until("alice's relay records", || async {
        let Ok(resp) = reqwest::get(&url).await else { return false };
        let Ok(body) = resp.json::<serde_json::Value>().await else { return false };
        let mut have: Vec<String> = body["records"]
            .as_array()
            .map(|rs| {
                rs.iter()
                    .filter_map(|r| r["value"]["url"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        have.sort();
        have == want
    })
    .await;
}

async fn wait_until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        if check().await {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
