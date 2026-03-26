//! Config-driven three-party Drawbridge push delivery scenario.
//!
//! The topology (relay assignment, participant kinds) is determined by a
//! [`WorldConfig`].  After the prologue, auto-polling is disabled on all
//! participants with a relay; delivery must arrive via Drawbridge push.
//!
//! The `run_boxed` wrapper uses a default config (all-Rust, separate relays)
//! for the scenario registry; the proptest calls `run` directly with a
//! generated config.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::actions::Action;
use crate::config::WorldConfig;
use crate::invariants::{
    check_consensus_ordering_n, check_delivery_n, check_no_duplicates_n, ScenarioState,
};
use crate::world::TestWorld;

use super::two_party_push::drain_events_push;
use super::{execute_action_n, format_action, vlog};

/// Registry-compatible wrapper: uses the default 3-party push topology.
pub(crate) fn run_boxed(
    actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let config = WorldConfig::default_3p_push();
    Box::pin(run(config, actions, verbose))
}

pub async fn run(config: WorldConfig, actions: Vec<Action>, verbose: bool) {
    vlog!(
        verbose,
        "=== Scenario: three-party-push (config: {}) ===",
        config
    );

    let n = config.participant_count();
    let push_mode = config.push_mode();
    let handle_suffix = ".postern.test";

    // ── Build world from config ──────────────────────────────────────────────
    vlog!(verbose, "[setup] starting TestWorld from config...");
    let mut world = TestWorld::from_config(&config, handle_suffix)
        .await
        .expect("world setup from config");

    // Collect clients and full handles.
    let client_owned: Vec<_> = config
        .participants
        .iter()
        .map(|p| world.client(p.handle).clone())
        .collect();
    let clients: Vec<&_> = client_owned.iter().collect();
    let full_handles: Vec<String> = config
        .participants
        .iter()
        .map(|p| format!("{}{handle_suffix}", p.handle))
        .collect();
    let handles: Vec<&str> = full_handles.iter().map(|s| s.as_str()).collect();

    // ── Login all participants ────────────────────────────────────────────────
    for (client, handle) in clients.iter().zip(handles.iter()) {
        client
            .login(handle, "any-password")
            .await
            .unwrap_or_else(|e| panic!("{handle} login failed: {e}"));
        vlog!(verbose, "[setup] login {handle}... done");
    }

    // ── Wait for Drawbridge connections ──────────────────────────────────────
    if push_mode {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let mut all_connected = true;
            for client in &clients {
                let status = client.status().await.expect("participant status");
                if !status.drawbridge_connected {
                    all_connected = false;
                    break;
                }
            }
            if all_connected {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let mut summary = Vec::new();
                for (i, client) in clients.iter().enumerate() {
                    let connected = client
                        .status()
                        .await
                        .map(|s| s.drawbridge_connected)
                        .unwrap_or(false);
                    summary.push(format!("{}={connected}", config.participants[i].handle));
                }
                panic!("Drawbridge not connected after 5s ({})", summary.join(", "));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        vlog!(verbose, "[setup] Drawbridge connections established");
    }

    // ── Watches: everyone watches participant 0 (Alice) ──────────────────────
    for client in clients.iter().skip(1) {
        client
            .watch_handle(handles[0])
            .await
            .expect("watch first participant");
    }

    // ── Start conversation: Alice invites Bob ────────────────────────────────
    let group_id = clients[0]
        .start_conversation(handles[1])
        .await
        .expect("start conversation");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stats = clients[1].poll().await.expect("bob join poll");
    assert!(
        stats.new_conversations > 0,
        "Bob should have joined the group"
    );

    // ── Add remaining participants (Carol, ...) ──────────────────────────────
    for i in 2..n {
        clients[0]
            .add_member(&group_id, handles[i])
            .await
            .unwrap_or_else(|e| panic!("add {} failed: {e}", handles[i]));

        tokio::time::sleep(Duration::from_millis(500)).await;

        let stats = clients[i].poll().await.expect("new member join poll");
        assert!(
            stats.new_conversations > 0,
            "{} should have joined the group",
            handles[i]
        );
        // Existing members pick up the epoch commit.
        for j in 1..i {
            let _ = clients[j].poll().await;
        }
    }

    // Exchange DrawbridgeHints: one poll round picks up reciprocal hints.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for client in &clients {
        let _ = client.poll().await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Disable auto-polling — delivery must come via Drawbridge push.
    if push_mode {
        for client in &clients {
            client
                .set_poll_interval(0)
                .await
                .expect("disable polling");
        }
        vlog!(verbose, "[setup] polling disabled (push-only mode)");
    }

    // ── Random action sequence ───────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    let mut state = ScenarioState {
        group_id,
        sent_messages: vec![],
    };

    let total = actions.len();
    for (i, action) in actions.iter().enumerate() {
        vlog!(
            verbose,
            "[action {}/{}] {}",
            i + 1,
            total,
            format_action(action)
        );
        execute_action_n(
            action,
            &clients,
            &mut world,
            &handles,
            push_mode,
            &mut state,
            verbose,
        )
        .await;
    }

    // ── Drain + invariants ───────────────────────────────────────────────────
    if verbose {
        eprintln!();
    }
    vlog!(verbose, "[drain] waiting for push events to propagate...");
    drain_events_push(clients[0], clients[1]).await;

    let confirmed = state
        .sent_messages
        .iter()
        .filter(|m| m.message_id.is_some())
        .count();

    check_delivery_n(&clients, &state)
        .await
        .expect("delivery invariant violated");
    vlog!(verbose, "[check] delivery... ok ({confirmed} messages)");

    check_consensus_ordering_n(&clients, &state)
        .await
        .expect("consensus ordering invariant violated");
    vlog!(verbose, "[check] consensus ordering... ok");

    check_no_duplicates_n(&clients, &state)
        .await
        .expect("no-duplicates invariant violated");
    vlog!(verbose, "[check] no duplicates... ok");

    if verbose {
        eprintln!();
        eprintln!("=== PASSED ===");
    }
}
