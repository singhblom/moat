//! Push latency scenario — Alice runs the Rust CLI, Bob runs the Dart server.
//!
//! Verifies that a mixed Rust+Dart topology delivers messages within the
//! latency deadline via Drawbridge without any polling.

use crate::config::{ParticipantConfig, WorldConfig};
use crate::world::{ParticipantKind, TestWorld};

use super::push_latency::run_with_world;

pub async fn run(verbose: bool) {
    let config = WorldConfig {
        participants: vec![
            ParticipantConfig {
                handle: "alice",
                kind: ParticipantKind::RustCli,
                relay_label: Some("alice"),
            },
            ParticipantConfig {
                handle: "bob",
                kind: ParticipantKind::DartServer,
                relay_label: Some("bob"),
            },
        ],
    };
    let world = TestWorld::from_config(&config, ".postern.test")
        .await
        .expect("world setup (rust + dart + drawbridge)");
    run_with_world(world, "mixed-push-latency", verbose).await;
}
