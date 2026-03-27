//! Push latency scenario — both participants run the Dart server.
//!
//! Identical to `push_latency` but uses `ParticipantKind::DartServer` for
//! both Alice and Bob.  Verifies that the Dart Drawbridge client actually
//! delivers messages within the latency deadline without any polling.

use crate::config::{ParticipantConfig, WorldConfig};
use crate::world::{ParticipantKind, TestWorld};

use super::push_latency::run_with_world;

pub async fn run(verbose: bool) {
    let config = WorldConfig {
        participants: vec![
            ParticipantConfig {
                handle: "alice",
                kind: ParticipantKind::DartServer,
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
        .expect("world setup (dart + dart + drawbridge)");
    run_with_world(world, "dart-push-latency", verbose).await;
}
