//! Smoke test: as `smoke_watched_before_welcome`, with the joiner on Dart.

use moat_beacon::scenarios::watched_before_welcome;

#[tokio::test]
async fn watched_before_welcome_d_converges() {
    watched_before_welcome::run_dart_joiner(true).await;
}
