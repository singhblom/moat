//! Smoke test: a joiner (Rust) that read a watched contact's messages before
//! holding the Welcome still receives them after joining.

use moat_beacon::scenarios::watched_before_welcome;

#[tokio::test]
async fn watched_before_welcome_converges() {
    watched_before_welcome::run(true).await;
}
