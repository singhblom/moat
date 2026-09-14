//! Smoke test: a Rust recipient keeps receiving past one candidate-tag
//! window of messages from a single sender, by poll and by push.

use moat_beacon::scenarios::sender_exceeds_tag_window;

#[tokio::test]
async fn sender_exceeds_tag_window_converges() {
    sender_exceeds_tag_window::run(true).await;
}
