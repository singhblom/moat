//! Smoke test: as `smoke_sender_exceeds_tag_window`, with a Dart recipient
//! on the poll path and across a restart.

use moat_beacon::scenarios::sender_exceeds_tag_window;

#[tokio::test]
async fn sender_exceeds_tag_window_d_converges() {
    sender_exceeds_tag_window::run_dart_recipient(true).await;
}
