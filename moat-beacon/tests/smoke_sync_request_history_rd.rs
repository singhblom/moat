//! Smoke test for the requested-sync scenario (rd runtime mix).

use moat_beacon::scenarios::sync_request_history_rd;

#[tokio::test]
async fn sync_request_delivers_missing_history_rd() {
    sync_request_history_rd::run(true).await;
}
