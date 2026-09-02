//! Smoke test for the user-initiated sync-request scenario.

use moat_beacon::scenarios::sync_request_history;

#[tokio::test]
async fn sync_request_delivers_missing_history() {
    sync_request_history::run(true).await;
}
