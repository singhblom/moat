//! Smoke test for the requested-sync scenario (dd runtime mix).

use moat_beacon::scenarios::sync_request_history_dd;

#[tokio::test]
async fn sync_request_delivers_missing_history_dd() {
    sync_request_history_dd::run(true).await;
}
