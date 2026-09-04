//! Smoke test for the requested-sync scenario (dr runtime mix).

use moat_beacon::scenarios::sync_request_history_dr;

#[tokio::test]
async fn sync_request_delivers_missing_history_dr() {
    sync_request_history_dr::run(true).await;
}
