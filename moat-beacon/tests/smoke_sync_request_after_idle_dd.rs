//! Smoke test: as `smoke_sync_request_after_idle`, with both of Alice's
//! devices on Dart.

use moat_beacon::scenarios::sync_request_history;

#[tokio::test]
async fn sync_request_after_idle_dd_converges() {
    sync_request_history::run_after_idle_dd(true).await;
}
