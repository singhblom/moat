//! Smoke test: requested history sync still works after the device ring
//! has sat idle through more than one tag window of ticks (all Rust).

use moat_beacon::scenarios::sync_request_history;

#[tokio::test]
async fn sync_request_after_idle_converges() {
    sync_request_history::run_after_idle(true).await;
}
