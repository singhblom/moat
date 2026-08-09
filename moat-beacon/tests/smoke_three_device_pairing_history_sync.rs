//! Smoke test for the three-device pairing history-sync scenario.

use moat_beacon::scenarios::three_device_pairing_history_sync;

#[tokio::test]
async fn three_device_pairing_history_sync_converges() {
    three_device_pairing_history_sync::run(true).await;
}
