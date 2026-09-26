//! Smoke test for the three-device pairing history-sync scenario, existing
//! device (D1) on Dart, new devices (D2/D3) on Rust.

use moat_beacon::scenarios::three_device_pairing_history_sync_rd;

#[tokio::test]
async fn three_device_pairing_history_sync_rd_converges() {
    three_device_pairing_history_sync_rd::run(true).await;
}
