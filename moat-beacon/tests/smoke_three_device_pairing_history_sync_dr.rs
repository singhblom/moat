//! Smoke test for the three-device pairing history-sync scenario, new
//! devices (D2/D3) on Dart, existing device (D1) on Rust.

use moat_beacon::scenarios::three_device_pairing_history_sync_dr;

#[tokio::test]
async fn three_device_pairing_history_sync_dr_converges() {
    three_device_pairing_history_sync_dr::run(true).await;
}
