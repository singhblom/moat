//! Smoke test for the two-device live pairing scenario, new=Rust existing=Dart.

use moat_beacon::scenarios::two_device_pairing_rd;

#[tokio::test]
async fn two_device_pairing_rd_converges() {
    two_device_pairing_rd::run(true).await;
}
