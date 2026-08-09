//! Smoke test for the two-device live pairing scenario, new=Dart existing=Rust.

use moat_beacon::scenarios::two_device_pairing_dr;

#[tokio::test]
async fn two_device_pairing_dr_converges() {
    two_device_pairing_dr::run(true).await;
}
