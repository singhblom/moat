//! Smoke test for the two-device live pairing scenario, Dart + Dart.

use moat_beacon::scenarios::two_device_pairing_dd;

#[tokio::test]
async fn two_device_pairing_dd_converges() {
    two_device_pairing_dd::run(true).await;
}
