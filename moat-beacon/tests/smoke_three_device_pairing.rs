//! Smoke test for the three-device live pairing scenario.

use moat_beacon::scenarios::three_device_pairing;

#[tokio::test]
async fn three_device_pairing_converges() {
    three_device_pairing::run(true).await;
}
