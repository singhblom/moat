//! Smoke test for the staggered three-device pairing scenario.

use moat_beacon::scenarios::staggered_device_pairing;

#[tokio::test]
async fn staggered_device_pairing_converges() {
    staggered_device_pairing::run(true).await;
}
