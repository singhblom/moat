//! Smoke test for the lost-device pairing scenario — the regression
//! statement of `qr-pairing.md`'s premise: pairing (and history recovery)
//! must keep working with the original device permanently gone.

use moat_beacon::scenarios::lost_device_pairing;

#[tokio::test]
async fn lost_device_pairing_recovers() {
    lost_device_pairing::run(true).await;
}
