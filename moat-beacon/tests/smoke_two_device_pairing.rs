//! Smoke test for the two-device live pairing scenario (Rust + Rust).

use moat_beacon::scenarios::two_device_pairing;

#[tokio::test]
async fn two_device_pairing_converges() {
    two_device_pairing::run(true).await;
}
