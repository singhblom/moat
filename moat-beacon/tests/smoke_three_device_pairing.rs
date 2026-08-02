//! Smoke test for the three-device live pairing scenario.
//!
//! Intentionally red: `moat-core::pairing::PairingSession` is unimplemented
//! and moat-cli's `/pair/*` HTTP endpoints don't exist yet.

use moat_beacon::scenarios::three_device_pairing;

#[tokio::test]
async fn three_device_pairing_converges() {
    three_device_pairing::run(true).await;
}
