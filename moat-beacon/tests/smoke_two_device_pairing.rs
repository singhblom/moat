//! Smoke test for the two-device live pairing scenario.
//!
//! Intentionally red: `moat-core::pairing::PairingSession` is unimplemented
//! and moat-cli's `/pair/*` HTTP endpoints don't exist yet.

use moat_beacon::scenarios::two_device_pairing;

#[tokio::test]
async fn two_device_pairing_converges() {
    two_device_pairing::run(true).await;
}
