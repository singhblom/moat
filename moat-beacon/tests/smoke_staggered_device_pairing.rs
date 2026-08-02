//! Smoke test for the staggered three-device pairing scenario.
//!
//! Intentionally red: `moat-core::pairing::PairingSession` is unimplemented
//! and moat-cli's `/pair/*` HTTP endpoints don't exist yet.

use moat_beacon::scenarios::staggered_device_pairing;

#[tokio::test]
async fn staggered_device_pairing_converges() {
    staggered_device_pairing::run(true).await;
}
