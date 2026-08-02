//! Smoke test for the three-device pairing history-sync scenario.
//!
//! Intentionally red: `moat-core::pairing::PairingSession` is unimplemented,
//! moat-cli's `/pair/*` HTTP endpoints don't exist yet, and the
//! `PairingCommand::StartSync` handoff to `SyncSession` isn't wired.

use moat_beacon::scenarios::three_device_pairing_history_sync;

#[tokio::test]
async fn three_device_pairing_history_sync_converges() {
    three_device_pairing_history_sync::run(true).await;
}
