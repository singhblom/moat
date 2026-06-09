use moat_beacon::scenarios::mixed_two_device_history_sync;

// See `smoke_two_device_history.rs` for the Phase 6 note — this scenario
// shares the same offerer-direction flake.
#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn mixed_two_device_history_sync_rd() {
    mixed_two_device_history_sync::run(false, true).await;
}

#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn mixed_two_device_history_sync_dr() {
    mixed_two_device_history_sync::run(true, true).await;
}
