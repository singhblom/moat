use moat_beacon::scenarios::dart_two_device_history_sync;

// See `smoke_two_device_history.rs` for the Phase 6 note — same flake.
#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn dart_two_device_history_sync() {
    dart_two_device_history_sync::run(true).await;
}
