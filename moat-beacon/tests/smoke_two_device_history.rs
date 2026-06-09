use moat_beacon::scenarios::two_device_history_sync;

// Ignored: depends on the device with prior history (d1) being the ring
// offerer. With random `device_id` allocation, d2 is the offerer roughly
// half the time, and the current static-leaf-0-streams-history rule then
// sends the (empty) joiner's history backwards. Phase 6 introduces
// bidirectional sync, at which point this test becomes reliable.
// See `moat-beacon/src/scenarios/two_device_history_sync.rs` for the full
// note; see `MULTI_DEVICE.md` Phase 6 for the planned fix.
#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn two_device_history_sync() {
    two_device_history_sync::run(true).await;
}
