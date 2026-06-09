use moat_beacon::scenarios::three_device_history_sync;
use moat_beacon::world::ParticipantKind::{DartServer as D, RustCli as R};

// See `smoke_two_device_history.rs` for the Phase 6 note. With three
// devices the offerer-direction flake is worse: history needs to flow
// from whichever device(s) have it to the new device, not from
// whichever happens to be ring creator.
#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn three_device_history_sync_rrr() {
    three_device_history_sync::run(R, R, R, true).await;
}

#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn three_device_history_sync_ddd() {
    three_device_history_sync::run(D, D, D, true).await;
}

#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn three_device_history_sync_drr() {
    three_device_history_sync::run(D, R, R, true).await;
}

#[ignore = "flaky pending Phase 6 bidirectional sync"]
#[tokio::test]
async fn three_device_history_sync_rrd() {
    three_device_history_sync::run(R, R, D, true).await;
}
