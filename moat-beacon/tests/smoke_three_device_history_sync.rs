use moat_beacon::scenarios::three_device_history_sync;
use moat_beacon::world::ParticipantKind::{DartServer as D, RustCli as R};

#[tokio::test]
async fn three_device_history_sync_rrr() {
    three_device_history_sync::run(R, R, R, true).await;
}

#[tokio::test]
async fn three_device_history_sync_ddd() {
    three_device_history_sync::run(D, D, D, true).await;
}

#[tokio::test]
async fn three_device_history_sync_drr() {
    three_device_history_sync::run(D, R, R, true).await;
}

#[tokio::test]
async fn three_device_history_sync_rrd() {
    three_device_history_sync::run(R, R, D, true).await;
}
