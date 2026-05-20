use moat_beacon::scenarios::three_device_staggered;
use moat_beacon::world::ParticipantKind::{DartServer as D, RustCli as R};

#[tokio::test]
async fn three_device_staggered_rrr() {
    three_device_staggered::run(R, R, R, true).await;
}

#[tokio::test]
async fn three_device_staggered_ddd() {
    three_device_staggered::run(D, D, D, true).await;
}

#[tokio::test]
async fn three_device_staggered_drr() {
    three_device_staggered::run(D, R, R, true).await;
}

#[tokio::test]
async fn three_device_staggered_rrd() {
    three_device_staggered::run(R, R, D, true).await;
}
