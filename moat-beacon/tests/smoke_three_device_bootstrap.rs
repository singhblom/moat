use moat_beacon::scenarios::three_device_bootstrap;
use moat_beacon::world::ParticipantKind::{DartServer as D, RustCli as R};

#[tokio::test]
async fn three_device_bootstrap_rrr() {
    three_device_bootstrap::run(R, R, R, true).await;
}

#[tokio::test]
async fn three_device_bootstrap_rrd() {
    three_device_bootstrap::run(R, R, D, true).await;
}

#[tokio::test]
async fn three_device_bootstrap_rdr() {
    three_device_bootstrap::run(R, D, R, true).await;
}

#[tokio::test]
async fn three_device_bootstrap_drr() {
    three_device_bootstrap::run(D, R, R, true).await;
}

#[tokio::test]
async fn three_device_bootstrap_rdd() {
    three_device_bootstrap::run(R, D, D, true).await;
}

#[tokio::test]
async fn three_device_bootstrap_drd() {
    three_device_bootstrap::run(D, R, D, true).await;
}

#[tokio::test]
async fn three_device_bootstrap_ddr() {
    three_device_bootstrap::run(D, D, R, true).await;
}

#[tokio::test]
async fn three_device_bootstrap_ddd() {
    three_device_bootstrap::run(D, D, D, true).await;
}
