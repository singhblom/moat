use moat_beacon::scenarios::two_device_history_sync;

#[tokio::test]
async fn two_device_history_sync() {
    two_device_history_sync::run(true).await;
}
