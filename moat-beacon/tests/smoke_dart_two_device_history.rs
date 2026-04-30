use moat_beacon::scenarios::dart_two_device_history_sync;

#[tokio::test]
async fn dart_two_device_history_sync() {
    dart_two_device_history_sync::run(true).await;
}
