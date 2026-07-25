use moat_beacon::scenarios::dart_two_device_bootstrap;

#[tokio::test]
async fn dart_two_device_bootstrap() {
    dart_two_device_bootstrap::run(true).await;
}
