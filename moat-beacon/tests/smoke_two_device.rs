use moat_beacon::scenarios::two_device_bootstrap;

#[tokio::test]
async fn two_device_bootstrap() {
    two_device_bootstrap::run(true).await;
}
