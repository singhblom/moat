use moat_beacon::scenarios::mixed_two_device_bootstrap;

#[tokio::test]
async fn mixed_two_device_bootstrap_rust_first() {
    mixed_two_device_bootstrap::run(false, true).await;
}

#[tokio::test]
async fn mixed_two_device_bootstrap_dart_first() {
    mixed_two_device_bootstrap::run(true, true).await;
}
