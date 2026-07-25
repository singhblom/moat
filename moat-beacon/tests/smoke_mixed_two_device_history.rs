use moat_beacon::scenarios::mixed_two_device_history_sync;

#[tokio::test]
async fn mixed_two_device_history_sync_rd() {
    mixed_two_device_history_sync::run(false, true).await;
}

#[tokio::test]
async fn mixed_two_device_history_sync_dr() {
    mixed_two_device_history_sync::run(true, true).await;
}
