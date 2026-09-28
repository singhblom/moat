/// FCM dispatch integration test.
///
/// Verifies that Drawbridge in recording mode:
/// - Sends FCM pushes to offline devices.
/// - Suppresses pushes while the device socket is live.
/// - Suppresses pushes within the 10 s reconnect grace window.
#[test]
fn fcm_dispatch() {
    let _slot = moat_beacon::parallel::world_slot(super::WORLDS);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(moat_beacon::scenarios::fcm_dispatch::run(false));
}
