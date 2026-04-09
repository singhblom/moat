/// FCM dispatch integration test.
///
/// Verifies that Drawbridge in recording mode:
/// - Sends FCM pushes to offline devices.
/// - Suppresses pushes while the device socket is live.
/// - Suppresses pushes within the 10 s reconnect grace window.
///
/// This is a single deterministic scenario (no proptest random generation),
/// wrapped in the proptest file naming convention for consistency.
#[test]
fn fcm_dispatch() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(moat_beacon::scenarios::fcm_dispatch::run(false));
}
