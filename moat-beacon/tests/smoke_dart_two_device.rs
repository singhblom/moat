use moat_beacon::scenarios::dart_two_device_bootstrap;

// Phase C moved same-user ring add to BootstrapKp events.  Dart's FFI
// tick() doesn't yet pass `sibling_stealth` through (it hardcodes `&[]`),
// so neither Dart device publishes a bootstrap KP and the smaller-id
// device's ring-add stalls.  Phase G adds the FFI field + FRB regen +
// Dart wiring.  See `proptest_multi_device.rs` for the matching note.
#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[tokio::test]
async fn dart_two_device_bootstrap() {
    dart_two_device_bootstrap::run(true).await;
}
