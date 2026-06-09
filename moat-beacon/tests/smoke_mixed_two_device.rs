use moat_beacon::scenarios::mixed_two_device_bootstrap;

// See `smoke_dart_two_device.rs` for the Phase G note — Dart's FFI
// doesn't yet publish bootstrap KPs, so any mixed-runtime ring add
// where the Rust adder needs Dart's KP stalls.
#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[tokio::test]
async fn mixed_two_device_bootstrap_rust_first() {
    mixed_two_device_bootstrap::run(false, true).await;
}

#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[tokio::test]
async fn mixed_two_device_bootstrap_dart_first() {
    mixed_two_device_bootstrap::run(true, true).await;
}
