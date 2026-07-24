use moat_beacon::scenarios::three_device_staggered;
use moat_beacon::world::ParticipantKind::{DartServer as D, RustCli as R};

#[tokio::test]
async fn three_device_staggered_rrr() {
    three_device_staggered::run(R, R, R, true).await;
}

// Cells involving a Dart participant are #[ignore] pending Phase G, matching
// the Dart cells in proptest_multi_device.rs.  The FFI tick() shim hardcodes
// `sibling_stealth: &[]`, so Dart devices never publish bootstrap KPs and the
// ring never forms around them.
#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[tokio::test]
async fn three_device_staggered_ddd() {
    three_device_staggered::run(D, D, D, true).await;
}

#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[tokio::test]
async fn three_device_staggered_drr() {
    three_device_staggered::run(D, R, R, true).await;
}

#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[tokio::test]
async fn three_device_staggered_rrd() {
    three_device_staggered::run(R, R, D, true).await;
}
