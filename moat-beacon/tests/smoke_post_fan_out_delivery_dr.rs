//! Smoke test for delivery after same-user fan-out, new device on Dart,
//! existing device on Rust.

use moat_beacon::scenarios::post_fan_out_delivery;

#[tokio::test]
async fn post_fan_out_delivery_dr_converges() {
    post_fan_out_delivery::run_dr(true).await;
}
