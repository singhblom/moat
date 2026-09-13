//! Smoke test for delivery after same-user fan-out, new device on Rust,
//! existing device on Dart.

use moat_beacon::scenarios::post_fan_out_delivery;

#[tokio::test]
async fn post_fan_out_delivery_rd_converges() {
    post_fan_out_delivery::run_rd(true).await;
}
