//! Smoke test for delivery after same-user fan-out, both devices on Rust.

use moat_beacon::scenarios::post_fan_out_delivery;

#[tokio::test]
async fn post_fan_out_delivery_converges() {
    post_fan_out_delivery::run(true).await;
}
