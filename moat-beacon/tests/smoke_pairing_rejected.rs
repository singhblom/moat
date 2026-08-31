//! Smoke test for the rejected-pairing scenario.

use moat_beacon::scenarios::pairing_rejected;

#[tokio::test]
async fn pairing_rejected_leaves_no_ring() {
    pairing_rejected::run(true).await;
}
