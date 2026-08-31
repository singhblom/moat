//! Smoke test for the cancelled-pairing scenario.

use moat_beacon::scenarios::pairing_cancelled;

#[tokio::test]
async fn pairing_cancelled_leaves_no_ring() {
    pairing_cancelled::run(true).await;
}
