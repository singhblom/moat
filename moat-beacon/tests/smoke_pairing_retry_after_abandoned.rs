//! Smoke test for retrying a pairing that was abandoned at the approval prompt.

use moat_beacon::scenarios::pairing_retry_after_abandoned;

#[tokio::test]
async fn pairing_retry_after_abandoned_succeeds() {
    pairing_retry_after_abandoned::run(true).await;
}
