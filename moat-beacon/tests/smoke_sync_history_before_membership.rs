//! Smoke test: history served for a conversation the requester is not in.

use moat_beacon::scenarios::sync_history_before_membership;

#[tokio::test]
async fn history_arrives_before_membership() {
    sync_history_before_membership::run(true).await;
}
