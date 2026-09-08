//! Smoke test: history offered by the device that has it.

use moat_beacon::scenarios::sync_offer_history;

#[tokio::test]
async fn offered_history_is_accepted_without_a_prompt() {
    sync_offer_history::run(true).await;
}
