//! Smoke test: the offering device runs Dart.

use moat_beacon::scenarios::sync_offer_history_dr;

#[tokio::test]
async fn dart_offers_history_without_prompting_the_recipient() {
    sync_offer_history_dr::run(true).await;
}
