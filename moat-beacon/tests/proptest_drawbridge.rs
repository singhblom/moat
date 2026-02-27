//! Phase 4: property-based two-party scenario using Drawbridge push delivery.
//!
//! The test structure mirrors `proptest_two_party`, but:
//!   - `TestWorld::new_with_drawbridge` is used so each moat-cli process is
//!     started with `--drawbridge-url`.
//!   - After the fixed prologue, polling is disabled on all participants via
//!     `POST /poll/0`.  Any message delivery must arrive via the Drawbridge
//!     push path (`new_event` → `spawn_targeted_fetch`), not auto-polling.
//!   - `drain_events_push` sleeps briefly (instead of explicitly polling) to
//!     let push-triggered fetches complete.
//!
//! Fixed prologue:
//!   1. Login Alice + Bob.
//!   2. Bob watches Alice.
//!   3. Alice starts a conversation with Bob.
//!   4. Poll once to exchange Welcomes and Drawbridge hints.
//!   5. Disable auto-polling on both participants.
//!
//! Invariants checked after drain:
//!   - Delivery         — every confirmed message ID appears in both views.
//!   - Consensus order  — Alice and Bob see the same message sequence.
//!   - No duplicates    — no participant has a repeated message ID.

use moat_beacon::actions::action_sequence;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
        )),
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_party_push_delivery(actions in action_sequence()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::two_party_push::run(actions, false));
    }
}
