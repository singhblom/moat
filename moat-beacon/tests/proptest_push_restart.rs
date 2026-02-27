//! Phase 6: property-based two-party scenario with offline/online cycles (Drawbridge push).
//!
//! Uses `action_sequence_with_offline()` to generate sequences that include
//! `GoOffline` / `ComeOnline` transitions.  Verifies that MLS state survives
//! restarts and that messages sent while offline are delivered after
//! reconnecting to Drawbridge.
//!
//! Fixed prologue:
//!   1. Login Alice + Bob.
//!   2. Bob watches Alice.
//!   3. Alice starts a conversation with Bob.
//!   4. Poll once to exchange Welcomes and Drawbridge hints.
//!   5. Disable auto-polling on both participants (push-only mode).
//!
//! After the action sequence:
//!   - Any offline participants are brought back online (with polling re-disabled).
//!   - `drain_events_push` lets push-triggered fetches complete.
//!   - Three invariants are checked: delivery, consensus ordering, no duplicates.

use moat_beacon::actions::action_sequence_with_offline;
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
    fn two_party_push_restart_actions(actions in action_sequence_with_offline()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::two_party_push_restart::run(actions, false));
    }
}
