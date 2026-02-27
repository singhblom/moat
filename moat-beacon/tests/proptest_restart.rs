//! Phase 6: property-based two-party scenario with offline/online cycles (polling).
//!
//! Uses `action_sequence_with_offline()` to generate sequences that include
//! `GoOffline` / `ComeOnline` transitions.  Verifies that MLS state, conversation
//! membership, and key material survive process restarts, and that messages sent
//! while a participant was offline are delivered after they come back via polling.
//!
//! Fixed prologue:
//!   1. Login Alice + Bob.
//!   2. Bob watches Alice.
//!   3. Alice starts a conversation with Bob.
//!   4. Bob polls to join (receives the MLS Welcome).
//!
//! After the action sequence:
//!   - Any offline participants are brought back online.
//!   - `drain_events` lets everything propagate.
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
    fn two_party_restart_actions(actions in action_sequence_with_offline()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::two_party_restart::run(actions, false));
    }
}
