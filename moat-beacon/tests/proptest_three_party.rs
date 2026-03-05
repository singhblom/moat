//! Property-based three-party scenario (polling).
//!
//! Alice creates a group with Bob, adds Carol, then `proptest` generates random
//! action sequences across all three participants. Uses `action_sequence_3p()`
//! which generates `ParticipantId(0..3)`.
//!
//! Fixed prologue:
//!   1. Login Alice, Bob, Carol.
//!   2. Bob + Carol watch Alice.
//!   3. Alice starts conversation with Bob.
//!   4. Bob polls to join.
//!   5. Alice adds Carol.
//!   6. Carol polls to join, Bob polls to receive Commit.
//!
//! After actions: drain, check delivery + consensus ordering + no duplicates.

use moat_beacon::actions::action_sequence_3p;
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
    fn three_party_random_actions(actions in action_sequence_3p()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_chat::run(actions, false));
    }
}
