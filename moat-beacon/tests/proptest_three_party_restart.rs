//! Property-based three-party scenario with offline/online cycles (polling).
//!
//! Uses `action_sequence_3p_with_offline()` to generate sequences that include
//! `GoOffline` / `ComeOnline` transitions across three participants.

use moat_beacon::actions::action_sequence_3p_with_offline;
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
    fn three_party_restart_actions(actions in action_sequence_3p_with_offline()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_restart::run(actions, false));
    }
}
