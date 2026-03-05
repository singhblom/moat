//! Property-based three-party scenario (Drawbridge push delivery).
//!
//! Same as `proptest_three_party` but uses Drawbridge for push-based delivery.
//! Requires Go toolchain for Drawbridge binary.

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
    fn three_party_push_actions(actions in action_sequence_3p()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_push::run(actions, false));
    }
}
