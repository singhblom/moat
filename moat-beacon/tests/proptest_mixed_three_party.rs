//! Property-based three-party scenario with mixed participants: Alice (Rust), Bob + Carol (Dart).

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
    fn mixed_three_party_random_actions(actions in action_sequence_3p()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::mixed_three_party_chat::run(actions, false));
    }
}
