//! Property-based two-party scenario with both participants running the Dart server.
//!
//! Both Alice and Bob run `moat_dart_server --http`.  The same action strategies
//! and invariants as the Rust two-party scenario are used, verifying that the
//! Dart implementation is functionally equivalent.

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
    fn dart_two_party_random_actions(actions in action_sequence()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::dart_two_party_chat::run(actions, false));
    }
}
