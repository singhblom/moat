//! Property-based cross-implementation two-party scenario.
//!
//! Alice runs `moat-cli --http` (Rust) and Bob runs `moat_dart_server --http`
//! (Dart).  Tests that MLS interoperability works across the language boundary:
//! key packages, stealth addresses, Welcome messages, and encrypted message
//! delivery all function correctly when one side is Rust and the other Dart.

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
    fn mixed_two_party_random_actions(actions in action_sequence()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::mixed_two_party_chat::run(actions, false));
    }
}
