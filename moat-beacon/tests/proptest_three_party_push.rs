//! Combinatorial property-based three-party push delivery test.
//!
//! Generates a random `WorldConfig` (relay topology, participant kinds) and a
//! random action sequence, then runs the three-party push scenario with that
//! configuration.  Requires Go toolchain for Drawbridge binary.

use moat_beacon::actions::action_sequence_n;
use moat_beacon::config::world_config_3p;
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
    fn three_party_push_combinatorial(
        (config, actions) in world_config_3p().prop_flat_map(|config| {
            let n = config.participant_count();
            (Just(config), action_sequence_n(n))
        })
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_push::run(config, actions, false));
    }
}
