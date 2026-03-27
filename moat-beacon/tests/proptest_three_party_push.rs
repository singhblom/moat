//! Combinatorial property-based three-party push delivery test.
//!
//! Generates a random `WorldConfig` (relay topology, participant kinds) and a
//! random action sequence with membership changes (`AddMember`, `RemoveMember`),
//! then runs the three-party push scenario with that configuration.
//!
//! The prologue only adds Alice and Bob to the group. Carol (and any other
//! participants) join via `AddMember` actions in the random sequence.
//!
//! Requires Go toolchain for Drawbridge binary.

use moat_beacon::actions::{action_sequence_n, action_sequence_with_membership};
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

    /// Test with membership changes: only Alice+Bob start in the group,
    /// Carol joins/leaves via AddMember/RemoveMember actions.
    #[test]
    fn three_party_push_membership(
        (config, actions) in world_config_3p().prop_flat_map(|config| {
            let n = config.participant_count();
            // Initial members: Alice (0) and Bob (1)
            let initial = vec![0, 1];
            (Just(config), action_sequence_with_membership(n, &initial))
        })
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_push::run(config, actions, true));
    }

    /// Test without membership changes: all 3 participants added in prologue.
    /// Exercises topology variation (relay patterns, participant kinds) with
    /// the standard 3-party action sequence.
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
