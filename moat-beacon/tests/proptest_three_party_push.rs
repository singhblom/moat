use moat_beacon::actions::{
    action_sequence_with_membership_and_offline, action_sequence_with_offline_n,
};
use moat_beacon::config::world_config_3p;
use proptest::prelude::*;

#[test]
fn three_party_push_membership() {
    let strategy = world_config_3p().prop_flat_map(|config| {
        let n = config.participant_count();
        (Just(config), action_sequence_with_membership_and_offline(n, &[0, 1]))
    });
    moat_beacon::parallel::run_parallel_cases(strategy, 8, |(config, actions)| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_push::run(config, actions, true));
    });
}

#[test]
fn three_party_push_combinatorial() {
    let strategy = world_config_3p().prop_flat_map(|config| {
        let n = config.participant_count();
        (Just(config), action_sequence_with_offline_n(n))
    });
    moat_beacon::parallel::run_parallel_cases(strategy, 8, |(config, actions)| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_push::run(config, actions, false));
    });
}
