use moat_beacon::actions::action_sequence;

#[test]
fn mixed_two_party_random_actions() {
    let _slot = moat_beacon::parallel::world_slot(super::WORLDS);
    moat_beacon::parallel::run_parallel_cases(action_sequence(), 8, |actions| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::mixed_two_party_chat::run(
            actions, false,
        ));
    });
}
