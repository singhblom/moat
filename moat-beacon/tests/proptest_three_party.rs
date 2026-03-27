use moat_beacon::actions::action_sequence_3p;

#[test]
fn three_party_random_actions() {
    moat_beacon::parallel::run_parallel_cases(action_sequence_3p(), 8, |actions| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::three_party_chat::run(actions, false));
    });
}
