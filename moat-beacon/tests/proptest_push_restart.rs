use moat_beacon::actions::action_sequence_with_offline;

#[test]
fn two_party_push_restart_actions() {
    moat_beacon::parallel::run_parallel_cases(action_sequence_with_offline(), 8, |actions| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::two_party_push_restart::run(actions, false));
    });
}
