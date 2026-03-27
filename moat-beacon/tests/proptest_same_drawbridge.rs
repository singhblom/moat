use moat_beacon::actions::action_sequence;

#[test]
fn same_drawbridge_local_delivery() {
    moat_beacon::parallel::run_parallel_cases(action_sequence(), 8, |actions| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::same_drawbridge_local::run(actions, false));
    });
}
