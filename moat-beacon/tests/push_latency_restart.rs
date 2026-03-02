//! Integration test: Drawbridge push delivery survives participant restart.
//!
//! Establishes a conversation with push delivery, kills both participants,
//! restarts them, and verifies push still works without polling.

#[test]
fn push_delivery_after_restart() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(moat_beacon::scenarios::push_latency_restart::run(true));
}
