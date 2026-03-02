//! Integration test: Drawbridge push delivery latency.
//!
//! Sends messages between Alice and Bob with polling disabled and asserts each
//! message arrives within 2 seconds via Drawbridge push alone.

#[test]
fn push_delivery_latency() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(moat_beacon::scenarios::push_latency::run(true));
}
