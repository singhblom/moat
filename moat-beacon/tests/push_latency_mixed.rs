//! Integration test: Drawbridge push delivery latency — Alice (Rust CLI) +
//! Bob (Dart server).

#[test]
fn push_delivery_latency_mixed() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(moat_beacon::scenarios::mixed_push_latency::run(true));
}
