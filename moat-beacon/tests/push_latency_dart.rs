//! Integration test: Drawbridge push delivery latency — both participants are
//! Dart servers.

#[test]
fn push_delivery_latency_dart() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(moat_beacon::scenarios::dart_push_latency::run(true));
}
