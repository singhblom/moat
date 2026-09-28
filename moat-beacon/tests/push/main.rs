//! Push-delivery timing tests. Latency assertions are sensitive to load,
//! so these run one `TestWorld` at a time (`BEACON_WORLDS` overrides).

mod fcm_dispatch;
mod latency;
mod latency_dart;
mod latency_mixed;
mod latency_restart;

const WORLDS: usize = 1;
