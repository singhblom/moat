//! Generative Beacon suites. One binary for the family; tests run one
//! `TestWorld` at a time (`BEACON_WORLDS` overrides, `BEACON_PARALLEL`
//! parallelises cases within a test).

mod dart_three_party;
mod dart_two_party;
mod drawbridge;
mod mixed;
mod mixed_three_party;
mod multi_device;
mod push_restart;
mod restart;
mod three_party_push;
mod two_party;

const WORLDS: usize = 1;
