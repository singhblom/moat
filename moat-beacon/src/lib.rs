//! moat-beacon: integration & property test harness for the moat stack.
//!
//! Beacon orchestrates real processes — `moat-cli --http`, Postern,
//! Toxiproxy, and Drawbridge — and verifies invariants over scripted or
//! randomly generated action sequences.
//!
//! Key components:
//! - [`world::TestWorld`] — spins up Postern, Toxiproxy, optional Drawbridge
//!   relays, and one `moat-cli --http` subprocess per participant.
//! - [`client::MoatCliClient`] — typed HTTP client for the moat-cli REST API.
//! - [`actions`] — `Action` enum with `prop_flat_map` fold strategy.
//! - [`invariants`] — `ScenarioState`, `drain_events`, invariant checkers.
//! - [`drawbridge`] — `DrawbridgeProcess`: build Go binary, spawn, health-check.
//! - [`scenarios`] — `Scenario` registry, seed utilities, and CLI (`list` / `run` / `replay`).

pub mod actions;
pub mod client;
pub mod drawbridge;
pub mod invariants;
pub mod scenarios;
pub mod toxiproxy;
pub mod world;
