//! moat-beacon: integration & property test harness for the moat stack.
//!
//! Beacon orchestrates real processes — `moat-cli --http`, Postern,
//! Toxiproxy, and (later) Drawbridge — and verifies invariants over
//! scripted or randomly generated action sequences.
//!
//! # Phase 1 (complete)
//! - [`TestWorld`] — spins up Postern + one `moat-cli --http` process per
//!   participant.
//! - [`MoatCliClient`] — typed HTTP client for the moat-cli REST API.
//!
//! # Phase 2 (complete)
//! - [`ToxiproxyManager`] — find/download/spawn Toxiproxy, create proxies.
//! - All participant connections now route through `proxy-pds` so tests can
//!   inject network faults via [`TestWorld::toxiproxy`].
//!
//! # Phase 3 (complete)
//! - [`actions`] — `Action` enum with `prop_flat_map` fold strategy.
//! - [`invariants`] — `ScenarioState`, `drain_events`, invariant checkers.
//!
//! # Future phases
//! - Phase 4: Drawbridge subprocess management.
//! - Phase 5: `beacon run <name>` / `beacon replay <seed>` CLI.

pub mod actions;
pub mod client;
pub mod invariants;
pub mod toxiproxy;
pub mod world;
