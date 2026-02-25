//! moat-beacon: integration & property test harness for the moat stack.
//!
//! Beacon orchestrates real processes — `moat-cli --http`, Postern, Drawbridge,
//! and Toxiproxy — and verifies invariants over generated action sequences.
//!
//! # Phase 1 (current)
//! - [`TestWorld`] — spins up Postern + one `moat-cli --http` process per participant.
//! - [`MoatCliClient`] — typed HTTP client for the moat-cli REST API.
//!
//! # Future phases
//! - Toxiproxy integration for network fault injection.
//! - Drawbridge subprocess management.
//! - proptest `Action` enum for random scenario generation.

pub mod client;
pub mod world;
