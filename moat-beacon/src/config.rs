//! `WorldConfig` — generated test topology for combinatorial property tests.
//!
//! A `WorldConfig` describes the participant count, relay topology, and
//! implementation kind (Rust CLI vs Dart server) for a single test run.
//! The proptest strategy [`world_config_3p`] generates configs from a
//! vocabulary of patterns rather than arbitrary combinations, giving
//! structured shrinking (all-Rust + shared-relay is the simplest config).

use crate::world::ParticipantKind;
use proptest::prelude::*;
use std::fmt;

const HANDLES: &[&str] = &["alice", "bob", "carol"];

/// Configuration for a single participant in a test topology.
#[derive(Debug, Clone)]
pub struct ParticipantConfig {
    /// Short handle (e.g. "alice").
    pub handle: &'static str,
    /// Which implementation to run.
    pub kind: ParticipantKind,
    /// Relay group label.  `None` = no Drawbridge relay; participants with the
    /// same `Some(label)` share a single Drawbridge instance.
    pub relay_label: Option<&'static str>,
}

/// Complete topology configuration for a test scenario.
#[derive(Debug, Clone)]
pub struct WorldConfig {
    pub participants: Vec<ParticipantConfig>,
}

impl WorldConfig {
    /// Whether any participant has a relay (and therefore push delivery is active).
    pub fn push_mode(&self) -> bool {
        self.participants.iter().any(|p| p.relay_label.is_some())
    }

    /// Number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Default 3-party push config: all Rust, each on a separate relay.
    ///
    /// Matches the original hardcoded `three_party_push` topology.
    pub fn default_3p_push() -> Self {
        Self {
            participants: vec![
                ParticipantConfig {
                    handle: "alice",
                    kind: ParticipantKind::RustCli,
                    relay_label: Some("a"),
                },
                ParticipantConfig {
                    handle: "bob",
                    kind: ParticipantKind::RustCli,
                    relay_label: Some("b"),
                },
                ParticipantConfig {
                    handle: "carol",
                    kind: ParticipantKind::RustCli,
                    relay_label: Some("c"),
                },
            ],
        }
    }
}

impl fmt::Display for WorldConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, p) in self.participants.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}({:?}", p.handle, p.kind)?;
            if let Some(relay) = p.relay_label {
                write!(f, ", relay={relay}")?;
            }
            write!(f, ")")?;
        }
        write!(f, "]")
    }
}

// ── Proptest strategy ────────────────────────────────────────────────────────

/// Generate a 3-participant `WorldConfig` with varied relay topology and
/// participant kinds.
///
/// Relay patterns:
/// - 0 = all-none (no relays, polling only) — simplest; shrinks toward this
/// - 1 = all-same (`"a"`, `"a"`, `"a"`) — shared relay, local delivery
/// - 2 = all-separate (`"a"`, `"b"`, `"c"`) — per-participant relays
/// - 3 = two-shared (`"a"`, `"a"`, `"b"`) — mixed relay topology
/// - 4 = partial (`"a"`, `"b"`, `None`) — two relay, one polling-only
///
/// Kind patterns:
/// - Without `dart` feature: always all-Rust
/// - With `dart` feature: all-Rust, all-Dart, or mixed (first Rust, rest Dart)
///
/// Shrinking favours simpler topologies: relay index shrinks toward 0
/// (all-none / polling), kind index shrinks toward 0 (all-Rust).
pub fn world_config_3p() -> BoxedStrategy<WorldConfig> {
    let relay_idx = 0..5usize;

    #[cfg(feature = "dart")]
    let kind_idx = 0..3usize;
    #[cfg(not(feature = "dart"))]
    let kind_idx = 0..1usize;

    (relay_idx, kind_idx)
        .prop_map(|(relay, kind)| {
            let labels: [Option<&'static str>; 3] = match relay {
                0 => [None, None, None],
                1 => [Some("a"), Some("a"), Some("a")],
                2 => [Some("a"), Some("b"), Some("c")],
                3 => [Some("a"), Some("a"), Some("b")],
                _ => [Some("a"), Some("b"), None],
            };
            let kinds: [ParticipantKind; 3] = match kind {
                1 => [
                    ParticipantKind::DartServer,
                    ParticipantKind::DartServer,
                    ParticipantKind::DartServer,
                ],
                2 => [
                    ParticipantKind::RustCli,
                    ParticipantKind::DartServer,
                    ParticipantKind::DartServer,
                ],
                _ => [
                    ParticipantKind::RustCli,
                    ParticipantKind::RustCli,
                    ParticipantKind::RustCli,
                ],
            };

            let participants = HANDLES
                .iter()
                .zip(labels.iter())
                .zip(kinds.iter())
                .map(|((handle, label), kind)| ParticipantConfig {
                    handle,
                    kind: kind.clone(),
                    relay_label: *label,
                })
                .collect();

            WorldConfig { participants }
        })
        .boxed()
}
