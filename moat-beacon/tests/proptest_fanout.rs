//! Property-based two-party scenario with per-participant Drawbridge relays.
//!
//! Each participant gets its own Drawbridge instance.  Message delivery
//! exercises the relay-to-relay fan-out path (`POST /relay/event`).
//!
//! Invariants checked after drain:
//!   - Delivery         — every confirmed message ID appears in both views.
//!   - Consensus order  — Alice and Bob see the same message sequence.
//!   - No duplicates    — no participant has a repeated message ID.

use moat_beacon::actions::action_sequence;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"),
        )),
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_party_fanout_delivery(actions in action_sequence()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::two_party_fanout::run(actions, false));
    }
}
