//! Phase 3: property-based two-party scenario.
//!
//! `proptest` generates random action sequences of length 1–10 using the
//! `prop_flat_map` fold strategy in `actions::action_sequence()`.  Reactions
//! are only generated after at least one `SendMessage`, and `message_idx` is
//! always in-bounds by construction.
//!
//! Fixed prologue (not randomised):
//!   1. Login Alice + Bob.
//!   2. Bob watches Alice.
//!   3. Alice starts a conversation with Bob.
//!   4. Bob polls to join (receives the MLS Welcome).
//!
//! After the action sequence, `drain_events` lets everything propagate and
//! three invariants are checked:
//!   - Delivery         — every sent message appears in both participants' lists.
//!   - Consensus order  — Alice and Bob see the same message sequence (global order).
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
    fn two_party_random_actions(actions in action_sequence()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::two_party_chat::run(actions, false));
    }
}
