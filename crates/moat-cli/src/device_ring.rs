//! Device ring driver for moat-cli.
//!
//! Pure state for the ring/coord group state machine.  All network I/O lives
//! in `App::do_ring_tick` in `app.rs`, following the same pattern as
//! `App::poll_for_new_devices`.

use std::collections::{HashMap, HashSet};

use crate::keystore::RingState;

/// State-machine driver for the device ring and coordination groups.
///
/// Owned by `App`. Holds only pure, serialisable state — no async, no I/O.
/// Network calls are performed by `App::do_ring_tick`.
pub struct DeviceRingDriver {
    /// Raw ring group ID bytes, if a ring exists.
    pub ring_group_id: Option<Vec<u8>>,
    /// Unix timestamp (ms) when the ring was created.
    pub ring_created_at: Option<i64>,
    /// sibling device_id (16 bytes) → coord group_id (raw bytes).
    pub coord_groups: HashMap<[u8; 16], Vec<u8>>,
    /// device_ids from which we've received a CoordMsg::Hello.
    pub sibling_sent_hello: HashSet<[u8; 16]>,
    /// Cursor (rkey) for incremental own-PDS stealth scan.
    pub own_events_cursor: Option<String>,
    /// Stub flag for Phase 4: set to true when the ring gains a new member.
    pub ring_has_new_sibling: bool,
}

impl DeviceRingDriver {
    /// Construct from persisted [`RingState`].
    pub fn from_state(state: &RingState) -> Self {
        let ring_group_id = state.ring_group_id.as_deref().and_then(|s| hex::decode(s).ok());
        let coord_groups = state
            .coord_groups
            .iter()
            .filter_map(|(k, v)| {
                let dev_id: [u8; 16] = hex::decode(k).ok()?.try_into().ok()?;
                let group_id = hex::decode(v).ok()?;
                Some((dev_id, group_id))
            })
            .collect();
        let sibling_sent_hello = state
            .sibling_sent_hello
            .iter()
            .filter_map(|s| {
                let bytes = hex::decode(s).ok()?;
                bytes.try_into().ok()
            })
            .collect();
        Self {
            ring_group_id,
            ring_created_at: state.ring_created_at,
            coord_groups,
            sibling_sent_hello,
            own_events_cursor: state.own_events_cursor.clone(),
            ring_has_new_sibling: false,
        }
    }

    /// Serialise current state for persistence.
    pub fn to_ring_state(&self) -> RingState {
        RingState {
            ring_group_id: self.ring_group_id.as_ref().map(hex::encode),
            ring_created_at: self.ring_created_at,
            coord_groups: self
                .coord_groups
                .iter()
                .map(|(k, v)| (hex::encode(k), hex::encode(v)))
                .collect(),
            sibling_sent_hello: self.sibling_sent_hello.iter().map(hex::encode).collect(),
            own_events_cursor: self.own_events_cursor.clone(),
        }
    }

    /// Record that a sibling has sent us a Hello.
    pub fn process_hello(&mut self, sender_device_id: [u8; 16]) {
        self.sibling_sent_hello.insert(sender_device_id);
    }

    /// Clear our ring state if it matches `old_ring_id`.
    pub fn process_supersede(&mut self, old_ring_id: &[u8]) {
        if self.ring_group_id.as_deref() == Some(old_ring_id) {
            self.ring_group_id = None;
            self.ring_created_at = None;
        }
    }

    /// Siblings that have an established coord group AND have sent us a Hello.
    pub fn hello_exchanged_siblings(&self) -> Vec<[u8; 16]> {
        self.sibling_sent_hello
            .iter()
            .filter(|id| self.coord_groups.contains_key(*id))
            .copied()
            .collect()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_state_roundtrip() {
        let driver = DeviceRingDriver {
            ring_group_id: Some(vec![1u8; 16]),
            ring_created_at: Some(12345),
            coord_groups: {
                let mut m = HashMap::new();
                m.insert([2u8; 16], vec![3u8; 16]);
                m
            },
            sibling_sent_hello: {
                let mut s = HashSet::new();
                s.insert([4u8; 16]);
                s
            },
            own_events_cursor: Some("rkey123".to_string()),
            ring_has_new_sibling: false,
        };

        let state = driver.to_ring_state();
        let restored = DeviceRingDriver::from_state(&state);

        assert_eq!(restored.ring_group_id, driver.ring_group_id);
        assert_eq!(restored.ring_created_at, driver.ring_created_at);
        assert_eq!(restored.coord_groups.len(), 1);
        assert_eq!(restored.sibling_sent_hello.len(), 1);
        assert_eq!(restored.own_events_cursor, driver.own_events_cursor);
    }

    #[test]
    fn process_hello_registers_sibling() {
        let mut driver = DeviceRingDriver {
            ring_group_id: None,
            ring_created_at: None,
            coord_groups: HashMap::new(),
            sibling_sent_hello: HashSet::new(),
            own_events_cursor: None,
            ring_has_new_sibling: false,
        };
        driver.process_hello([7u8; 16]);
        assert!(driver.sibling_sent_hello.contains(&[7u8; 16]));
    }

    #[test]
    fn process_supersede_clears_ring() {
        let old_ring = vec![0xAAu8; 16];
        let mut driver = DeviceRingDriver {
            ring_group_id: Some(old_ring.clone()),
            ring_created_at: Some(1000),
            coord_groups: HashMap::new(),
            sibling_sent_hello: HashSet::new(),
            own_events_cursor: None,
            ring_has_new_sibling: false,
        };
        driver.process_supersede(&old_ring);
        assert!(driver.ring_group_id.is_none());
        assert!(driver.ring_created_at.is_none());
    }

    #[test]
    fn process_supersede_wrong_id_no_op() {
        let my_ring = vec![0xAAu8; 16];
        let other_ring = vec![0xBBu8; 16];
        let mut driver = DeviceRingDriver {
            ring_group_id: Some(my_ring.clone()),
            ring_created_at: Some(1000),
            coord_groups: HashMap::new(),
            sibling_sent_hello: HashSet::new(),
            own_events_cursor: None,
            ring_has_new_sibling: false,
        };
        driver.process_supersede(&other_ring);
        assert_eq!(driver.ring_group_id, Some(my_ring));
    }

    #[test]
    fn hello_exchanged_siblings_requires_coord_group() {
        let mut driver = DeviceRingDriver {
            ring_group_id: None,
            ring_created_at: None,
            coord_groups: HashMap::new(),
            sibling_sent_hello: HashSet::new(),
            own_events_cursor: None,
            ring_has_new_sibling: false,
        };

        let sibling_a = [1u8; 16];
        let sibling_b = [2u8; 16];

        driver.process_hello(sibling_a);
        driver.process_hello(sibling_b);
        // Only sibling_a has a coord group
        driver.coord_groups.insert(sibling_a, vec![0u8; 16]);

        let ready = driver.hello_exchanged_siblings();
        assert_eq!(ready, vec![sibling_a]);
    }
}
