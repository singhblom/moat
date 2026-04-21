//! Device ring and coordination group primitives.
//!
//! Pure logic (no async, no I/O). Consumed by the driver layers in moat-cli
//! and moat-dart/common.

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::{Error, MoatCredential, Result};

/// Classification of an MLS group by its role within the Moat multi-device system.
///
/// Persisted alongside `GroupMetadata` so callers can filter conversations
/// without re-deriving classification on every load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    /// A user-facing conversation (default for all existing groups).
    #[default]
    User,
    /// The N-party device ring spanning all devices with the same DID.
    Ring,
    /// A pairwise coordination group between two sibling devices.
    DeviceCoord,
}

/// Result of creating a device coordination group.
#[derive(Debug)]
pub struct CoordGroupResult {
    pub group_id: Vec<u8>,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// Coordination messages sent as MLS application messages over a `DeviceCoord` group.
///
/// Serialised as JSON and placed in `Event.payload` with `EventKind::Coord`.
/// All variants encode to well under 512 bytes after JSON serialisation.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordMsg {
    /// Sent by the group creator to signal its presence once the sibling joins.
    Hello {
        #[serde_as(as = "Base64")]
        sender_device_id: Vec<u8>,
    },
    /// Informs a sibling about the current ring (for bootstrap or reconciliation).
    RingInfo {
        #[serde_as(as = "Base64")]
        ring_id: Vec<u8>,
        /// Unix timestamp (ms) when the ring was created.
        created_at: i64,
    },
    /// Tells the recipient to abandon a losing ring during split-brain reconciliation.
    Supersede {
        #[serde_as(as = "Base64")]
        old_ring_id: Vec<u8>,
    },
    /// Delivers the MLS ring-group Welcome to the new sibling through the coord channel.
    ///
    /// Preferred over stealth delivery because it arrives in the same ordered channel
    /// as `RingInfo`, so the recipient always knows `ring_id` by the time `welcome` is
    /// processed.
    RingWelcome {
        #[serde_as(as = "Base64")]
        ring_id: Vec<u8>,
        #[serde_as(as = "Base64")]
        welcome: Vec<u8>,
        created_at: i64,
    },
}

/// Encode a [`CoordMsg`] to bytes suitable for use as `Event.payload`.
pub fn encode_coord_msg(msg: &CoordMsg) -> Vec<u8> {
    serde_json::to_vec(msg).expect("CoordMsg serialization should never fail")
}

/// Decode a [`CoordMsg`] from `Event.payload` bytes.
pub fn decode_coord_msg(bytes: &[u8]) -> Result<CoordMsg> {
    serde_json::from_slice(bytes).map_err(|e| Error::Deserialization(e.to_string()))
}

/// Outcome of comparing two ring instances to decide which survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileDecision {
    /// Keep the locally-known ring; the peer should switch to ours.
    KeepMine,
    /// Abandon the locally-known ring; join the peer's ring instead.
    SwitchToTheirs,
    /// Both devices are already in the same ring — nothing to do.
    AlreadyInTheirs,
}

/// Decide which ring wins when two devices discover they are in different rings.
///
/// Oldest `created_at` wins. Tie broken by lexicographically smallest `ring_id`.
pub fn reconcile_rings(
    mine_ring_id: &[u8],
    mine_created_at: i64,
    theirs_ring_id: &[u8],
    theirs_created_at: i64,
) -> ReconcileDecision {
    if mine_ring_id == theirs_ring_id {
        return ReconcileDecision::AlreadyInTheirs;
    }
    match mine_created_at.cmp(&theirs_created_at) {
        std::cmp::Ordering::Less => ReconcileDecision::KeepMine,
        std::cmp::Ordering::Greater => ReconcileDecision::SwitchToTheirs,
        std::cmp::Ordering::Equal => {
            if mine_ring_id <= theirs_ring_id {
                ReconcileDecision::KeepMine
            } else {
                ReconcileDecision::SwitchToTheirs
            }
        }
    }
}

/// Classify a group as `DeviceCoord` or `User` based on member credentials.
///
/// Returns `DeviceCoord` iff all members carry `my_did`; otherwise `User`.
///
/// Ring detection (group_id == ring_group_id) is the caller's responsibility —
/// check that first and short-circuit before calling this function.
pub fn classify_group_kind(
    members: &[(u32, Option<MoatCredential>)],
    my_did: &str,
) -> GroupKind {
    if members.is_empty() {
        return GroupKind::User;
    }
    let all_same_did = members
        .iter()
        .all(|(_, cred)| cred.as_ref().map(|c| c.did() == my_did).unwrap_or(false));
    if all_same_did {
        GroupKind::DeviceCoord
    } else {
        GroupKind::User
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MoatCredential, MoatSession};

    fn make_members(dids: &[&str]) -> Vec<(u32, Option<MoatCredential>)> {
        dids.iter()
            .enumerate()
            .map(|(i, did)| {
                let mut device_id = [0u8; 16];
                device_id[0] = i as u8;
                (i as u32, Some(MoatCredential::new(*did, "device", device_id)))
            })
            .collect()
    }

    #[test]
    fn reconcile_older_mine_wins() {
        assert_eq!(
            reconcile_rings(&[1u8; 32], 1000, &[2u8; 32], 2000),
            ReconcileDecision::KeepMine
        );
    }

    #[test]
    fn reconcile_older_theirs_wins() {
        assert_eq!(
            reconcile_rings(&[2u8; 32], 2000, &[1u8; 32], 1000),
            ReconcileDecision::SwitchToTheirs
        );
    }

    #[test]
    fn reconcile_tie_smaller_id_wins() {
        assert_eq!(
            reconcile_rings(&[2u8; 32], 1000, &[1u8; 32], 1000),
            ReconcileDecision::SwitchToTheirs,
            "theirs is smaller, should switch"
        );
        assert_eq!(
            reconcile_rings(&[1u8; 32], 1000, &[2u8; 32], 1000),
            ReconcileDecision::KeepMine,
            "mine is smaller, should keep"
        );
    }

    #[test]
    fn reconcile_same_ring_id() {
        let id = [5u8; 32];
        assert_eq!(
            reconcile_rings(&id, 1000, &id, 2000),
            ReconcileDecision::AlreadyInTheirs
        );
    }

    #[test]
    fn coord_msg_roundtrip_hello() {
        let msg = CoordMsg::Hello {
            sender_device_id: vec![0xABu8; 16],
        };
        let decoded = decode_coord_msg(&encode_coord_msg(&msg)).unwrap();
        match decoded {
            CoordMsg::Hello { sender_device_id } => assert_eq!(sender_device_id, vec![0xABu8; 16]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn coord_msg_roundtrip_ring_info() {
        let msg = CoordMsg::RingInfo {
            ring_id: vec![0xDEu8; 32],
            created_at: 1_234_567_890,
        };
        let decoded = decode_coord_msg(&encode_coord_msg(&msg)).unwrap();
        match decoded {
            CoordMsg::RingInfo { ring_id, created_at } => {
                assert_eq!(ring_id, vec![0xDEu8; 32]);
                assert_eq!(created_at, 1_234_567_890);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn coord_msg_roundtrip_supersede() {
        let msg = CoordMsg::Supersede {
            old_ring_id: vec![0xCAu8; 32],
        };
        let decoded = decode_coord_msg(&encode_coord_msg(&msg)).unwrap();
        assert!(matches!(decoded, CoordMsg::Supersede { .. }));
    }

    #[test]
    fn coord_msg_fits_in_small_bucket() {
        let msgs = [
            CoordMsg::Hello {
                sender_device_id: vec![0u8; 16],
            },
            CoordMsg::RingInfo {
                ring_id: vec![0u8; 32],
                created_at: i64::MAX,
            },
            CoordMsg::Supersede {
                old_ring_id: vec![0u8; 32],
            },
        ];
        for msg in &msgs {
            let n = encode_coord_msg(msg).len();
            assert!(n < 512, "CoordMsg variant encoded to {n} bytes, must fit in 512-byte bucket");
        }
    }

    #[test]
    fn classify_all_same_did_is_device_coord() {
        let members = make_members(&["did:plc:alice", "did:plc:alice"]);
        assert_eq!(
            classify_group_kind(&members, "did:plc:alice"),
            GroupKind::DeviceCoord
        );
    }

    #[test]
    fn classify_different_dids_is_user() {
        let members = make_members(&["did:plc:alice", "did:plc:bob"]);
        assert_eq!(
            classify_group_kind(&members, "did:plc:alice"),
            GroupKind::User
        );
    }

    #[test]
    fn classify_empty_is_user() {
        assert_eq!(classify_group_kind(&[], "did:plc:alice"), GroupKind::User);
    }

    #[test]
    fn create_device_coord_group_sibling_can_join() {
        let alice = MoatSession::new();
        let bob = MoatSession::new();

        let alice_cred = MoatCredential::new("did:plc:alice", "laptop", [0u8; 16]);
        let bob_cred = MoatCredential::new("did:plc:alice", "phone", [1u8; 16]);

        let (bob_kp, _bob_key_bundle) = bob.generate_key_package(&bob_cred).unwrap();
        let (_, alice_key_bundle) = alice.generate_key_package(&alice_cred).unwrap();

        let result = alice
            .create_device_coord_group(&alice_cred, &alice_key_bundle, &bob_kp)
            .unwrap();
        assert!(!result.group_id.is_empty());
        assert!(!result.welcome.is_empty());

        let joined_id = bob.process_welcome(&result.welcome).unwrap();
        assert_eq!(joined_id, result.group_id);

        let members = alice.get_group_members(&result.group_id).unwrap();
        assert_eq!(
            classify_group_kind(&members, "did:plc:alice"),
            GroupKind::DeviceCoord
        );
    }

    #[test]
    fn create_device_ring_produces_distinct_random_ids() {
        let session = MoatSession::new();
        let cred = MoatCredential::new("did:plc:alice", "laptop", [0u8; 16]);
        let (_, key_bundle) = session.generate_key_package(&cred).unwrap();

        let id1 = session.create_device_ring(&cred, &key_bundle).unwrap();
        let id2 = session.create_device_ring(&cred, &key_bundle).unwrap();
        assert_ne!(id1, id2, "ring IDs must be random, not deterministic");
        assert!(!id1.is_empty());
    }
}
