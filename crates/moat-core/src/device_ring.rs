//! Device ring and coordination group primitives.
//!
//! Pure logic (no async, no I/O). Consumed by the driver layers in moat-cli
//! and moat-dart/common.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::{encrypt_for_stealth, try_decrypt_stealth, Error, Event, MoatCredential, MoatSession, Result};

/// Magic bytes for the Welcome envelope wire format: ASCII "MWE1".
const WELCOME_ENVELOPE_MAGIC: [u8; 4] = *b"MWE1";

/// Encode a Welcome into the wire envelope: `[MWE1][4-byte BE welcome_len][welcome][hints_json]`.
///
/// Hints are a JSON array reserved for future use; this helper always writes
/// the empty array `[]`. Both moat-cli and moat-dart wrap stealth-published
/// Welcomes in this envelope, so the ring driver does the same internally.
pub fn encode_welcome_envelope(welcome: &[u8]) -> Vec<u8> {
    let hints_json: &[u8] = b"[]";
    let mut buf = Vec::with_capacity(8 + welcome.len() + hints_json.len());
    buf.extend_from_slice(&WELCOME_ENVELOPE_MAGIC);
    buf.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
    buf.extend_from_slice(welcome);
    buf.extend_from_slice(hints_json);
    buf
}

/// Decode a Welcome envelope, returning the raw welcome bytes.
///
/// Returns `None` if the envelope is missing the MWE1 magic or is truncated.
/// Hints (if present) are ignored.
pub fn decode_welcome_envelope(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 || data[..4] != WELCOME_ENVELOPE_MAGIC {
        return None;
    }
    let welcome_len = u32::from_be_bytes(data[4..8].try_into().ok()?) as usize;
    if data.len() < 8 + welcome_len {
        return None;
    }
    Some(data[8..8 + welcome_len].to_vec())
}

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
    /// Carries the Drawbridge pairing token from the ring offerer to the new member.
    ///
    /// Sent as a ring MLS application message after the new device is added to the ring.
    /// The recipient uses the token to call `pair_join` on Drawbridge and open the pair WS.
    SyncOffer {
        #[serde_as(as = "Base64")]
        token: Vec<u8>,
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

/// Persisted state for the device ring driver.
///
/// Hex-encoded serialisation form for on-disk storage. The runtime form is
/// [`DeviceRingDriver`], which holds raw byte arrays.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RingState {
    /// Hex-encoded ring group ID, or None if no ring exists yet.
    #[serde(default)]
    pub ring_group_id: Option<String>,
    /// Unix timestamp (ms) when the ring was created.
    #[serde(default)]
    pub ring_created_at: Option<i64>,
    /// Map from sibling device_id (hex) → coord group_id (hex).
    #[serde(default)]
    pub coord_groups: HashMap<String, String>,
    /// device_ids (hex) of siblings from whom we've received a Hello.
    #[serde(default)]
    pub sibling_sent_hello: HashSet<String>,
    /// Cursor (rkey) for incremental own-PDS stealth scan.
    #[serde(default)]
    pub own_events_cursor: Option<String>,
}

/// State-machine driver for the device ring and coordination groups.
///
/// Holds only pure, serialisable state — no async, no I/O. Network calls and
/// MLS mutations are performed by the host layer (`moat-cli`'s `App` or the
/// Dart `DeviceRingService`), driven by the methods on this struct.
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
    /// Set to true when the ring gains a new member; consumed by the sync layer.
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

    /// Drive one ring coordination tick.
    ///
    /// Pure orchestration: takes pre-fetched data via [`TickInputs`] and a
    /// borrowed [`MoatSession`] for MLS operations, returns a list of
    /// [`RingCommand`] for the host to execute (publishing to the PDS, sending
    /// Drawbridge frames, persisting metadata, etc.).
    pub fn tick(&mut self, mls: &MoatSession, inputs: TickInputs<'_>) -> Vec<RingCommand> {
        let mut cmds = Vec::new();
        let my_device_id = *mls.device_id();

        // ── 1. Filter sibling key packages ──────────────────────────────
        let siblings: Vec<&KeyPackageInput> = inputs
            .key_packages
            .iter()
            .filter(|kp| {
                mls.extract_credential_from_key_package(&kp.key_package)
                    .ok()
                    .flatten()
                    .map(|c| *c.device_id() != my_device_id)
                    .unwrap_or(false)
            })
            .collect();

        // ── 2. Create coord groups for new siblings ─────────────────────
        for kp in &siblings {
            let sibling_cred = match mls.extract_credential_from_key_package(&kp.key_package) {
                Ok(Some(c)) => c,
                _ => continue,
            };
            let sibling_device_id: [u8; 16] = *sibling_cred.device_id();
            if self.coord_groups.contains_key(&sibling_device_id) {
                continue;
            }
            let CoordGroupResult { group_id, commit, welcome } = match mls
                .create_device_coord_group(inputs.credential, inputs.key_bundle, &kp.key_package)
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            cmds.push(RingCommand::RegisterGroup {
                group_id: group_id.clone(),
                kind: GroupKind::DeviceCoord,
            });

            // Publish coord commit
            let commit_tag = mls
                .derive_next_tag(&group_id, inputs.key_bundle)
                .unwrap_or_else(|_| rand::random());
            cmds.push(RingCommand::PublishEvent {
                tag: commit_tag,
                ciphertext: commit,
                mark_own: true,
            });

            // Publish Hello in coord group
            let epoch = mls.get_group_epoch(&group_id).ok().flatten().unwrap_or(0);
            let hello_event = Event::coord(
                group_id.clone(),
                epoch,
                encode_coord_msg(&CoordMsg::Hello {
                    sender_device_id: my_device_id.to_vec(),
                }),
            );
            if let Ok(enc) = mls.encrypt_event(&group_id, inputs.key_bundle, &hello_event) {
                cmds.push(RingCommand::PublishEvent {
                    tag: enc.tag,
                    ciphertext: enc.ciphertext,
                    mark_own: true,
                });
            }

            // Stealth-publish Welcome to siblings (wrapped in MWE1 envelope for
            // wire compat with moat-cli and moat-dart hosts).
            if !inputs.stealth_pubkeys.is_empty() {
                let envelope = encode_welcome_envelope(&welcome);
                if let Ok(ct) = encrypt_for_stealth(inputs.stealth_pubkeys, &envelope) {
                    cmds.push(RingCommand::StealthPublishWelcome {
                        tag: rand::random(),
                        ciphertext: ct,
                    });
                }
            }

            self.coord_groups.insert(sibling_device_id, group_id);
        }

        // ── 3. Stealth-scan own PDS events for incoming Welcomes ────────
        let mut coord_groups_to_greet: Vec<Vec<u8>> = Vec::new();
        for ev in inputs.own_events {
            let plaintext = match try_decrypt_stealth(inputs.stealth_privkey, &ev.ciphertext) {
                Some(p) => p,
                None => continue,
            };
            // Stealth payload may be either the raw Welcome (legacy) or an MWE1
            // envelope. Try to unwrap; fall back to the raw plaintext.
            let welcome_bytes_owned = decode_welcome_envelope(&plaintext);
            let welcome_bytes: &[u8] = welcome_bytes_owned
                .as_deref()
                .unwrap_or(plaintext.as_slice());
            match mls.process_welcome(welcome_bytes) {
                Ok(group_id) => {
                    let kind = if self.ring_group_id.as_deref() == Some(&group_id) {
                        GroupKind::Ring
                    } else {
                        let members = mls.get_group_members(&group_id).unwrap_or_default();
                        let k = classify_group_kind(&members, inputs.my_did);
                        if k == GroupKind::DeviceCoord {
                            // Record the coord group from recipient side
                            if let Some(sibling_id) = members.iter().find_map(|(_, c)| {
                                c.as_ref().and_then(|c| {
                                    if c.did() == inputs.my_did
                                        && *c.device_id() != my_device_id
                                    {
                                        Some(*c.device_id())
                                    } else {
                                        None
                                    }
                                })
                            }) {
                                self.coord_groups
                                    .entry(sibling_id)
                                    .or_insert_with(|| group_id.clone());
                            }
                            coord_groups_to_greet.push(group_id.clone());
                        }
                        k
                    };
                    cmds.push(RingCommand::RegisterGroup {
                        group_id: group_id.clone(),
                        kind,
                    });
                }
                Err(_) => {} // already joined or not for us
            }
        }

        if !coord_groups_to_greet.is_empty() {
            cmds.push(RingCommand::ReplenishKeyPackage);
        }
        for coord_id in &coord_groups_to_greet {
            let epoch = mls.get_group_epoch(coord_id).ok().flatten().unwrap_or(0);
            let hello_event = Event::coord(
                coord_id.clone(),
                epoch,
                encode_coord_msg(&CoordMsg::Hello {
                    sender_device_id: my_device_id.to_vec(),
                }),
            );
            if let Ok(enc) = mls.encrypt_event(coord_id, inputs.key_bundle, &hello_event) {
                cmds.push(RingCommand::PublishEvent {
                    tag: enc.tag,
                    ciphertext: enc.ciphertext,
                    mark_own: true,
                });
            }
        }

        // Advance own-events cursor
        if let Some(last) = inputs.own_events.last() {
            if !last.rkey.is_empty() {
                self.own_events_cursor = Some(last.rkey.clone());
            }
        }

        // ── 4. Bootstrap ring when Hello-exchanged siblings are known ──
        let hello_exchanged = self.hello_exchanged_siblings();
        if !hello_exchanged.is_empty() {
            if let Some(ring_id) = self.ring_group_id.clone() {
                for sibling_id in &hello_exchanged {
                    if let Ok(members) = mls.get_group_members(&ring_id) {
                        if members.iter().any(|(_, c)| {
                            c.as_ref()
                                .map(|c| *c.device_id() == *sibling_id)
                                .unwrap_or(false)
                        }) {
                            continue;
                        }
                    }
                    // Pick newest key package (siblings are in fetch order; reverse it).
                    let sibling_kp = siblings.iter().rev().find(|kp| {
                        mls.extract_credential_from_key_package(&kp.key_package)
                            .ok()
                            .flatten()
                            .map(|c| *c.device_id() == *sibling_id)
                            .unwrap_or(false)
                    });
                    if let Some(kp) = sibling_kp {
                        if let Ok(wr) = mls.add_device(&ring_id, inputs.key_bundle, &kp.key_package)
                        {
                            self.ring_has_new_sibling = true;
                            let commit_tag = mls
                                .derive_next_tag(&ring_id, inputs.key_bundle)
                                .unwrap_or_else(|_| rand::random());
                            cmds.push(RingCommand::PublishEvent {
                                tag: commit_tag,
                                ciphertext: wr.commit,
                                mark_own: true,
                            });
                            self.emit_ring_welcome_to_coord(
                                mls,
                                inputs.key_bundle,
                                *sibling_id,
                                &ring_id,
                                &wr.welcome,
                                &mut cmds,
                            );
                        }
                    }
                }
            } else {
                // No ring yet — smallest device_id creates it.
                let mut all_ids: Vec<[u8; 16]> = hello_exchanged.clone();
                all_ids.push(my_device_id);
                all_ids.sort();
                if all_ids[0] == my_device_id {
                    if let Ok(ring_id) =
                        mls.create_device_ring(inputs.credential, inputs.key_bundle)
                    {
                        self.ring_group_id = Some(ring_id.clone());
                        self.ring_created_at = Some(inputs.now_ms);
                        self.ring_has_new_sibling = true;
                        cmds.push(RingCommand::RegisterGroup {
                            group_id: ring_id.clone(),
                            kind: GroupKind::Ring,
                        });
                        for sibling_id in &hello_exchanged {
                            let sibling_kp = siblings.iter().rev().find(|kp| {
                                mls.extract_credential_from_key_package(&kp.key_package)
                                    .ok()
                                    .flatten()
                                    .map(|c| *c.device_id() == *sibling_id)
                                    .unwrap_or(false)
                            });
                            if let Some(kp) = sibling_kp {
                                if let Ok(wr) =
                                    mls.add_device(&ring_id, inputs.key_bundle, &kp.key_package)
                                {
                                    let commit_tag = mls
                                        .derive_next_tag(&ring_id, inputs.key_bundle)
                                        .unwrap_or_else(|_| rand::random());
                                    cmds.push(RingCommand::PublishEvent {
                                        tag: commit_tag,
                                        ciphertext: wr.commit,
                                        mark_own: true,
                                    });
                                    self.emit_ring_welcome_to_coord(
                                        mls,
                                        inputs.key_bundle,
                                        *sibling_id,
                                        &ring_id,
                                        &wr.welcome,
                                        &mut cmds,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── 5. Trigger history sync if we are the offerer ──────────────
        if self.ring_has_new_sibling {
            self.ring_has_new_sibling = false;
            if inputs.drawbridge_has_own_connection && !inputs.sync_session_active {
                if let Some(ring_id) = self.ring_group_id.clone() {
                    let our_leaf = mls
                        .get_own_leaf_index(&ring_id, inputs.key_bundle)
                        .ok()
                        .flatten()
                        .unwrap_or(u32::MAX);
                    if our_leaf == 0 {
                        use rand::RngCore;
                        let mut token = vec![0u8; 32];
                        rand::thread_rng().fill_bytes(&mut token);
                        let epoch = mls
                            .get_group_epoch(&ring_id)
                            .ok()
                            .flatten()
                            .unwrap_or(0);
                        let offer_event = Event::coord(
                            ring_id.clone(),
                            epoch,
                            encode_coord_msg(&CoordMsg::SyncOffer { token: token.clone() }),
                        );
                        if let Ok(enc) =
                            mls.encrypt_event(&ring_id, inputs.key_bundle, &offer_event)
                        {
                            cmds.push(RingCommand::PublishEvent {
                                tag: enc.tag,
                                ciphertext: enc.ciphertext,
                                mark_own: true,
                            });
                        }
                        cmds.push(RingCommand::SendDrawbridgePairOffer { token });
                    }
                }
            }
            cmds.push(RingCommand::PollForNewDevices);
        }

        cmds
    }

    /// Handle an incoming coordination message decoded from a coord-group event.
    ///
    /// The host is responsible for decrypting the event (via MLS) into the
    /// payload and decoding it via [`decode_coord_msg`]; the resulting [`CoordMsg`]
    /// plus its source `group_id` are passed in.
    pub fn handle_coord_msg(
        &mut self,
        mls: &MoatSession,
        my_did: &str,
        group_id: &[u8],
        msg: CoordMsg,
    ) -> Vec<RingCommand> {
        let mut cmds = Vec::new();
        let my_device_id = *mls.device_id();

        let from_device_id: [u8; 16] = {
            let members = mls.get_group_members(group_id).unwrap_or_default();
            members
                .iter()
                .find_map(|(_, c)| {
                    c.as_ref().and_then(|c| {
                        if c.did() == my_did && *c.device_id() != my_device_id {
                            Some(*c.device_id())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or([0u8; 16])
        };

        match msg {
            CoordMsg::Hello { sender_device_id } => {
                let id: [u8; 16] = sender_device_id.try_into().unwrap_or(from_device_id);
                self.process_hello(id);
            }
            CoordMsg::RingInfo { ring_id, created_at } => {
                if let Some(mine_id) = self.ring_group_id.clone() {
                    match reconcile_rings(
                        &mine_id,
                        self.ring_created_at.unwrap_or(0),
                        &ring_id,
                        created_at,
                    ) {
                        ReconcileDecision::AlreadyInTheirs | ReconcileDecision::KeepMine => {}
                        ReconcileDecision::SwitchToTheirs => {
                            self.ring_group_id = None;
                            self.ring_created_at = None;
                        }
                    }
                }
            }
            CoordMsg::Supersede { old_ring_id } => {
                self.process_supersede(&old_ring_id);
            }
            CoordMsg::RingWelcome { ring_id, welcome, created_at } => {
                if self.ring_group_id.is_none() {
                    if let Ok(joined_id) = mls.process_welcome(&welcome) {
                        if joined_id == ring_id {
                            self.ring_group_id = Some(ring_id.clone());
                            self.ring_created_at = Some(created_at);
                            cmds.push(RingCommand::RegisterGroup {
                                group_id: ring_id,
                                kind: GroupKind::Ring,
                            });
                        }
                    }
                }
            }
            CoordMsg::SyncOffer { token } => {
                cmds.push(RingCommand::SendDrawbridgePairJoin { token });
            }
        }

        cmds
    }

    /// Encrypt and publish a `RingWelcome` into a sibling's coord group.
    ///
    /// Internal helper used by [`tick`].
    fn emit_ring_welcome_to_coord(
        &self,
        mls: &MoatSession,
        key_bundle: &[u8],
        sibling_id: [u8; 16],
        ring_id: &[u8],
        welcome: &[u8],
        out: &mut Vec<RingCommand>,
    ) {
        let coord_id = match self.coord_groups.get(&sibling_id) {
            Some(id) => id.clone(),
            None => return,
        };
        let msg = CoordMsg::RingWelcome {
            ring_id: ring_id.to_vec(),
            welcome: welcome.to_vec(),
            created_at: self.ring_created_at.unwrap_or(0),
        };
        let epoch = mls.get_group_epoch(&coord_id).ok().flatten().unwrap_or(0);
        let ev = Event::coord(coord_id.clone(), epoch, encode_coord_msg(&msg));
        if let Ok(enc) = mls.encrypt_event(&coord_id, key_bundle, &ev) {
            out.push(RingCommand::PublishEvent {
                tag: enc.tag,
                ciphertext: enc.ciphertext,
                mark_own: true,
            });
        }
    }
}

/// Sibling key package fed into [`DeviceRingDriver::tick`].
#[derive(Debug, Clone)]
pub struct KeyPackageInput {
    /// Raw TLS-serialised MLS key package.
    pub key_package: Vec<u8>,
}

/// Own-PDS event fed into [`DeviceRingDriver::tick`] for stealth scan.
#[derive(Debug, Clone)]
pub struct OwnEventInput {
    /// Record rkey, used to advance the cursor across calls.
    pub rkey: String,
    /// Raw stealth-encrypted ciphertext as fetched from the PDS.
    pub ciphertext: Vec<u8>,
}

/// Inputs to a single ring-driver tick.
///
/// All slices are pre-fetched by the host: ring tick is a pure step that
/// consumes them and emits commands, never doing I/O itself.
pub struct TickInputs<'a> {
    /// Key packages fetched from our own PDS (includes our own; tick filters them).
    pub key_packages: &'a [KeyPackageInput],
    /// Stealth scan-pubkeys for all of our devices, used for outgoing Welcome
    /// encryption.
    pub stealth_pubkeys: &'a [[u8; 32]],
    /// Own-PDS event records since `own_events_cursor`, used for incoming Welcome
    /// scan.
    pub own_events: &'a [OwnEventInput],
    /// Our stealth scan private key, used to decrypt incoming Welcomes.
    pub stealth_privkey: &'a [u8; 32],
    /// Our credential.
    pub credential: &'a MoatCredential,
    /// Identity key bundle.
    pub key_bundle: &'a [u8],
    /// Wall-clock time (ms since epoch); used as `ring_created_at` when we
    /// create a new ring.
    pub now_ms: i64,
    /// Whether the host's main Drawbridge WS is connected (gate for SyncOffer).
    pub drawbridge_has_own_connection: bool,
    /// Whether a sync session is already running (avoids re-arming).
    pub sync_session_active: bool,
    /// Our DID, used to classify groups by member credentials.
    pub my_did: &'a str,
}

/// Side effect requested by the ring driver. The host interprets these in
/// terms of its own I/O layer (PDS publish, Drawbridge frames, persistence).
#[derive(Debug, Clone)]
pub enum RingCommand {
    /// Publish a tagged event to the PDS event stream. If `mark_own` is true,
    /// the host should add `tag` to its own-published-tags set so the eventual
    /// echo is skipped (MLS forbids self-decryption).
    PublishEvent {
        tag: [u8; 16],
        ciphertext: Vec<u8>,
        mark_own: bool,
    },
    /// Publish a stealth-encrypted Welcome ciphertext under a random tag.
    /// Stealth payloads are decrypted out-of-band by recipients, so they are
    /// **not** marked as own.
    StealthPublishWelcome {
        tag: [u8; 16],
        ciphertext: Vec<u8>,
    },
    /// We just joined a coord group via Welcome — replenish our consumed key
    /// package so siblings can still add us to the ring.
    ReplenishKeyPackage,
    /// Register a newly-classified group with the host's metadata store and
    /// candidate-tag set.
    RegisterGroup {
        group_id: Vec<u8>,
        kind: GroupKind,
    },
    /// Initiate the Drawbridge pair flow as the offerer (history sync).
    SendDrawbridgePairOffer {
        token: Vec<u8>,
    },
    /// Initiate the Drawbridge pair flow as the joiner (history sync).
    SendDrawbridgePairJoin {
        token: Vec<u8>,
    },
    /// A new sibling joined the ring; immediately add them to all existing
    /// user conversations.
    PollForNewDevices,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MoatCredential, MoatSession};

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
    fn coord_msg_roundtrip_sync_offer() {
        let msg = CoordMsg::SyncOffer { token: vec![0xFFu8; 32] };
        let decoded = decode_coord_msg(&encode_coord_msg(&msg)).unwrap();
        assert!(matches!(decoded, CoordMsg::SyncOffer { token } if token == vec![0xFFu8; 32]));
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
            CoordMsg::SyncOffer {
                token: vec![0u8; 32],
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

    fn empty_driver() -> DeviceRingDriver {
        DeviceRingDriver {
            ring_group_id: None,
            ring_created_at: None,
            coord_groups: HashMap::new(),
            sibling_sent_hello: HashSet::new(),
            own_events_cursor: None,
            ring_has_new_sibling: false,
        }
    }

    /// First tick with a sibling key package should:
    /// - create a coord group
    /// - emit RegisterGroup, two PublishEvent commands (commit + Hello),
    ///   and a StealthPublishWelcome.
    #[test]
    fn tick_creates_coord_group_for_new_sibling() {
        let alice = MoatSession::new();
        let bob = MoatSession::new();

        let alice_cred = MoatCredential::new("did:plc:alice", "laptop", *alice.device_id());
        let bob_cred = MoatCredential::new("did:plc:alice", "phone", *bob.device_id());

        let (bob_kp, _bob_kb) = bob.generate_key_package(&bob_cred).unwrap();
        let (_, alice_kb) = alice.generate_key_package(&alice_cred).unwrap();

        let stealth_priv = [0xAAu8; 32];
        let stealth_pubkeys = [[0xBBu8; 32]];

        let inputs = TickInputs {
            key_packages: &[KeyPackageInput { key_package: bob_kp.clone() }],
            stealth_pubkeys: &stealth_pubkeys,
            own_events: &[],
            stealth_privkey: &stealth_priv,
            credential: &alice_cred,
            key_bundle: &alice_kb,
            now_ms: 1_000_000,
            drawbridge_has_own_connection: false,
            sync_session_active: false,
            my_did: "did:plc:alice",
        };

        let mut driver = empty_driver();
        let cmds = driver.tick(&alice, inputs);

        assert!(driver.coord_groups.contains_key(bob.device_id()));
        let register_count = cmds
            .iter()
            .filter(|c| matches!(c, RingCommand::RegisterGroup { kind: GroupKind::DeviceCoord, .. }))
            .count();
        assert_eq!(register_count, 1, "expected one DeviceCoord registration");
        let publish_count = cmds
            .iter()
            .filter(|c| matches!(c, RingCommand::PublishEvent { .. }))
            .count();
        assert!(publish_count >= 2, "expected commit+Hello publishes, got {publish_count}");
        let welcome_count = cmds
            .iter()
            .filter(|c| matches!(c, RingCommand::StealthPublishWelcome { .. }))
            .count();
        assert_eq!(welcome_count, 1, "expected one stealth Welcome");
    }

    /// After a Hello has been received and we have a coord group, tick should
    /// bootstrap the ring (creator picks lowest device_id).
    #[test]
    fn tick_bootstraps_ring_when_hello_exchanged() {
        // Run until we draw a session pair where alice has the smaller id —
        // that's the role responsible for creating the ring.
        let (alice, bob) = loop {
            let a = MoatSession::new();
            let b = MoatSession::new();
            if a.device_id() < b.device_id() {
                break (a, b);
            }
        };

        let alice_cred = MoatCredential::new("did:plc:alice", "laptop", *alice.device_id());
        let bob_cred = MoatCredential::new("did:plc:alice", "phone", *bob.device_id());

        let (bob_kp, _) = bob.generate_key_package(&bob_cred).unwrap();
        let (_, alice_kb) = alice.generate_key_package(&alice_cred).unwrap();

        // Pre-state: coord group already exists between alice and bob, and
        // alice has received bob's Hello.
        let coord = alice
            .create_device_coord_group(&alice_cred, &alice_kb, &bob_kp)
            .unwrap();

        let bob_dev_id = *bob.device_id();
        let mut driver = empty_driver();
        driver.coord_groups.insert(bob_dev_id, coord.group_id.clone());
        driver.process_hello(bob_dev_id);

        // Need a fresh sibling key package for the ring add.
        let (bob_kp2, _) = bob.generate_key_package(&bob_cred).unwrap();

        let inputs = TickInputs {
            key_packages: &[KeyPackageInput { key_package: bob_kp2 }],
            stealth_pubkeys: &[],
            own_events: &[],
            stealth_privkey: &[0u8; 32],
            credential: &alice_cred,
            key_bundle: &alice_kb,
            now_ms: 2_000_000,
            drawbridge_has_own_connection: false,
            sync_session_active: false,
            my_did: "did:plc:alice",
        };

        let cmds = driver.tick(&alice, inputs);

        assert!(driver.ring_group_id.is_some(), "ring should be created");
        assert_eq!(driver.ring_created_at, Some(2_000_000));

        let ring_register = cmds
            .iter()
            .any(|c| matches!(c, RingCommand::RegisterGroup { kind: GroupKind::Ring, .. }));
        assert!(ring_register, "expected RegisterGroup(Ring)");
        let poll_cmd = cmds
            .iter()
            .any(|c| matches!(c, RingCommand::PollForNewDevices));
        assert!(poll_cmd, "expected PollForNewDevices after sibling joined");
    }

    /// `handle_coord_msg(SyncOffer)` must emit a SendDrawbridgePairJoin command
    /// regardless of group state.
    #[test]
    fn handle_coord_msg_sync_offer_emits_pair_join() {
        let session = MoatSession::new();
        let mut driver = empty_driver();
        let cmds = driver.handle_coord_msg(
            &session,
            "did:plc:alice",
            &[0u8; 16],
            CoordMsg::SyncOffer { token: vec![1, 2, 3, 4] },
        );
        assert_eq!(cmds.len(), 1);
        assert!(matches!(
            &cmds[0],
            RingCommand::SendDrawbridgePairJoin { token } if token == &vec![1, 2, 3, 4]
        ));
    }

    /// `handle_coord_msg(Hello)` updates `sibling_sent_hello` and emits no
    /// commands.
    #[test]
    fn handle_coord_msg_hello_no_commands() {
        let session = MoatSession::new();
        let mut driver = empty_driver();
        let cmds = driver.handle_coord_msg(
            &session,
            "did:plc:alice",
            &[0u8; 16],
            CoordMsg::Hello { sender_device_id: vec![9u8; 16] },
        );
        assert!(cmds.is_empty());
        assert!(driver.sibling_sent_hello.contains(&[9u8; 16]));
    }

    /// `handle_coord_msg(Supersede)` clears matching ring state.
    #[test]
    fn handle_coord_msg_supersede_clears_ring() {
        let session = MoatSession::new();
        let mut driver = empty_driver();
        driver.ring_group_id = Some(vec![0xAAu8; 16]);
        driver.ring_created_at = Some(1234);
        let cmds = driver.handle_coord_msg(
            &session,
            "did:plc:alice",
            &[0u8; 16],
            CoordMsg::Supersede { old_ring_id: vec![0xAAu8; 16] },
        );
        assert!(cmds.is_empty());
        assert!(driver.ring_group_id.is_none());
    }

    // ── End-to-end interop test ─────────────────────────────────────────────
    //
    // Drives two `DeviceRingDriver`s through the full multi-device bootstrap
    // protocol via a shared fake PDS. Catches state-machine divergence bugs
    // independent of host glue.

    use crate::generate_stealth_keypair;
    use std::collections::VecDeque;

    /// Per-side state for the interop simulation.
    struct DeviceSim {
        mls: MoatSession,
        cred: MoatCredential,
        /// Initial key package matching `key_bundle`. Uploaded to the fake PDS
        /// so siblings can build a coord group that targets us.
        key_package: Vec<u8>,
        key_bundle: Vec<u8>,
        stealth_priv: [u8; 32],
        stealth_pub: [u8; 32],
        driver: DeviceRingDriver,
        cursor: Option<String>,
        /// All groups this side has registered (coord + ring). Used to attempt
        /// MLS decrypt of incoming events — mirrors how a real host scans
        /// against its full group catalog rather than only `coord_groups`.
        known_groups: Vec<Vec<u8>>,
        /// Coord messages we've received on coord groups (decrypted).
        pending_coord_msgs: VecDeque<(Vec<u8>, CoordMsg)>,
        /// rkeys of events already decrypted into `pending_coord_msgs` so
        /// re-scans don't double-feed.
        seen_rkeys: HashSet<String>,
    }

    impl DeviceSim {
        fn new(did: &str, name: &str) -> Self {
            let mls = MoatSession::new();
            let cred = MoatCredential::new(did, name, *mls.device_id());
            let (key_package, key_bundle) = mls.generate_key_package(&cred).unwrap();
            let (sp, spub) = generate_stealth_keypair();
            Self {
                mls,
                cred,
                key_package,
                key_bundle,
                stealth_priv: sp,
                stealth_pub: spub,
                driver: DeviceRingDriver {
                    ring_group_id: None,
                    ring_created_at: None,
                    coord_groups: HashMap::new(),
                    sibling_sent_hello: HashSet::new(),
                    own_events_cursor: None,
                    ring_has_new_sibling: false,
                },
                cursor: None,
                known_groups: Vec::new(),
                pending_coord_msgs: VecDeque::new(),
                seen_rkeys: HashSet::new(),
            }
        }
    }

    /// Shared fake PDS for one DID.
    #[derive(Default)]
    struct FakePds {
        /// Available key packages. Each key package is consumed (removed) when
        /// processed by `create_device_coord_group` or `add_device`.
        key_packages: Vec<Vec<u8>>,
        /// Stealth scan public keys (one per device).
        stealth_pubkeys: Vec<[u8; 32]>,
        /// All published events with their rkeys (monotonically increasing).
        events: Vec<(String, [u8; 16], Vec<u8>)>,
        /// Tags published by each device in the current iteration. Used to
        /// route coord-group events into the right side's pending queue.
        own_published_tags: HashSet<[u8; 16]>,
        next_rkey: u64,
    }

    impl FakePds {
        fn publish(&mut self, tag: [u8; 16], ct: Vec<u8>, mark_own: bool) {
            self.next_rkey += 1;
            let rkey = format!("rk{:08}", self.next_rkey);
            self.events.push((rkey, tag, ct));
            if mark_own {
                self.own_published_tags.insert(tag);
            }
        }

        fn events_after(&self, cursor: Option<&str>) -> Vec<OwnEventInput> {
            let mut out = Vec::new();
            let start_after = cursor.unwrap_or("");
            for (rk, _tag, ct) in &self.events {
                if rk.as_str() > start_after {
                    out.push(OwnEventInput {
                        rkey: rk.clone(),
                        ciphertext: ct.clone(),
                    });
                }
            }
            out
        }
    }

    /// Helper: feed PDS events into the group-decrypt path, queuing decoded
    /// `CoordMsg`s for `handle_coord_msg`.
    ///
    /// We attempt MLS decrypt against every group this side knows about
    /// (coord + ring). Success means the event belongs to that group; failure
    /// is silently ignored — exactly mirroring how a real host scans incoming
    /// events against its full group catalog.
    fn drain_coord_messages(side: &mut DeviceSim, pds: &FakePds) {
        let groups = side.known_groups.clone();
        for (rk, _tag, ct) in &pds.events {
            if side.seen_rkeys.contains(rk) {
                continue;
            }
            for gid in &groups {
                if let Ok(outcome) = side.mls.decrypt_event(gid, ct) {
                    if matches!(outcome.result().event.kind, crate::EventKind::Coord) {
                        if let Ok(msg) = decode_coord_msg(&outcome.result().event.payload) {
                            side.pending_coord_msgs.push_back((gid.clone(), msg));
                        }
                    }
                    side.seen_rkeys.insert(rk.clone());
                    break;
                }
            }
        }
    }

    /// Two-device ring bootstrap exercised entirely through `tick()` and
    /// `handle_coord_msg()`. Both sides share a single fake PDS.
    #[test]
    fn two_device_bootstrap_via_command_loop() {
        let did = "did:plc:alice";

        // Loop until alice's session-random device id is smaller than bob's:
        // the ring-creator role is assigned to the smallest device id, and
        // the assertions below assume alice is the creator.
        let (mut alice, mut bob) = loop {
            let a = DeviceSim::new(did, "laptop");
            let b = DeviceSim::new(did, "phone");
            if a.mls.device_id() < b.mls.device_id() {
                break (a, b);
            }
        };

        let mut pds = FakePds::default();
        pds.stealth_pubkeys.push(alice.stealth_pub);
        pds.stealth_pubkeys.push(bob.stealth_pub);

        // Upload each side's initial key package (matching their stored
        // key_bundle, so siblings can target it for coord-group creation).
        pds.key_packages.push(alice.key_package.clone());
        pds.key_packages.push(bob.key_package.clone());

        let mut now: i64 = 1_000_000;

        // Iterate the protocol loop until both sides agree on a ring.
        for _iter in 0..10 {
            for side in [&mut alice, &mut bob] {
                let kps: Vec<KeyPackageInput> = pds
                    .key_packages
                    .iter()
                    .map(|k| KeyPackageInput { key_package: k.clone() })
                    .collect();
                let own_events = pds.events_after(side.cursor.as_deref());

                let inputs = TickInputs {
                    key_packages: &kps,
                    stealth_pubkeys: &pds.stealth_pubkeys,
                    own_events: &own_events,
                    stealth_privkey: &side.stealth_priv,
                    credential: &side.cred,
                    key_bundle: &side.key_bundle,
                    now_ms: now,
                    drawbridge_has_own_connection: false,
                    sync_session_active: false,
                    my_did: did,
                };
                now += 1;

                let cmds = side.driver.tick(&side.mls, inputs);
                interpret_for(side, &mut pds, cmds);
                side.cursor = side.driver.own_events_cursor.clone();

                // Decrypt any newly visible coord-group events.
                drain_coord_messages(side, &pds);
                while let Some((gid, msg)) = side.pending_coord_msgs.pop_front() {
                    let cmds = side.driver.handle_coord_msg(&side.mls, did, &gid, msg);
                    interpret_for(side, &mut pds, cmds);
                }
            }

            if alice.driver.ring_group_id.is_some()
                && bob.driver.ring_group_id.is_some()
                && alice.driver.ring_group_id == bob.driver.ring_group_id
            {
                break;
            }
        }

        // Both sides should now agree on a ring.
        assert!(
            alice.driver.ring_group_id.is_some(),
            "alice should have ring"
        );
        assert!(bob.driver.ring_group_id.is_some(), "bob should have ring");
        assert_eq!(
            alice.driver.ring_group_id, bob.driver.ring_group_id,
            "rings must match"
        );

        // The ring should contain both device IDs as members.
        let ring_id = alice.driver.ring_group_id.clone().unwrap();
        let alice_members = alice.mls.get_group_members(&ring_id).unwrap();
        let alice_dev_ids: HashSet<[u8; 16]> = alice_members
            .iter()
            .filter_map(|(_, c)| c.as_ref().map(|c| *c.device_id()))
            .collect();
        assert!(alice_dev_ids.contains(alice.mls.device_id()));
        assert!(alice_dev_ids.contains(bob.mls.device_id()));
    }

    /// Interpret a list of `RingCommand`s, recording group registrations on
    /// `side` and routing publishes through the shared PDS.
    fn interpret_for(side: &mut DeviceSim, pds: &mut FakePds, cmds: Vec<RingCommand>) {
        for cmd in cmds {
            match cmd {
                RingCommand::PublishEvent { tag, ciphertext, mark_own } => {
                    pds.publish(tag, ciphertext, mark_own);
                }
                RingCommand::StealthPublishWelcome { tag, ciphertext } => {
                    pds.publish(tag, ciphertext, false);
                }
                RingCommand::RegisterGroup { group_id, .. } => {
                    if !side.known_groups.iter().any(|g| g == &group_id) {
                        side.known_groups.push(group_id);
                    }
                }
                RingCommand::ReplenishKeyPackage => {
                    // Generate a fresh key package and upload it. The previous
                    // KP was consumed by a coord-group join, so siblings need
                    // a new one to add us to the ring. Keep `side.key_bundle`
                    // pinned to the original leaf — MLS retains the new KP's
                    // private state internally; the original bundle is what
                    // existing groups continue to operate against.
                    if let Ok((kp, _kb)) = side.mls.generate_key_package(&side.cred) {
                        pds.key_packages.push(kp);
                    }
                }
                RingCommand::SendDrawbridgePairOffer { .. } => {} // sync flow
                RingCommand::SendDrawbridgePairJoin { .. } => {}
                RingCommand::PollForNewDevices => {}
            }
        }
    }
}
