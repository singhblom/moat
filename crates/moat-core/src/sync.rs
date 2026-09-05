//! History sync state machine.
//!
//! [`SyncSession`] is a pure state machine driven by the host layer. It
//! produces [`SyncOutput`] values describing what the caller should do (send
//! a frame, store messages, mark the session done). No I/O or async here.
//!
//! Wire format: each [`SyncMsg`] is JSON-encoded, padded to the nearest
//! bucket size, then encrypted via the ring MLS group (`encrypt_event` with
//! `EventKind::SyncApp`) and sent as a raw binary frame on the pair WS.
//!
//! The wire type [`SyncMessage`] is the canonical message representation
//! transferred during sync. Hosts (moat-cli, moat-dart) adapt it to/from
//! their own `StoredMessage` type at the FFI / state-machine boundary.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::{DigestAnchor, Error, MoatSession, Result};

// ── Wire types ────────────────────────────────────────────────────────────────

/// What one side holds for a conversation, as declared in [`SyncMsg::Hello`].
///
/// A span cannot describe a hole in the middle of a history, which is
/// exactly the shape a device ends up with after being offline past the
/// point where it can still decrypt what it missed — so the normal case
/// enumerates. At roughly 13 bytes per rkey that is far cheaper than the
/// messages it saves, which is why no digest comparison or bisection is
/// needed to plan a transfer.
///
/// The variants exist so "I hold nothing" and "I am not listing what I
/// hold" can never be confused for one another: they want opposite
/// responses from the peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvInventory {
    /// Every rkey held, enumerated. The peer sends exactly the complement.
    Complete { rkeys: Vec<String> },
    /// Too large to enumerate inside the Hello's byte budget, so only the
    /// span is given. The peer can narrow to what falls outside it, but
    /// cannot see holes within it.
    Range {
        oldest: String,
        newest: String,
        count: u64,
    },
    /// Nothing held at all.
    Empty,
}

impl ConvInventory {
    /// Build the most precise inventory for a set of held rkeys.
    pub fn of(rkeys: Vec<String>) -> Self {
        if rkeys.is_empty() {
            ConvInventory::Empty
        } else {
            ConvInventory::Complete { rkeys }
        }
    }

    /// `true` when the declaring side holds no messages at all.
    pub fn is_empty(&self) -> bool {
        match self {
            ConvInventory::Empty => true,
            ConvInventory::Complete { rkeys } => rkeys.is_empty(),
            ConvInventory::Range { count, .. } => *count == 0,
        }
    }

    /// Roughly what this costs inside a JSON Hello, for budgeting.
    fn encoded_size(&self) -> usize {
        match self {
            // Each entry is the rkey plus quotes and a separator.
            ConvInventory::Complete { rkeys } => {
                rkeys.iter().map(|r| r.len() + 3).sum::<usize>() + 32
            }
            ConvInventory::Range { oldest, newest, .. } => oldest.len() + newest.len() + 64,
            ConvInventory::Empty => 16,
        }
    }

    /// Drop from an enumeration to a span, keeping the conversation
    /// describable when the full list will not fit.
    fn downgrade(&self) -> Option<Self> {
        match self {
            ConvInventory::Complete { rkeys } if !rkeys.is_empty() => {
                let mut sorted: Vec<&String> = rkeys.iter().collect();
                sorted.sort();
                Some(ConvInventory::Range {
                    oldest: sorted.first().map(|s| (*s).clone())?,
                    newest: sorted.last().map(|s| (*s).clone())?,
                    count: rkeys.len() as u64,
                })
            }
            _ => None,
        }
    }
}

/// Per-conversation state included in the [`SyncMsg::Hello`] handshake.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConvState {
    /// Conversation MLS group ID.
    #[serde_as(as = "Base64")]
    pub group_id: Vec<u8>,
    /// Digest tip (32 bytes).
    #[serde_as(as = "Base64")]
    pub tip_digest: Vec<u8>,
    /// Digest anchors at epoch boundaries.
    pub anchors: Vec<AnchorDto>,
    /// What this side holds for the conversation.
    pub inventory: ConvInventory,
}

/// Byte budget for all inventories in one `Hello`.
///
/// The pair WS closes the connection on any frame over 1 MiB, and a Hello
/// carries *every* conversation — so a per-conversation cap guards the
/// wrong dimension: fifty conversations of two thousand messages each
/// exceeds the limit with no single conversation anywhere near a
/// per-conversation bound. Budgeting the whole frame is what keeps the
/// session alive; the headroom below the hard limit covers MLS framing,
/// bucket padding, and the rest of the message.
pub const HELLO_INVENTORY_BUDGET_BYTES: usize = 512 * 1024;

/// Fit a Hello's inventories inside [`HELLO_INVENTORY_BUDGET_BYTES`] by
/// downgrading the largest enumerations to spans until the total fits.
///
/// Largest-first so the fewest conversations lose precision, and
/// deterministic so both sides of a session make the same choice from the
/// same data.
pub fn fit_hello_inventories(convs: &mut [ConvState]) {
    let mut total: usize = convs.iter().map(|c| c.inventory.encoded_size()).sum();
    if total <= HELLO_INVENTORY_BUDGET_BYTES {
        return;
    }
    let mut order: Vec<usize> = (0..convs.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(convs[i].inventory.encoded_size()));
    for i in order {
        if total <= HELLO_INVENTORY_BUDGET_BYTES {
            break;
        }
        if let Some(downgraded) = convs[i].inventory.downgrade() {
            total -= convs[i].inventory.encoded_size();
            total += downgraded.encoded_size();
            convs[i].inventory = downgraded;
        }
    }
}

/// Digest anchor in the on-wire form (DTO mirrors [`DigestAnchor`] but uses
/// `Vec<u8>` for the digest so it serialises cleanly with `serde_with`).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorDto {
    pub rkey: String,
    #[serde_as(as = "Base64")]
    pub digest: Vec<u8>,
}

impl From<&DigestAnchor> for AnchorDto {
    fn from(a: &DigestAnchor) -> Self {
        Self { rkey: a.rkey.clone(), digest: a.digest.to_vec() }
    }
}

/// Direction of a sync flow.
///
/// `Backward` = transferring older messages from a donor to a new joiner.
/// `Forward` = transferring newer messages a peer is missing (Phase 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncDirection {
    Forward,
    Backward,
}

/// Plaintext message exchanged during a sync session.
///
/// Mirrors the host's `StoredMessage` but with explicit, JSON-friendly fields.
/// Optional values use `Option<…>` directly so they round-trip through JSON
/// without sentinel values.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncMessage {
    pub rkey: String,
    #[serde_as(as = "Option<Base64>")]
    pub message_id: Option<Vec<u8>>,
    pub sender_did: String,
    pub sender_device_name: String,
    pub timestamp_ms: i64,
    pub content: String,
    pub is_own: bool,
    pub blob_uri: Option<String>,
    #[serde_as(as = "Option<Base64>")]
    pub blob_key: Option<Vec<u8>>,
    #[serde_as(as = "Option<Base64>")]
    pub blob_ciphertext_hash: Option<Vec<u8>>,
    pub blob_ciphertext_size: Option<u64>,
    #[serde_as(as = "Option<Base64>")]
    pub blob_content_hash: Option<Vec<u8>>,
    pub blob_mime: Option<String>,
    pub blob_width: Option<u32>,
    pub blob_height: Option<u32>,
}

/// The sync protocol message, serialised to JSON and transmitted as a
/// ring-MLS-encrypted binary frame on the pair WebSocket.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncMsg {
    /// Initial handshake: each side sends its conversation state.
    Hello {
        convs: Vec<ConvState>,
        ring_epoch: u64,
    },
    /// Forward-sync manifest request (Phase 6).
    ManifestReq {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        from_rkey: Option<String>,
        to_rkey: Option<String>,
    },
    /// Forward-sync manifest response (Phase 6).
    Manifest {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        rkeys: Vec<String>,
    },
    /// Backward-sync batch request.
    BatchReq {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        from_rkey: Option<String>,
        to_rkey: Option<String>,
        cursor: Option<String>,
    },
    /// Backward-sync batch with messages.
    Batch {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        messages: Vec<SyncMessage>,
        next_cursor: Option<String>,
    },
    /// All messages for `group_id` in `direction` have been sent.
    Done {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        direction: SyncDirection,
    },
}

/// Encode a [`SyncMsg`] to raw JSON bytes.
///
/// No extra padding is applied here — the MLS `encrypt_event` call applies
/// bucket padding before the frame goes on the pair WS.
pub fn encode_sync_msg(msg: &SyncMsg) -> Vec<u8> {
    serde_json::to_vec(msg).expect("SyncMsg serialization should never fail")
}

/// Decode a [`SyncMsg`] from raw JSON bytes.
pub fn decode_sync_msg(bytes: &[u8]) -> std::result::Result<SyncMsg, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("SyncMsg decode: {e}"))
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Action produced by [`SyncSession`] for the host to interpret.
#[derive(Debug)]
pub enum SyncOutput {
    /// JSON-encode, encrypt via ring MLS, and send as a binary pair-WS frame.
    Send(SyncMsg),
    /// Persist these messages for the conversation `conv_id` (hex group ID).
    ///
    /// The host converts each [`SyncMessage`] to its native stored form
    /// (e.g. `StoredMessage` in moat-cli, `Message` in moat-dart) and merges
    /// them into local message storage.
    Store {
        conv_id: String,
        messages: Vec<SyncMessage>,
    },
}

/// Session phase. Internal — exposed only via [`SyncSession::is_done`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Pair WS is attached; [`SyncSession::on_paired`] hasn't been called yet.
    SendingHello,
    /// We've sent Hello; waiting for peer's Hello.
    WaitingHello,
    /// Hello exchanged; in progress (sending/receiving BatchReqs/Batches).
    Active,
    /// All Done messages sent and received.
    Done,
}

/// Per-conversation sync plan derived from the Hello exchange.
#[derive(Debug)]
struct ConvPlan {
    group_id: Vec<u8>,
    conv_id: String,
    /// Our messages to send (donor side, backward sync).
    our_messages: Vec<SyncMessage>,
    /// Whether we expect to receive a batch from the peer.
    expecting_batch: bool,
    /// Whether we've sent `Done{Backward}` for this conversation.
    sent_done: bool,
    /// Whether we've received `Done{Backward}` for this conversation.
    received_done: bool,
}

/// History sync session state machine.
///
/// Drives the bidirectional message-transfer flow over an established pair WS.
/// Pure: [`on_paired`] / [`on_message`] take inputs and return outputs; no
/// state lives outside the struct.
#[derive(Debug)]
pub struct SyncSession {
    phase: Phase,
    plans: Vec<ConvPlan>,
}

impl Default for SyncSession {
    fn default() -> Self {
        Self::new()
    }
}

const BATCH_SIZE: usize = 50;

impl SyncSession {
    /// Create a new session in the `SendingHello` phase. Add per-conversation
    /// state via [`add_conv_plan`] before calling [`on_paired`].
    pub fn new() -> Self {
        Self { phase: Phase::SendingHello, plans: Vec::new() }
    }

    /// Populate the plan for one conversation.
    ///
    /// `our_messages` is the (already-converted) list of messages this side
    /// can serve to the peer. `expecting_batch` = `true` if the peer might
    /// send us its own backward batch (typically `true` on a new joiner with
    /// no local history).
    pub fn add_conv_plan(
        &mut self,
        group_id: Vec<u8>,
        conv_id: String,
        our_messages: Vec<SyncMessage>,
        expecting_batch: bool,
    ) {
        self.plans.push(ConvPlan {
            group_id,
            conv_id,
            our_messages,
            expecting_batch,
            sent_done: false,
            received_done: false,
        });
    }

    /// Called when the pair WS reaches the `paired` state. Returns the Hello
    /// frame to send.
    pub fn on_paired(&mut self, our_convs: Vec<ConvState>, ring_epoch: u64) -> Vec<SyncOutput> {
        self.phase = Phase::WaitingHello;
        vec![SyncOutput::Send(SyncMsg::Hello { convs: our_convs, ring_epoch })]
    }

    /// Feed a received and decrypted [`SyncMsg`] into the state machine.
    ///
    /// `mls` records the sync watermark as batches land, so an interrupted
    /// transfer resumes rather than restarting — see
    /// [`handle_batch`](Self::handle_batch).
    ///
    /// `our_did` is reserved for future per-DID logic (Phase 6); it is
    /// currently unused but kept in the signature for API stability.
    /// Feed a received and decrypted [`SyncMsg`] into the state machine.
    ///
    /// An empty output list means exactly one thing: the message was
    /// handled and there is nothing to send or store yet. Anything the
    /// session cannot account for — a batch for a conversation it has no
    /// plan for, a variant it does not implement — is an error rather than
    /// a silent drop, since both of those lose messages the peer believed
    /// it had delivered.
    ///
    /// Completion is deliberately *not* an output: the caller applies the
    /// outputs and then asks [`is_done`](Self::is_done). Reporting it in
    /// the list would let a caller that acts in order tear the channel down
    /// before flushing whatever follows.
    pub fn on_message(
        &mut self,
        mls: &MoatSession,
        msg: SyncMsg,
        our_did: &str,
    ) -> Result<Vec<SyncOutput>> {
        let _ = our_did;
        match msg {
            SyncMsg::Hello { convs: peer_convs, .. } => Ok(self.handle_hello(peer_convs)),
            SyncMsg::BatchReq { group_id, from_rkey, to_rkey, cursor } => {
                Ok(self.handle_batch_req(group_id, from_rkey, to_rkey, cursor))
            }
            SyncMsg::Batch { group_id, messages, next_cursor } => {
                self.handle_batch(mls, group_id, messages, next_cursor)
            }
            SyncMsg::Done { group_id, direction: SyncDirection::Backward } => {
                Ok(self.handle_done_backward(group_id))
            }
            SyncMsg::Done { direction: SyncDirection::Forward, .. }
            | SyncMsg::ManifestReq { .. }
            | SyncMsg::Manifest { .. } => Err(Error::SyncProtocol(
                "forward sync is not implemented; the peer should not have \
                 sent this"
                    .to_string(),
            )),
        }
    }

    /// `true` once the session has reached the `Done` phase.
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    // ── Internal handlers ─────────────────────────────────────────────────────

    fn handle_hello(&mut self, peer_convs: Vec<ConvState>) -> Vec<SyncOutput> {
        self.phase = Phase::Active;
        let mut outputs = Vec::new();

        for plan in &mut self.plans {
            let peer_state = peer_convs.iter().find(|c| c.group_id == plan.group_id);
            let want_batch = match peer_state.map(|s| &s.inventory) {
                // Both directions of the diff from one enumeration: drop
                // what the peer already holds from what we will serve, and
                // ask only for what we are actually missing.
                Some(ConvInventory::Complete { rkeys }) => {
                    let peer_set: HashSet<&str> = rkeys.iter().map(String::as_str).collect();
                    let ours: HashSet<&str> =
                        plan.our_messages.iter().map(|m| m.rkey.as_str()).collect();
                    let missing_here = peer_set.iter().any(|r| !ours.contains(r));
                    plan.our_messages.retain(|m| !peer_set.contains(m.rkey.as_str()));
                    missing_here
                }
                // The peer's list did not fit, so all we know is its span.
                // Serve what falls outside it and ask for the same, which
                // cannot see holes inside the span but is far better than
                // exchanging whole histories.
                Some(ConvInventory::Range { oldest, newest, .. }) => {
                    // Taken before the retain below narrows the list.
                    let our_span = plan
                        .our_messages
                        .iter()
                        .map(|m| m.rkey.clone())
                        .fold(None::<(String, String)>, |acc, rkey| match acc {
                            None => Some((rkey.clone(), rkey)),
                            Some((lo, hi)) => Some((
                                if rkey < lo { rkey.clone() } else { lo },
                                if rkey > hi { rkey } else { hi },
                            )),
                        });
                    plan.our_messages.retain(|m| {
                        m.rkey.as_str() < oldest.as_str() || m.rkey.as_str() > newest.as_str()
                    });
                    // We cannot enumerate what they hold, so ask whenever
                    // their span reaches beyond ours.
                    match our_span {
                        Some((lo, hi)) => {
                            oldest.as_str() < lo.as_str() || newest.as_str() > hi.as_str()
                        }
                        // We hold nothing here, so anything they have is new.
                        None => true,
                    }
                }
                // Peer holds nothing, or did not mention this conversation
                // at all: nothing to ask for, everything to offer.
                Some(ConvInventory::Empty) | None => false,
            };

            plan.expecting_batch = want_batch;
            if want_batch {
                outputs.push(SyncOutput::Send(SyncMsg::BatchReq {
                    group_id: plan.group_id.clone(),
                    from_rkey: None,
                    to_rkey: None,
                    cursor: None,
                }));
            }
        }

        // Conversations only the peer knows about — a device fanned into a
        // group after its own sync plan was built.
        for peer_state in &peer_convs {
            if peer_state.inventory.is_empty() {
                continue;
            }
            if self.plans.iter().any(|p| p.group_id == peer_state.group_id) {
                continue;
            }
            let conv_id = hex::encode(&peer_state.group_id);
            self.plans.push(ConvPlan {
                group_id: peer_state.group_id.clone(),
                conv_id,
                our_messages: Vec::new(),
                expecting_batch: true,
                sent_done: false,
                received_done: false,
            });
            outputs.push(SyncOutput::Send(SyncMsg::BatchReq {
                group_id: peer_state.group_id.clone(),
                from_rkey: None,
                to_rkey: None,
                cursor: None,
            }));
        }

        // Two devices that already agree have nothing to say to each other,
        // and the Hello exchange is where that becomes knowable.
        //
        // Guarded on having *some* plan: `check_complete` folds over the
        // plan list, so an empty one is vacuously "all done". A session
        // that knows about no conversations has nothing to offer, which is
        // not the same as the exchange being finished.
        if !self.plans.is_empty() {
            self.check_complete();
        }
        outputs
    }

    fn handle_batch_req(
        &mut self,
        group_id: Vec<u8>,
        _from_rkey: Option<String>,
        _to_rkey: Option<String>,
        cursor: Option<String>,
    ) -> Vec<SyncOutput> {
        let cursor_idx: usize = cursor.as_deref().and_then(|c| c.parse().ok()).unwrap_or(0);

        let plan = match self.plans.iter_mut().find(|p| p.group_id == group_id) {
            Some(p) => p,
            None => {
                return vec![SyncOutput::Send(SyncMsg::Done {
                    group_id,
                    direction: SyncDirection::Backward,
                })];
            }
        };

        let slice: Vec<SyncMessage> = plan
            .our_messages
            .iter()
            .skip(cursor_idx)
            .take(BATCH_SIZE)
            .cloned()
            .collect();

        let next_idx = cursor_idx + slice.len();
        let is_last = next_idx >= plan.our_messages.len();
        let next_cursor = if is_last { None } else { Some(next_idx.to_string()) };

        let mut outputs = vec![SyncOutput::Send(SyncMsg::Batch {
            group_id: plan.group_id.clone(),
            messages: slice,
            next_cursor: next_cursor.clone(),
        })];

        if is_last {
            plan.sent_done = true;
            outputs.push(SyncOutput::Send(SyncMsg::Done {
                group_id: plan.group_id.clone(),
                direction: SyncDirection::Backward,
            }));
        }

        outputs
    }

    fn handle_batch(
        &mut self,
        mls: &MoatSession,
        group_id: Vec<u8>,
        messages: Vec<SyncMessage>,
        next_cursor: Option<String>,
    ) -> Result<Vec<SyncOutput>> {
        let plan = match self.plans.iter_mut().find(|p| p.group_id == group_id) {
            Some(p) => p,
            // Dropping these silently would lose messages the peer believes
            // it delivered, with nothing anywhere to say so.
            None => {
                return Err(Error::SyncProtocol(format!(
                    "batch for conversation {} which this session has no plan for",
                    hex::encode(&group_id)
                )))
            }
        };

        // Durable resume point for an interrupted transfer. Backward sync
        // streams newest-first, so the watermark ("oldest rkey received")
        // only ever moves backwards.
        //
        // Deliberately not also `append_to_digest`: that chain is ordered
        // rkey-ascending, these arrive descending, so appending on arrival
        // would corrupt it — worse than leaving backfill out. Repairing it
        // belongs with Phase 6, which consumes digests.
        if let Some(batch_oldest) = messages.iter().map(|m| m.rkey.as_str()).min() {
            let new_watermark = match mls.watermark(&group_id) {
                Some(current) if current.as_str() <= batch_oldest => current,
                _ => batch_oldest.to_string(),
            };
            // Non-fatal: a lost resume point only costs a restart.
            let _ = mls.set_watermark(&group_id, &new_watermark);
        }

        let mut outputs = vec![SyncOutput::Store {
            conv_id: plan.conv_id.clone(),
            messages,
        }];

        if next_cursor.is_some() {
            outputs.push(SyncOutput::Send(SyncMsg::BatchReq {
                group_id: plan.group_id.clone(),
                from_rkey: None,
                to_rkey: None,
                cursor: next_cursor,
            }));
        }

        Ok(outputs)
    }

    fn handle_done_backward(&mut self, group_id: Vec<u8>) -> Vec<SyncOutput> {
        if let Some(plan) = self.plans.iter_mut().find(|p| p.group_id == group_id) {
            plan.received_done = true;
        }
        self.check_complete();
        Vec::new()
    }

    /// Move to `Done` when every plan has been satisfied in both
    /// directions. Emits nothing: callers observe completion through
    /// [`is_done`](Self::is_done) *after* applying the outputs, so a
    /// channel can never be closed with sends still pending.
    fn check_complete(&mut self) {
        let all_done = self.plans.iter().all(|p| {
            (p.our_messages.is_empty() || p.sent_done)
                && (!p.expecting_batch || p.received_done)
        });
        if all_done && self.phase == Phase::Active {
            self.phase = Phase::Done;
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_msg(rkey: &str, content: &str) -> SyncMessage {
        SyncMessage {
            rkey: rkey.to_string(),
            message_id: None,
            sender_did: "did:plc:alice".to_string(),
            sender_device_name: "laptop".to_string(),
            timestamp_ms: 0,
            content: content.to_string(),
            is_own: true,
            blob_uri: None,
            blob_key: None,
            blob_ciphertext_hash: None,
            blob_ciphertext_size: None,
            blob_content_hash: None,
            blob_mime: None,
            blob_width: None,
            blob_height: None,
        }
    }

    fn empty_state(group_id: &[u8]) -> ConvState {
        ConvState {
            group_id: group_id.to_vec(),
            tip_digest: vec![0u8; 32],
            anchors: vec![],
            inventory: ConvInventory::Empty,
        }
    }

    /// A peer whose list did not fit, so it declared only its span — the
    /// reduced path, which cannot see holes inside the range.
    fn full_state(group_id: &[u8]) -> ConvState {
        ConvState {
            group_id: group_id.to_vec(),
            tip_digest: vec![1u8; 32],
            anchors: vec![],
            inventory: ConvInventory::Range {
                oldest: "a".to_string(),
                newest: "z".to_string(),
                count: 2,
            },
        }
    }

    #[test]
    fn encode_decode_roundtrip_hello() {
        let msg = SyncMsg::Hello { convs: vec![], ring_epoch: 42 };
        let decoded = decode_sync_msg(&encode_sync_msg(&msg)).unwrap();
        assert!(matches!(decoded, SyncMsg::Hello { ring_epoch: 42, .. }));
    }

    #[test]
    fn encode_decode_roundtrip_batch() {
        let msg = SyncMsg::Batch {
            group_id: vec![1, 2, 3],
            messages: vec![empty_msg("rk1", "hi")],
            next_cursor: None,
        };
        let decoded = decode_sync_msg(&encode_sync_msg(&msg)).unwrap();
        match decoded {
            SyncMsg::Batch { group_id, messages, next_cursor } => {
                assert_eq!(group_id, vec![1, 2, 3]);
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].content, "hi");
                assert!(next_cursor.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn encode_decode_roundtrip_done_backward() {
        let msg = SyncMsg::Done {
            group_id: vec![9u8; 32],
            direction: SyncDirection::Backward,
        };
        let decoded = decode_sync_msg(&encode_sync_msg(&msg)).unwrap();
        assert!(matches!(decoded, SyncMsg::Done { direction: SyncDirection::Backward, .. }));
    }

    #[test]
    fn on_paired_emits_hello() {
        let mut s = SyncSession::new();
        let outs = s.on_paired(vec![], 7);
        assert_eq!(outs.len(), 1);
        assert!(matches!(
            &outs[0],
            SyncOutput::Send(SyncMsg::Hello { ring_epoch: 7, .. })
        ));
    }

    /// Two-conversation scenario, joiner side: peer (donor) has history, we
    /// have nothing. Expect: BatchReq for each, then receive Batch+Done, then
    /// An interrupted transfer must leave a durable resume point: each
    /// batch records how far back it reached, so a device that dies
    /// mid-history (the motivating case — an old phone streaming a large
    /// backlog) resumes instead of restarting. Backward sync streams
    /// newest-first, so the watermark only ever moves *backwards*.
    #[test]
    fn backward_batches_move_the_watermark_backwards_only() {
        let mls = MoatSession::new();
        let g = vec![7u8; 32];

        let mut s = SyncSession::new();
        s.add_conv_plan(g.clone(), hex::encode(&g), vec![], true);
        let _ = s.on_paired(vec![], 0);
        let _ = s.on_message(
            &mls,
            SyncMsg::Hello { convs: vec![full_state(&g)], ring_epoch: 0 },
            "did:plc:alice",
        ).unwrap();

        assert!(
            mls.watermark(&g).is_none(),
            "no transfer progress before the first batch lands"
        );

        // Newest slice first.
        let _ = s.on_message(
            &mls,
            SyncMsg::Batch {
                group_id: g.clone(),
                messages: vec![empty_msg("r50", "newer"), empty_msg("r40", "newest-1")],
                next_cursor: Some("c".to_string()),
            },
            "did:plc:alice",
        ).unwrap();
        assert_eq!(
            mls.watermark(&g).as_deref(),
            Some("r40"),
            "watermark tracks the oldest rkey received so far"
        );

        // An older slice moves it further back.
        let _ = s.on_message(
            &mls,
            SyncMsg::Batch {
                group_id: g.clone(),
                messages: vec![empty_msg("r30", "older"), empty_msg("r20", "oldest")],
                next_cursor: None,
            },
            "did:plc:alice",
        ).unwrap();
        assert_eq!(
            mls.watermark(&g).as_deref(),
            Some("r20"),
            "watermark advances backwards as older history arrives"
        );

        // A late/duplicate newer slice must not lose the progress already made.
        let _ = s.on_message(
            &mls,
            SyncMsg::Batch {
                group_id: g.clone(),
                messages: vec![empty_msg("r45", "newer again")],
                next_cursor: None,
            },
            "did:plc:alice",
        ).unwrap();
        assert_eq!(
            mls.watermark(&g).as_deref(),
            Some("r20"),
            "a newer batch must never drag the resume point forwards"
        );
    }

    /// Complete.
    #[test]
    fn joiner_drives_full_session() {
        let mls = MoatSession::new();
        let g1 = vec![1u8; 32];
        let g2 = vec![2u8; 32];

        let mut s = SyncSession::new();
        s.add_conv_plan(g1.clone(), hex::encode(&g1), vec![], true);
        s.add_conv_plan(g2.clone(), hex::encode(&g2), vec![], true);
        let _ = s.on_paired(vec![], 0);

        // Receive peer's Hello — they have history for both.
        let outs = s.on_message(&mls, 
            SyncMsg::Hello {
                convs: vec![full_state(&g1), full_state(&g2)],
                ring_epoch: 0,
            },
            "did:plc:alice",
        ).unwrap();
        let req_count = outs
            .iter()
            .filter(|o| matches!(o, SyncOutput::Send(SyncMsg::BatchReq { .. })))
            .count();
        assert_eq!(req_count, 2, "one BatchReq per conv");

        // Receive batch + Done for g1.
        let outs = s.on_message(&mls, 
            SyncMsg::Batch {
                group_id: g1.clone(),
                messages: vec![empty_msg("r1", "hi")],
                next_cursor: None,
            },
            "did:plc:alice",
        ).unwrap();
        assert!(outs.iter().any(|o| matches!(o, SyncOutput::Store { .. })));

        let outs = s.on_message(&mls, 
            SyncMsg::Done { group_id: g1.clone(), direction: SyncDirection::Backward },
            "did:plc:alice",
        ).unwrap();
        // Not done yet — g2 still pending.
        assert!(outs.is_empty());
        assert!(!s.is_done());

        // Receive batch + Done for g2.
        let _ = s.on_message(&mls, 
            SyncMsg::Batch {
                group_id: g2.clone(),
                messages: vec![empty_msg("r2", "hey")],
                next_cursor: None,
            },
            "did:plc:alice",
        ).unwrap();
        let outs = s.on_message(&mls, 
            SyncMsg::Done { group_id: g2.clone(), direction: SyncDirection::Backward },
            "did:plc:alice",
        ).unwrap();
        // Completion is a state, not an output: the caller applies whatever
        // came back and *then* asks, so it can never close the channel with
        // sends still pending.
        assert!(outs.is_empty());
        assert!(s.is_done());
    }

    /// Donor side: we have history, peer has nothing. Expect: hold off on
    /// requesting (peer has nothing), serve BatchReq when it arrives, send
    /// Done after the last batch, complete only on peer's Done.
    #[test]
    fn donor_serves_batch_and_completes() {
        let mls = MoatSession::new();
        let g = vec![3u8; 32];
        let mut s = SyncSession::new();
        s.add_conv_plan(
            g.clone(),
            hex::encode(&g),
            vec![empty_msg("r1", "a"), empty_msg("r2", "b")],
            false,
        );
        let _ = s.on_paired(vec![full_state(&g)], 0);

        // Peer's Hello (they have nothing).
        let outs = s.on_message(&mls, 
            SyncMsg::Hello { convs: vec![empty_state(&g)], ring_epoch: 0 },
            "did:plc:alice",
        ).unwrap();
        // We do NOT send BatchReq (peer has nothing).
        assert!(!outs.iter().any(|o| matches!(o, SyncOutput::Send(SyncMsg::BatchReq { .. }))));

        // Peer requests our batch.
        let outs = s.on_message(&mls, 
            SyncMsg::BatchReq {
                group_id: g.clone(),
                from_rkey: None,
                to_rkey: None,
                cursor: None,
            },
            "did:plc:alice",
        ).unwrap();
        // We send a Batch and Done.
        let batch_count = outs
            .iter()
            .filter(|o| matches!(o, SyncOutput::Send(SyncMsg::Batch { .. })))
            .count();
        let done_count = outs
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    SyncOutput::Send(SyncMsg::Done { direction: SyncDirection::Backward, .. })
                )
            })
            .count();
        assert_eq!(batch_count, 1);
        assert_eq!(done_count, 1);
        // We've sent our Done but haven't received peer's Done yet — not complete.
        assert!(!s.is_done());

        // Peer's Done — even though `expecting_batch=false`, the protocol still
        // tears down via the peer's terminating Done.
        let outs = s.on_message(&mls, 
            SyncMsg::Done { group_id: g.clone(), direction: SyncDirection::Backward },
            "did:plc:alice",
        ).unwrap();
        // Completion is a state, not an output: the caller applies whatever
        // came back and *then* asks, so it can never close the channel with
        // sends still pending.
        assert!(outs.is_empty());
        assert!(s.is_done());
    }

    /// Donor that paginates across multiple BatchReq cursors.
    #[test]
    fn donor_paginates_with_cursor() {
        let mls = MoatSession::new();
        let g = vec![4u8; 32];
        let mut s = SyncSession::new();
        // 75 messages forces two batches (BATCH_SIZE = 50).
        let our_msgs: Vec<SyncMessage> = (0..75)
            .map(|i| empty_msg(&format!("r{i}"), "x"))
            .collect();
        s.add_conv_plan(g.clone(), hex::encode(&g), our_msgs, false);
        let _ = s.on_paired(vec![full_state(&g)], 0);
        let _ = s.on_message(&mls, 
            SyncMsg::Hello { convs: vec![empty_state(&g)], ring_epoch: 0 },
            "did:plc:alice",
        ).unwrap();

        // First BatchReq: cursor=None → returns 50, next_cursor=Some("50").
        let outs = s.on_message(&mls, 
            SyncMsg::BatchReq {
                group_id: g.clone(),
                from_rkey: None,
                to_rkey: None,
                cursor: None,
            },
            "did:plc:alice",
        ).unwrap();
        let next = outs.iter().find_map(|o| match o {
            SyncOutput::Send(SyncMsg::Batch { messages, next_cursor, .. }) => {
                Some((messages.len(), next_cursor.clone()))
            }
            _ => None,
        });
        assert_eq!(next, Some((50, Some("50".to_string()))));
        assert!(!outs
            .iter()
            .any(|o| matches!(o, SyncOutput::Send(SyncMsg::Done { .. }))));

        // Second BatchReq: cursor=Some("50") → returns 25, Done.
        let outs = s.on_message(&mls, 
            SyncMsg::BatchReq {
                group_id: g.clone(),
                from_rkey: None,
                to_rkey: None,
                cursor: Some("50".to_string()),
            },
            "did:plc:alice",
        ).unwrap();
        let last = outs.iter().find_map(|o| match o {
            SyncOutput::Send(SyncMsg::Batch { messages, next_cursor, .. }) => {
                Some((messages.len(), next_cursor.clone()))
            }
            _ => None,
        });
        assert_eq!(last, Some((25, None)));
        assert!(outs
            .iter()
            .any(|o| matches!(o, SyncOutput::Send(SyncMsg::Done { .. }))));
    }

    /// Peer's Hello mentions a conv we don't have a plan for — auto-add it
    /// and request its batch.
    #[test]
    fn unknown_peer_conv_auto_added() {
        let mls = MoatSession::new();
        let g = vec![5u8; 32];
        let mut s = SyncSession::new();
        let _ = s.on_paired(vec![], 0);
        let outs = s.on_message(&mls, 
            SyncMsg::Hello { convs: vec![full_state(&g)], ring_epoch: 0 },
            "did:plc:alice",
        ).unwrap();
        let batch_req = outs.iter().any(|o| matches!(
            o,
            SyncOutput::Send(SyncMsg::BatchReq { group_id, .. }) if *group_id == g
        ));
        assert!(batch_req, "expected BatchReq for auto-added conv");
    }

    /// BatchReq for an unknown group → reply with empty Done so the peer
    /// can mark that conversation complete.
    #[test]
    fn batch_req_unknown_group_replies_done() {
        let mls = MoatSession::new();
        let g = vec![6u8; 32];
        let mut s = SyncSession::new();
        let _ = s.on_paired(vec![], 0);
        let outs = s.on_message(&mls, 
            SyncMsg::BatchReq {
                group_id: g.clone(),
                from_rkey: None,
                to_rkey: None,
                cursor: None,
            },
            "did:plc:alice",
        ).unwrap();
        assert_eq!(outs.len(), 1);
        assert!(matches!(
            &outs[0],
            SyncOutput::Send(SyncMsg::Done {
                direction: SyncDirection::Backward,
                ..
            })
        ));
    }

    /// Forward sync is unimplemented, so a peer sending it is a protocol
    /// error rather than something to swallow — silently ignoring it would
    /// leave the peer believing it had delivered something.
    #[test]
    fn forward_done_is_a_protocol_error() {
        let mls = MoatSession::new();
        let mut s = SyncSession::new();
        let _ = s.on_paired(vec![], 0);
        let result = s.on_message(&mls, 
            SyncMsg::Done { group_id: vec![1u8; 32], direction: SyncDirection::Forward },
            "did:plc:alice",
        );
        assert!(result.is_err());
        assert!(!s.is_done());
    }

    /// `default()` is equivalent to `new()`.
    #[test]
    fn default_equals_new() {
        let s: SyncSession = Default::default();
        assert!(!s.is_done());
    }
}
