//! History sync state machine.
//!
//! [`SyncSession`] is a pure state machine driven by the host layer. It
//! produces [`SyncOutput`] values describing what the caller should do (send
//! a frame, store messages, mark the session done). No I/O or async here.
//!
//! Wire format: each [`SyncMsg`] is JSON-encoded and sent as a binary frame
//! on the pair WS, sealed by a [`crate::PairingFrameChannel`] — the pairing
//! session's, or one keyed from the secret in a [`crate::RingMsg`].
//!
//! The wire type [`SyncMessage`] is the canonical message representation
//! transferred during sync. Hosts (moat-cli, moat-dart) adapt it to/from
//! their own `StoredMessage` type at the FFI / state-machine boundary.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::device_ring::DeviceId;
use crate::{Error, Result};

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
    /// What this side holds for the conversation.
    pub inventory: ConvInventory,
}

/// One conversation's stored history, as a host hands it to
/// [`SyncSession::start`].
#[derive(Debug, Clone)]
pub struct ConvHistory {
    pub group_id: Vec<u8>,
    pub conv_id: String,
    pub messages: Vec<SyncMessage>,
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

/// One emoji reaction, as carried by a synced message.
///
/// Reactions arrive as their own events on the PDS, so a device that was
/// present can rebuild them by replaying. A device receiving history from
/// before it joined cannot: those events are not decryptable to it. If
/// sync does not carry them they are lost for good, which is why they
/// travel with the message rather than being left to the transport.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncReaction {
    pub emoji: String,
    pub sender_did: String,
}

/// Plaintext message exchanged during a sync session.
///
/// Mirrors the host's `StoredMessage` but with explicit, JSON-friendly fields.
/// Optional values use `Option<…>` directly so they round-trip through JSON
/// without sentinel values.
///
/// The rule this type exists to keep: **everything a host persists about a
/// message travels**. A field held on one side and not carried here is
/// silently lost on the other, and for history predating the receiver's
/// membership it cannot be recovered from the PDS afterwards — the
/// original events are not decryptable to it.
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
    /// The image's blurry placeholder, shown while the blob downloads.
    /// Stored beside the other blob metadata, so it travels with it.
    #[serde_as(as = "Option<Base64>")]
    pub blob_thumbhash: Option<Vec<u8>>,
    /// Emoji reactions on this message.
    pub reactions: Vec<SyncReaction>,
}

/// The sync protocol message, serialised to JSON and transmitted as a
/// sealed binary frame on the pair WebSocket (see the module docs).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncMsg {
    /// Initial handshake: each side sends its conversation state, and
    /// names itself so the peer can report where history came from.
    Hello {
        convs: Vec<ConvState>,
        #[serde_as(as = "Base64")]
        device_id: DeviceId,
    },
    /// Batch request.
    BatchReq {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        cursor: Option<String>,
    },
    /// Batch of messages.
    Batch {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        messages: Vec<SyncMessage>,
        next_cursor: Option<String>,
        /// How many messages the sender will serve for this conversation
        /// in all, so the receiver can show progress.
        total: u64,
    },
    /// Every message this side holds for `group_id` has been sent.
    Done {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
    },
    /// Every `Done` this side was waiting for has arrived: the peer's
    /// sends are confirmed delivered. Sent once per session.
    Fin,
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
    /// JSON-encode, seal under the transfer's channel, and send as a binary
    /// pair-WS frame.
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

/// What a finished session moved in each direction.
///
/// With one donor per gesture, "nothing new — that device didn't have
/// more than you" is the outcome that tells the user to try a *different*
/// device. Without it a sync that transferred everything and one that
/// transferred nothing look identical, so the counts are not decoration:
/// they are the difference between a legible result and a mysterious one.
///
/// `messages`/`conversations` count what the peer *delivered*, not what
/// storage accepted as new.
/// The inventory diff means the donor already sent only the complement,
/// so the two agree except where a `range` inventory forced it to serve
/// across a span it could not see holes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SyncTally {
    pub messages: u64,
    pub conversations: u64,
    /// What this side served to the peer, confirmed by the peer's `Fin`.
    pub sent_messages: u64,
    pub sent_conversations: u64,
}

/// How far a running session has got, for a progress indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProgress {
    /// The totals are not known yet: the `Hello`s are still being
    /// exchanged, or a conversation's first page has yet to arrive with
    /// the donor's count.
    Starting,
    /// Both totals are exact from here on.
    Transferring {
        received: u64,
        receive_total: u64,
        sent: u64,
        send_total: u64,
    },
}

impl SyncProgress {
    /// The share of both directions done, or `None` while starting.
    pub fn fraction(&self) -> Option<f64> {
        let Self::Transferring { received, receive_total, sent, send_total } = *self else {
            return None;
        };
        let total = receive_total + send_total;
        if total == 0 {
            return Some(1.0);
        }
        Some(((received + sent) as f64 / total as f64).min(1.0))
    }
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
    /// All `Done`s sent and received, and `Fin` sent and received.
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
    /// Whether we've received `Done` for this conversation.
    received_done: bool,
    /// What the peer said it will send us here, from its first `Batch`.
    incoming_total: Option<u64>,
    /// Our span, when our `Hello` could only give that rather than the
    /// full list.
    sent_span: Option<(String, String)>,
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
    /// Messages received from the peer, and the conversations they
    /// arrived for. Counted here rather than in each host so both
    /// runtimes report the same number from the same events.
    received_messages: u64,
    received_convs: HashSet<String>,
    sent_messages: u64,
    sent_convs: HashSet<String>,
    sent_fin: bool,
    received_fin: bool,
    peer_device_id: Option<DeviceId>,
}

impl Default for SyncSession {
    fn default() -> Self {
        Self::new()
    }
}

const BATCH_SIZE: usize = 50;

impl SyncSession {
    /// Create a new session in the `SendingHello` phase. Add per-conversation
    /// state via [`add_conv_plan`](Self::add_conv_plan) before calling
    /// [`on_paired`](Self::on_paired), or use [`start`](Self::start).
    pub fn new() -> Self {
        Self {
            phase: Phase::SendingHello,
            plans: Vec::new(),
            received_messages: 0,
            received_convs: HashSet::new(),
            sent_messages: 0,
            sent_convs: HashSet::new(),
            sent_fin: false,
            received_fin: false,
            peer_device_id: None,
        }
    }

    /// Start a session from this side's stored history and return it with
    /// the `Hello` to send. `history` holds only settled messages, which
    /// both serve the peer and make up this side's inventories.
    pub fn start(device_id: DeviceId, history: Vec<ConvHistory>) -> (Self, Vec<SyncOutput>) {
        let mut session = Self::new();
        let mut convs = Vec::with_capacity(history.len());
        for conv in history {
            let rkeys = conv.messages.iter().map(|m| m.rkey.clone()).collect();
            convs.push(ConvState {
                group_id: conv.group_id.clone(),
                inventory: ConvInventory::of(rkeys),
            });
            session.add_conv_plan(conv.group_id, conv.conv_id, conv.messages);
        }
        fit_hello_inventories(&mut convs);
        let outputs = session.on_paired(convs, device_id);
        (session, outputs)
    }

    /// Populate the plan for one conversation. `our_messages` is what this
    /// side can serve to the peer. [`start`](Self::start) is the host entry
    /// point; this and [`on_paired`](Self::on_paired) let a test declare an
    /// inventory that differs from the plan.
    pub fn add_conv_plan(
        &mut self,
        group_id: Vec<u8>,
        conv_id: String,
        our_messages: Vec<SyncMessage>,
    ) {
        self.plans.push(ConvPlan {
            group_id,
            conv_id,
            our_messages,
            expecting_batch: false,
            received_done: false,
            incoming_total: None,
            sent_span: None,
        });
    }

    /// Called when the pair WS reaches the `paired` state. Returns the Hello
    /// frame to send.
    pub fn on_paired(&mut self, our_convs: Vec<ConvState>, device_id: DeviceId) -> Vec<SyncOutput> {
        for conv in &our_convs {
            if let ConvInventory::Range { oldest, newest, .. } = &conv.inventory {
                if let Some(plan) = self.plans.iter_mut().find(|p| p.group_id == conv.group_id) {
                    plan.sent_span = Some((oldest.clone(), newest.clone()));
                }
            }
        }
        self.phase = Phase::WaitingHello;
        vec![SyncOutput::Send(SyncMsg::Hello { convs: our_convs, device_id })]
    }

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
    pub fn on_message(&mut self, msg: SyncMsg) -> Result<Vec<SyncOutput>> {
        match msg {
            SyncMsg::Hello { convs: peer_convs, device_id } => {
                self.peer_device_id = Some(device_id);
                Ok(self.handle_hello(peer_convs))
            }
            SyncMsg::BatchReq { group_id, cursor } => Ok(self.handle_batch_req(group_id, cursor)),
            SyncMsg::Batch { group_id, messages, next_cursor, total } => {
                self.handle_batch(group_id, messages, next_cursor, total)
            }
            SyncMsg::Done { group_id } => Ok(self.handle_done(group_id)),
            SyncMsg::Fin => {
                self.received_fin = true;
                self.check_complete();
                Ok(Vec::new())
            }
        }
    }

    /// The device the peer named in its `Hello`, once that has arrived.
    pub fn peer_device_id(&self) -> Option<&DeviceId> {
        self.peer_device_id.as_ref()
    }

    /// `true` once the session has reached the `Done` phase.
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    /// What this side has received so far. Meaningful at any point, but
    /// read at completion, where it becomes the report the user sees.
    pub fn tally(&self) -> SyncTally {
        SyncTally {
            messages: self.received_messages,
            conversations: self.received_convs.len() as u64,
            sent_messages: self.sent_messages,
            sent_conversations: self.sent_convs.len() as u64,
        }
    }

    /// Transfer progress in both directions, for the UI.
    ///
    /// The send total is settled by the `Hello` exchange, which leaves
    /// each plan holding exactly what the peer will ask for. The receive
    /// total needs the donor's count from each conversation's first page.
    pub fn progress(&self) -> SyncProgress {
        if matches!(self.phase, Phase::SendingHello | Phase::WaitingHello) {
            return SyncProgress::Starting;
        }
        let receive_total = self
            .plans
            .iter()
            .filter(|p| p.expecting_batch)
            .try_fold(0u64, |sum, p| p.incoming_total.map(|t| sum + t));
        let Some(receive_total) = receive_total else {
            return SyncProgress::Starting;
        };
        SyncProgress::Transferring {
            received: self.received_messages,
            receive_total,
            sent: self.sent_messages,
            send_total: self.plans.iter().map(|p| p.our_messages.len() as u64).sum(),
        }
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
                    // Given only our span, the peer asks just when it
                    // reaches beyond its own, so anything else stays unsent.
                    if let Some((oldest, newest)) = &plan.sent_span {
                        let beyond = match (rkeys.iter().min(), rkeys.iter().max()) {
                            (Some(lo), Some(hi)) => oldest < lo || newest > hi,
                            _ => true,
                        };
                        if !beyond {
                            plan.our_messages.clear();
                        }
                    }
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
                received_done: false,
                incoming_total: None,
                sent_span: None,
            });
            outputs.push(SyncOutput::Send(SyncMsg::BatchReq {
                group_id: peer_state.group_id.clone(),
                cursor: None,
            }));
        }

        // A side expecting nothing confirms that at once, so two devices
        // that already agree finish on one exchange of `Fin`s.
        self.maybe_send_fin(&mut outputs);
        self.check_complete();
        outputs
    }

    fn handle_batch_req(
        &mut self,
        group_id: Vec<u8>,
        cursor: Option<String>,
    ) -> Vec<SyncOutput> {
        let cursor_idx: usize = cursor.as_deref().and_then(|c| c.parse().ok()).unwrap_or(0);

        let plan = match self.plans.iter_mut().find(|p| p.group_id == group_id) {
            Some(p) => p,
            None => {
                return vec![SyncOutput::Send(SyncMsg::Done { group_id })];
            }
        };

        let slice: Vec<SyncMessage> = plan
            .our_messages
            .iter()
            .skip(cursor_idx)
            .take(BATCH_SIZE)
            .cloned()
            .collect();

        if !slice.is_empty() {
            self.sent_messages += slice.len() as u64;
            self.sent_convs.insert(plan.conv_id.clone());
        }

        let next_idx = cursor_idx + slice.len();
        let is_last = next_idx >= plan.our_messages.len();
        let next_cursor = if is_last { None } else { Some(next_idx.to_string()) };

        let mut outputs = vec![SyncOutput::Send(SyncMsg::Batch {
            group_id: plan.group_id.clone(),
            messages: slice,
            next_cursor: next_cursor.clone(),
            total: plan.our_messages.len() as u64,
        })];

        if is_last {
            outputs.push(SyncOutput::Send(SyncMsg::Done {
                group_id: plan.group_id.clone(),
            }));
        }

        outputs
    }

    fn handle_batch(
        &mut self,
        group_id: Vec<u8>,
        messages: Vec<SyncMessage>,
        next_cursor: Option<String>,
        total: u64,
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

        plan.incoming_total = Some(total);
        if !messages.is_empty() {
            self.received_messages += messages.len() as u64;
            self.received_convs.insert(plan.conv_id.clone());
        }

        let mut outputs = vec![SyncOutput::Store {
            conv_id: plan.conv_id.clone(),
            messages,
        }];

        if next_cursor.is_some() {
            outputs.push(SyncOutput::Send(SyncMsg::BatchReq {
                group_id: plan.group_id.clone(),
                cursor: next_cursor,
            }));
        }

        Ok(outputs)
    }

    fn handle_done(&mut self, group_id: Vec<u8>) -> Vec<SyncOutput> {
        if let Some(plan) = self.plans.iter_mut().find(|p| p.group_id == group_id) {
            plan.received_done = true;
            // A peer with no plan here answers with a bare `Done`.
            plan.incoming_total.get_or_insert(0);
        }
        let mut outputs = Vec::new();
        self.maybe_send_fin(&mut outputs);
        self.check_complete();
        outputs
    }

    /// Send `Fin` once every `Done` we are waiting for has arrived.
    fn maybe_send_fin(&mut self, outputs: &mut Vec<SyncOutput>) {
        if self.phase != Phase::Active || self.sent_fin {
            return;
        }
        if self.plans.iter().all(|p| !p.expecting_batch || p.received_done) {
            self.sent_fin = true;
            outputs.push(SyncOutput::Send(SyncMsg::Fin));
        }
    }

    /// Move to `Done` once both sides have confirmed receipt with `Fin`.
    /// The peer's `Fin` follows our last `Done`, so it also means our sends
    /// arrived. Emits nothing: callers observe completion through
    /// [`is_done`](Self::is_done) *after* applying the outputs, and must
    /// close the channel behind them, never ahead.
    fn check_complete(&mut self) {
        if self.phase == Phase::Active && self.sent_fin && self.received_fin {
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
            blob_uri: None,
            blob_key: None,
            blob_ciphertext_hash: None,
            blob_ciphertext_size: None,
            blob_content_hash: None,
            blob_mime: None,
            blob_width: None,
            blob_height: None,
            blob_thumbhash: None,
            reactions: Vec::new(),
        }
    }

    fn empty_state(group_id: &[u8]) -> ConvState {
        ConvState {
            group_id: group_id.to_vec(),
            inventory: ConvInventory::Empty,
        }
    }

    /// A peer whose list did not fit, so it declared only its span — the
    /// reduced path, which cannot see holes inside the range.
    fn full_state(group_id: &[u8]) -> ConvState {
        ConvState {
            group_id: group_id.to_vec(),
            inventory: ConvInventory::Range {
                oldest: "a".to_string(),
                newest: "z".to_string(),
                count: 2,
            },
        }
    }

    #[test]
    fn encode_decode_roundtrip_hello() {
        let msg = SyncMsg::Hello { convs: vec![], device_id: [42; 16] };
        let decoded = decode_sync_msg(&encode_sync_msg(&msg)).unwrap();
        assert!(matches!(decoded, SyncMsg::Hello { device_id, .. } if device_id == [42; 16]));
    }

    #[test]
    fn encode_decode_roundtrip_batch() {
        let msg = SyncMsg::Batch {
            group_id: vec![1, 2, 3],
            messages: vec![empty_msg("rk1", "hi")],
            next_cursor: None,
            total: 1,
        };
        let decoded = decode_sync_msg(&encode_sync_msg(&msg)).unwrap();
        match decoded {
            SyncMsg::Batch { group_id, messages, next_cursor, .. } => {
                assert_eq!(group_id, vec![1, 2, 3]);
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].content, "hi");
                assert!(next_cursor.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn encode_decode_roundtrip_done() {
        let msg = SyncMsg::Done { group_id: vec![9u8; 32] };
        let decoded = decode_sync_msg(&encode_sync_msg(&msg)).unwrap();
        assert!(matches!(decoded, SyncMsg::Done { .. }));
    }

    #[test]
    fn on_paired_emits_hello() {
        let mut s = SyncSession::new();
        let outs = s.on_paired(vec![], [7; 16]);
        assert_eq!(outs.len(), 1);
        assert!(matches!(
            &outs[0],
            SyncOutput::Send(SyncMsg::Hello { device_id, .. }) if *device_id == [7; 16]
        ));
    }

    /// Complete.
    #[test]
    fn joiner_drives_full_session() {
        let g1 = vec![1u8; 32];
        let g2 = vec![2u8; 32];

        let mut s = SyncSession::new();
        s.add_conv_plan(g1.clone(), hex::encode(&g1), vec![]);
        s.add_conv_plan(g2.clone(), hex::encode(&g2), vec![]);
        let _ = s.on_paired(vec![], [0; 16]);

        // Receive peer's Hello — they have history for both.
        let outs = s.on_message(SyncMsg::Hello {
                convs: vec![full_state(&g1), full_state(&g2)],
                device_id: [0; 16],
            }).unwrap();
        let req_count = outs
            .iter()
            .filter(|o| matches!(o, SyncOutput::Send(SyncMsg::BatchReq { .. })))
            .count();
        assert_eq!(req_count, 2, "one BatchReq per conv");

        // Receive batch + Done for g1.
        let outs = s.on_message(SyncMsg::Batch {
                group_id: g1.clone(),
                messages: vec![empty_msg("r1", "hi")],
                next_cursor: None,
                total: 1,
            }).unwrap();
        assert!(outs.iter().any(|o| matches!(o, SyncOutput::Store { .. })));

        let outs = s.on_message(SyncMsg::Done { group_id: g1.clone() }).unwrap();
        // Not done yet — g2 still pending, so no Fin either.
        assert!(outs.is_empty());
        assert!(!s.is_done());

        // Receive batch + Done for g2.
        let _ = s.on_message(SyncMsg::Batch {
                group_id: g2.clone(),
                messages: vec![empty_msg("r2", "hey")],
                next_cursor: None,
                total: 1,
            }).unwrap();
        let outs = s.on_message(SyncMsg::Done { group_id: g2.clone() }).unwrap();
        // Everything arrived: confirm it. Not done until the peer confirms
        // the other direction.
        assert!(matches!(outs.as_slice(), [SyncOutput::Send(SyncMsg::Fin)]));
        assert!(!s.is_done());

        let outs = s.on_message(SyncMsg::Fin).unwrap();
        assert!(outs.is_empty());
        assert!(s.is_done());
    }

    /// Donor side: we have history, peer has nothing. Expect: hold off on
    /// requesting (peer has nothing), serve BatchReq when it arrives, send
    /// Done after the last batch, complete only on peer's Done.
    #[test]
    fn donor_serves_batch_and_completes() {
        let g = vec![3u8; 32];
        let mut s = SyncSession::new();
        s.add_conv_plan(
            g.clone(),
            hex::encode(&g),
            vec![empty_msg("r1", "a"), empty_msg("r2", "b")],
        );
        let _ = s.on_paired(vec![full_state(&g)], [0; 16]);

        // Peer's Hello (they have nothing).
        let outs = s
            .on_message(SyncMsg::Hello { convs: vec![empty_state(&g)], device_id: [0; 16] })
            .unwrap();
        // We do NOT send BatchReq (peer has nothing), and expecting nothing
        // we confirm that straight away.
        assert!(!outs.iter().any(|o| matches!(o, SyncOutput::Send(SyncMsg::BatchReq { .. }))));
        assert!(outs.iter().any(|o| matches!(o, SyncOutput::Send(SyncMsg::Fin))));

        // Peer requests our batch.
        let outs = s.on_message(SyncMsg::BatchReq {
                group_id: g.clone(),
                cursor: None,
            }).unwrap();
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
                    SyncOutput::Send(SyncMsg::Done { .. })
                )
            })
            .count();
        assert_eq!(batch_count, 1);
        assert_eq!(done_count, 1);
        // Everything is sent, but nothing says it arrived — not complete.
        assert!(!s.is_done());

        // The peer's Fin confirms delivery.
        let outs = s.on_message(SyncMsg::Fin).unwrap();
        // Completion is a state, not an output: the caller applies whatever
        // came back and *then* asks, so it can never close the channel with
        // sends still pending.
        assert!(outs.is_empty());
        assert!(s.is_done());
        let tally = s.tally();
        assert_eq!((tally.sent_messages, tally.sent_conversations), (2, 1));
        assert_eq!(tally.messages, 0, "nothing was received");
    }

    /// History the peer never asked for does not hold the session open:
    /// its Fin says it has everything it wanted.
    #[test]
    fn peer_fin_completes_without_unrequested_sends() {
        let g = vec![7u8; 32];
        let mut s = SyncSession::new();
        s.add_conv_plan(g.clone(), hex::encode(&g), vec![empty_msg("r1", "x")]);
        let _ = s.on_paired(vec![], [0; 16]);
        let _ = s
            .on_message(SyncMsg::Hello { convs: vec![empty_state(&g)], device_id: [0; 16] })
            .unwrap();
        let _ = s.on_message(SyncMsg::Fin).unwrap();
        assert!(s.is_done());
        assert_eq!(s.tally().sent_messages, 0);
    }

    /// Two-way: each side both serves and receives. Neither finishes until
    /// both directions are confirmed.
    #[test]
    fn two_way_session_needs_both_fins() {
        let g = vec![8u8; 32];
        let mut s = SyncSession::new();
        s.add_conv_plan(g.clone(), hex::encode(&g), vec![empty_msg("a1", "x")]);
        let _ = s.on_paired(vec![], [0; 16]);
        let peer = ConvState {
            group_id: g.clone(),
            inventory: ConvInventory::Complete { rkeys: vec!["b1".to_string()] },
        };
        let outs = s.on_message(SyncMsg::Hello { convs: vec![peer], device_id: [0; 16] }).unwrap();
        assert!(!outs.iter().any(|o| matches!(o, SyncOutput::Send(SyncMsg::Fin))));

        let _ = s.on_message(SyncMsg::BatchReq {
                group_id: g.clone(),
                cursor: None,
            }).unwrap();
        let _ = s.on_message(SyncMsg::Fin).unwrap();
        assert!(!s.is_done(), "we have not received their batch");

        let _ = s.on_message(SyncMsg::Batch {
                group_id: g.clone(),
                messages: vec![empty_msg("b1", "y")],
                next_cursor: None,
                total: 1,
            }).unwrap();
        let outs = s.on_message(SyncMsg::Done { group_id: g.clone() }).unwrap();
        assert!(matches!(outs.as_slice(), [SyncOutput::Send(SyncMsg::Fin)]));
        assert!(s.is_done());
    }

    fn sends(outs: Vec<SyncOutput>) -> Vec<SyncMsg> {
        outs.into_iter()
            .filter_map(|o| match o {
                SyncOutput::Send(m) => Some(m),
                SyncOutput::Store { .. } => None,
            })
            .collect()
    }

    /// Pair `a` and `b` and deliver every frame until neither has anything
    /// left to send, calling `after_each` with both sessions after every
    /// round.
    fn pump(
        a: &mut SyncSession,
        a_convs: Vec<ConvState>,
        b: &mut SyncSession,
        b_convs: Vec<ConvState>,
        mut after_each: impl FnMut(&SyncSession, &SyncSession),
    ) {
        let mut to_b = sends(a.on_paired(a_convs, [0; 16]));
        let mut to_a = sends(b.on_paired(b_convs, [0; 16]));
        after_each(a, b);
        while !(to_a.is_empty() && to_b.is_empty()) {
            for m in std::mem::take(&mut to_a) {
                to_b.extend(sends(a.on_message(m).unwrap()));
            }
            for m in std::mem::take(&mut to_b) {
                to_a.extend(sends(b.on_message(m).unwrap()));
            }
            after_each(a, b);
        }
    }

    /// Progress stays `Starting` until both totals are known, and from
    /// then on the totals never move.
    #[test]
    fn progress_totals_are_exact_from_the_first_report() {
        let g = vec![6u8; 32];
        let conv = hex::encode(&g);
        let rkeys: Vec<String> = (0..75).map(|i| format!("r{i:03}")).collect();
        let mut donor = SyncSession::new();
        donor.add_conv_plan(
            g.clone(),
            conv.clone(),
            rkeys.iter().map(|r| empty_msg(r, "x")).collect(),
        );
        let mut joiner = SyncSession::new();
        joiner.add_conv_plan(g.clone(), conv, Vec::new());

        let mut seen = Vec::new();
        pump(
            &mut donor,
            vec![ConvState { group_id: g.clone(), inventory: ConvInventory::of(rkeys) }],
            &mut joiner,
            vec![empty_state(&g)],
            |d, j| seen.push((d.progress(), j.progress())),
        );
        assert_eq!(seen[0], (SyncProgress::Starting, SyncProgress::Starting));
        for (d, j) in &seen {
            if let SyncProgress::Transferring { receive_total, send_total, .. } = *j {
                assert_eq!((receive_total, send_total), (75, 0));
            }
            if let SyncProgress::Transferring { receive_total, send_total, .. } = *d {
                assert_eq!((receive_total, send_total), (0, 75));
            }
        }
        assert!(seen.iter().any(|(_, j)| j.fraction().is_some_and(|f| f > 0.0 && f < 1.0)));
        assert!(donor.is_done() && joiner.is_done());
        assert_eq!(joiner.progress().fraction(), Some(1.0));
        assert_eq!(donor.progress().fraction(), Some(1.0));
    }

    /// A conversation the peer answers with a bare `Done`, having no plan
    /// for it, still counts as a known total.
    #[test]
    fn bare_done_settles_the_receive_total() {
        let g = vec![7u8; 32];
        let mut s = SyncSession::new();
        s.add_conv_plan(g.clone(), hex::encode(&g), Vec::new());
        let _ = s.on_paired(vec![empty_state(&g)], [0; 16]);
        let _ = s
            .on_message(SyncMsg::Hello {
                convs: vec![ConvState {
                    group_id: g.clone(),
                    inventory: ConvInventory::of(vec!["r1".to_string()]),
                }],
                device_id: [0; 16],
            })
            .unwrap();
        assert_eq!(s.progress(), SyncProgress::Starting);
        let _ = s.on_message(SyncMsg::Done { group_id: g }).unwrap();
        assert_eq!(
            s.progress(),
            SyncProgress::Transferring { received: 0, receive_total: 0, sent: 0, send_total: 0 }
        );
    }

    /// A side that could only declare its span is asked for nothing when
    /// that span sits inside the peer's, so what it holds there is not
    /// counted as owed, and both sides still finish on exact totals.
    #[test]
    fn a_span_inside_the_peers_is_never_counted_as_owed() {
        let g = vec![8u8; 32];
        let conv = hex::encode(&g);
        let mut ranged = SyncSession::new();
        ranged.add_conv_plan(
            g.clone(),
            conv.clone(),
            vec![empty_msg("r2", "x"), empty_msg("r4", "x")],
        );
        let mut complete = SyncSession::new();
        complete.add_conv_plan(
            g.clone(),
            conv,
            ["r1", "r3", "r5"].iter().map(|r| empty_msg(r, "x")).collect(),
        );

        pump(
            &mut ranged,
            vec![ConvState {
                group_id: g.clone(),
                inventory: ConvInventory::Range {
                    oldest: "r2".to_string(),
                    newest: "r4".to_string(),
                    count: 2,
                },
            }],
            &mut complete,
            vec![ConvState {
                group_id: g.clone(),
                inventory: ConvInventory::of(vec!["r1".into(), "r3".into(), "r5".into()]),
            }],
            |_, _| {},
        );
        assert!(ranged.is_done() && complete.is_done());
        // `complete` cannot see r3 is missing inside the span it was given,
        // so it serves only what lies outside it.
        assert_eq!(
            ranged.progress(),
            SyncProgress::Transferring { received: 2, receive_total: 2, sent: 0, send_total: 0 }
        );
        assert_eq!(
            complete.progress(),
            SyncProgress::Transferring { received: 0, receive_total: 0, sent: 2, send_total: 2 }
        );
    }

    /// Donor that paginates across multiple BatchReq cursors.
    #[test]
    fn donor_paginates_with_cursor() {
        let g = vec![4u8; 32];
        let mut s = SyncSession::new();
        // 75 messages forces two batches (BATCH_SIZE = 50).
        let our_msgs: Vec<SyncMessage> = (0..75)
            .map(|i| empty_msg(&format!("r{i}"), "x"))
            .collect();
        s.add_conv_plan(g.clone(), hex::encode(&g), our_msgs);
        let _ = s.on_paired(vec![full_state(&g)], [0; 16]);
        let _ = s
            .on_message(SyncMsg::Hello { convs: vec![empty_state(&g)], device_id: [0; 16] })
            .unwrap();

        // First BatchReq: cursor=None → returns 50, next_cursor=Some("50").
        let outs = s.on_message(SyncMsg::BatchReq {
                group_id: g.clone(),
                cursor: None,
            }).unwrap();
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
        let outs = s.on_message(SyncMsg::BatchReq {
                group_id: g.clone(),
                cursor: Some("50".to_string()),
            }).unwrap();
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
        let g = vec![5u8; 32];
        let mut s = SyncSession::new();
        let _ = s.on_paired(vec![], [0; 16]);
        let outs = s
            .on_message(SyncMsg::Hello { convs: vec![full_state(&g)], device_id: [0; 16] })
            .unwrap();
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
        let g = vec![6u8; 32];
        let mut s = SyncSession::new();
        let _ = s.on_paired(vec![], [0; 16]);
        let outs = s.on_message(SyncMsg::BatchReq {
                group_id: g.clone(),
                cursor: None,
            }).unwrap();
        assert_eq!(outs.len(), 1);
        assert!(matches!(
            &outs[0],
            SyncOutput::Send(SyncMsg::Done { .. })
        ));
    }

    #[test]
    fn default_equals_new() {
        let s: SyncSession = Default::default();
        assert!(!s.is_done());
    }
}
