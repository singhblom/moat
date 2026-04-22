//! Phase 4 history sync protocol.
//!
//! `SyncSession` is a pure state machine driven by the App layer. It produces
//! `SyncOutput` values describing what the caller should do (send a frame,
//! store messages, fetch rkeys, close the session). No I/O or async here.
//!
//! Wire format: each `SyncMsg` is JSON-encoded, padded to the nearest 4 KB
//! multiple, then encrypted via the ring MLS group (`encrypt_event` with
//! `EventKind::SyncApp`) and sent as a raw binary frame on the pair WS.

use crate::keystore::StoredMessage;
use moat_core::DigestAnchor;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

// ── Wire types ────────────────────────────────────────────────────────────────

/// Our conversation state included in the Hello handshake.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvState {
    #[serde_as(as = "Base64")]
    pub group_id: Vec<u8>,
    pub oldest_rkey: Option<String>,
    pub newest_rkey: Option<String>,
    #[serde_as(as = "Base64")]
    pub tip_digest: Vec<u8>,
    pub anchors: Vec<AnchorDto>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// A plaintext message transferred during backward sync.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl SyncMessage {
    pub fn from_stored(m: &StoredMessage) -> Self {
        Self {
            rkey: m.rkey.clone(),
            message_id: m.message_id.clone(),
            sender_did: m.sender_did.clone().unwrap_or_default(),
            sender_device_name: m.sender_device.clone().unwrap_or_default(),
            timestamp_ms: m.timestamp.timestamp_millis(),
            content: m.content.clone(),
            is_own: m.is_own,
            blob_uri: m.blob_uri.clone(),
            blob_key: m.blob_key.clone(),
            blob_ciphertext_hash: m.blob_ciphertext_hash.clone(),
            blob_ciphertext_size: m.blob_ciphertext_size,
            blob_content_hash: m.blob_content_hash.clone(),
            blob_mime: m.blob_mime.clone(),
            blob_width: m.blob_width,
            blob_height: m.blob_height,
        }
    }

    pub fn to_stored(&self) -> StoredMessage {
        StoredMessage {
            rkey: self.rkey.clone(),
            content: self.content.clone(),
            timestamp: chrono::DateTime::from_timestamp_millis(self.timestamp_ms)
                .unwrap_or_else(chrono::Utc::now),
            is_own: self.is_own,
            message_id: self.message_id.clone(),
            sender_did: if self.sender_did.is_empty() { None } else { Some(self.sender_did.clone()) },
            sender_device: if self.sender_device_name.is_empty() { None } else { Some(self.sender_device_name.clone()) },
            blob_uri: self.blob_uri.clone(),
            blob_key: self.blob_key.clone(),
            blob_ciphertext_hash: self.blob_ciphertext_hash.clone(),
            blob_ciphertext_size: self.blob_ciphertext_size,
            blob_content_hash: self.blob_content_hash.clone(),
            blob_mime: self.blob_mime.clone(),
            blob_width: self.blob_width,
            blob_height: self.blob_height,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncDirection {
    Forward,
    Backward,
}

/// The sync protocol message, serialized to JSON and transmitted as a
/// ring-MLS-encrypted binary frame on the pair WebSocket.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncMsg {
    Hello {
        convs: Vec<ConvState>,
        ring_epoch: u64,
    },
    ManifestReq {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        from_rkey: Option<String>,
        to_rkey: Option<String>,
    },
    Manifest {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        rkeys: Vec<String>,
    },
    BatchReq {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        from_rkey: Option<String>,
        to_rkey: Option<String>,
        cursor: Option<String>,
    },
    Batch {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        messages: Vec<SyncMessage>,
        next_cursor: Option<String>,
    },
    Done {
        #[serde_as(as = "Base64")]
        group_id: Vec<u8>,
        direction: SyncDirection,
    },
}

/// Encode a `SyncMsg` to bytes, padding to the nearest 4 KB boundary.
pub fn encode_sync_msg(msg: &SyncMsg) -> Vec<u8> {
    let json = serde_json::to_vec(msg).expect("SyncMsg serialization should never fail");
    pad_4k(&json)
}

/// Decode a `SyncMsg` from (possibly padded) bytes.
pub fn decode_sync_msg(bytes: &[u8]) -> Result<SyncMsg, String> {
    let unpadded = unpad_4k(bytes);
    serde_json::from_slice(unpadded).map_err(|e| format!("SyncMsg decode: {e}"))
}

/// Pad data to the next 4 KB multiple: `[4-byte LE length][data][zero padding]`.
fn pad_4k(data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 4096;
    let content = 4 + data.len();
    let padded_len = ((content + BLOCK - 1) / BLOCK) * BLOCK;
    let mut buf = Vec::with_capacity(padded_len);
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf.resize(padded_len, 0);
    buf
}

/// Extract the payload from a `pad_4k`-encoded buffer.
fn unpad_4k(buf: &[u8]) -> &[u8] {
    if buf.len() < 4 {
        return buf;
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if 4 + len > buf.len() {
        return buf;
    }
    &buf[4..4 + len]
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Actions produced by `SyncSession` for the caller to execute.
pub enum SyncOutput {
    /// JSON-encode, encrypt via ring MLS, and send as a binary pair-WS frame.
    Send(SyncMsg),
    /// Store these messages for the conversation (conv_id_hex).
    Store { conv_id: String, messages: Vec<StoredMessage> },
    /// Sync is complete; the caller should close the pair WS.
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Pair WS is attached; we haven't sent Hello yet.
    SendingHello,
    /// We've sent Hello; waiting for peer's Hello.
    WaitingHello,
    /// Exchanged Hello; in progress (sending/receiving BatchReqs/Batches).
    Active,
    /// All Done messages sent and received.
    Done,
}

/// Per-conversation sync plan derived from Hello exchange.
struct ConvPlan {
    group_id: Vec<u8>,
    conv_id: String,
    /// Our stored messages to send (backward sync donor side).
    our_messages: Vec<StoredMessage>,
    /// Whether we expect to receive a batch from the peer.
    expecting_batch: bool,
    /// Whether we've sent Done{Backward} for this conversation.
    sent_done: bool,
    /// Whether we've received Done{Backward} for this conversation.
    received_done: bool,
}

pub struct SyncSession {
    phase: Phase,
    plans: Vec<ConvPlan>,
}

const BATCH_SIZE: usize = 50;

impl SyncSession {
    pub fn new() -> Self {
        Self { phase: Phase::SendingHello, plans: Vec::new() }
    }

    /// Called when the pair WS becomes `paired`. Returns the Hello frame to send.
    pub fn on_paired(&mut self, our_convs: Vec<ConvState>, ring_epoch: u64) -> Vec<SyncOutput> {
        self.phase = Phase::WaitingHello;
        vec![SyncOutput::Send(SyncMsg::Hello { convs: our_convs, ring_epoch })]
    }

    /// Feed a received and decrypted `SyncMsg` into the state machine.
    pub fn on_message(&mut self, msg: SyncMsg, our_did: &str) -> Vec<SyncOutput> {
        match msg {
            SyncMsg::Hello { convs: peer_convs, .. } => self.handle_hello(peer_convs, our_did),
            SyncMsg::BatchReq { group_id, from_rkey, to_rkey, cursor } => {
                self.handle_batch_req(group_id, from_rkey, to_rkey, cursor)
            }
            SyncMsg::Batch { group_id, messages, next_cursor } => {
                self.handle_batch(group_id, messages, next_cursor)
            }
            SyncMsg::Done { group_id, direction: SyncDirection::Backward } => {
                self.handle_done_backward(group_id)
            }
            // ManifestReq/Manifest/Done-Forward: deferred to Phase 6
            _ => vec![],
        }
    }

    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    // ── Internal handlers ─────────────────────────────────────────────────────

    fn handle_hello(&mut self, peer_convs: Vec<ConvState>, _our_did: &str) -> Vec<SyncOutput> {
        self.phase = Phase::Active;
        let mut outputs = Vec::new();

        for plan in &self.plans {
            let peer_state = peer_convs.iter().find(|c| c.group_id == plan.group_id);
            let peer_has_nothing = peer_state.map(|s| s.oldest_rkey.is_none()).unwrap_or(true);

            if peer_has_nothing && !plan.our_messages.is_empty() {
                // Peer needs our history: wait for their BatchReq
                // (Peer will send BatchReq upon seeing our Hello with messages)
            } else if !peer_has_nothing {
                // Peer has history we might need — send BatchReq
                outputs.push(SyncOutput::Send(SyncMsg::BatchReq {
                    group_id: plan.group_id.clone(),
                    from_rkey: None,
                    to_rkey: None,
                    cursor: None,
                }));
            }
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
        let cursor_idx: usize = cursor.as_deref()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);

        let plan = match self.plans.iter_mut().find(|p| p.group_id == group_id) {
            Some(p) => p,
            None => return vec![SyncOutput::Send(SyncMsg::Done {
                group_id,
                direction: SyncDirection::Backward,
            })],
        };

        let slice: Vec<SyncMessage> = plan.our_messages
            .iter()
            .skip(cursor_idx)
            .take(BATCH_SIZE)
            .map(SyncMessage::from_stored)
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
        group_id: Vec<u8>,
        messages: Vec<SyncMessage>,
        next_cursor: Option<String>,
    ) -> Vec<SyncOutput> {
        let plan = match self.plans.iter_mut().find(|p| p.group_id == group_id) {
            Some(p) => p,
            None => return vec![],
        };

        let stored: Vec<StoredMessage> = messages.iter().map(|m| m.to_stored()).collect();
        let mut outputs = vec![SyncOutput::Store {
            conv_id: plan.conv_id.clone(),
            messages: stored,
        }];

        if next_cursor.is_some() {
            outputs.push(SyncOutput::Send(SyncMsg::BatchReq {
                group_id: plan.group_id.clone(),
                from_rkey: None,
                to_rkey: None,
                cursor: next_cursor,
            }));
        }

        outputs
    }

    fn handle_done_backward(&mut self, group_id: Vec<u8>) -> Vec<SyncOutput> {
        if let Some(plan) = self.plans.iter_mut().find(|p| p.group_id == group_id) {
            plan.received_done = true;
        }
        self.check_complete()
    }

    fn check_complete(&mut self) -> Vec<SyncOutput> {
        let all_done = self.plans.iter().all(|p| {
            (p.our_messages.is_empty() || p.sent_done) &&
            (!p.expecting_batch || p.received_done)
        });
        if all_done && self.phase == Phase::Active {
            self.phase = Phase::Done;
            vec![SyncOutput::Complete]
        } else {
            vec![]
        }
    }
}

impl SyncSession {
    /// Populate the plan from our known conversations and their stored messages.
    ///
    /// Called after `new()`, before the pair WS is established.
    pub fn add_conv_plan(
        &mut self,
        group_id: Vec<u8>,
        conv_id: String,
        our_messages: Vec<StoredMessage>,
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
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let msg = SyncMsg::Hello {
            convs: vec![],
            ring_epoch: 42,
        };
        let encoded = encode_sync_msg(&msg);
        assert!(encoded.len() % 4096 == 0, "must be 4K-aligned");
        let decoded = decode_sync_msg(&encoded).expect("decode");
        assert!(matches!(decoded, SyncMsg::Hello { ring_epoch: 42, .. }));
    }

    #[test]
    fn batch_msg_roundtrip() {
        let msg = SyncMsg::Batch {
            group_id: vec![1, 2, 3],
            messages: vec![SyncMessage {
                rkey: "abc123".to_string(),
                message_id: Some(vec![0u8; 16]),
                sender_did: "did:plc:alice".to_string(),
                sender_device_name: "laptop".to_string(),
                timestamp_ms: 1_700_000_000_000,
                content: "hello".to_string(),
                is_own: true,
                blob_uri: None,
                blob_key: None,
                blob_ciphertext_hash: None,
                blob_ciphertext_size: None,
                blob_content_hash: None,
                blob_mime: None,
                blob_width: None,
                blob_height: None,
            }],
            next_cursor: None,
        };
        let encoded = encode_sync_msg(&msg);
        let decoded = decode_sync_msg(&encoded).expect("decode");
        assert!(matches!(decoded, SyncMsg::Batch { .. }));
    }

    #[test]
    fn pad_4k_alignment() {
        for size in [0usize, 1, 4091, 4092, 4093, 8000, 16383] {
            let data = vec![0xABu8; size];
            let padded = pad_4k(&data);
            assert_eq!(padded.len() % 4096, 0, "size {size} -> padded len {}", padded.len());
            assert_eq!(unpad_4k(&padded), data.as_slice());
        }
    }

    #[test]
    fn sync_message_stored_roundtrip() {
        let stored = StoredMessage {
            rkey: "rkey001".to_string(),
            content: "test message".to_string(),
            timestamp: chrono::Utc::now(),
            is_own: false,
            message_id: Some(vec![1u8; 16]),
            sender_did: Some("did:plc:bob".to_string()),
            sender_device: Some("phone".to_string()),
            blob_uri: None,
            blob_key: None,
            blob_ciphertext_hash: None,
            blob_ciphertext_size: None,
            blob_content_hash: None,
            blob_mime: None,
            blob_width: None,
            blob_height: None,
        };
        let sync = SyncMessage::from_stored(&stored);
        let back = sync.to_stored();
        assert_eq!(back.rkey, stored.rkey);
        assert_eq!(back.content, stored.content);
        assert_eq!(back.sender_did, stored.sender_did);
    }
}
