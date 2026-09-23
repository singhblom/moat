//! Typed HTTP client for the moat-cli `--http` REST API.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A typed client for one `moat-cli --http` participant process.
///
/// All methods are async and return `anyhow::Result`.
#[derive(Clone, Debug)]
pub struct MoatCliClient {
    http: Client,
    base_url: String,
}

// ── Request / response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StatusResponse {
    pub logged_in: bool,
    pub handle: Option<String>,
    pub did: Option<String>,
    #[serde(default)]
    pub drawbridge_connected: bool,
}

#[derive(Debug, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub name: String,
    pub participant_dids: Vec<String>,
    /// `false` while the device holds this conversation's history but is
    /// not yet a member of its MLS group — history that arrived by sync
    /// ahead of the fan-out `Add`. Defaulted so a runtime that predates
    /// the field still deserializes.
    #[serde(default = "default_true")]
    pub is_member: bool,
    pub epoch: u64,
    pub unread: usize,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub from: String,
    pub content: String,
    pub timestamp: String,
    pub is_own: bool,
    pub sender_did: Option<String>,
    pub message_id: Option<String>,
    #[serde(default)]
    pub attachment: Option<ImageAttachmentInfo>,
    /// Emoji reactions on this message. Defaulted so a runtime that
    /// predates the field still deserializes.
    #[serde(default)]
    pub reactions: Vec<ReactionInfo>,
    /// `sending`, `sent` or `failed`. Only the Rust CLI reports it.
    #[serde(default)]
    pub status: Option<String>,
    /// Why a `failed` message did not send.
    #[serde(default)]
    pub send_error: Option<String>,
}

/// One emoji reaction on a message, as either runtime reports it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReactionInfo {
    pub emoji: String,
    pub sender_did: String,
}

/// Image attachment metadata returned by the Dart server (camelCase keys from `ImageAttachment.toJson()`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageAttachmentInfo {
    pub uri: String,
    /// Base64-encoded 32-byte decryption key.
    pub key: String,
    pub ciphertext_hash: String,
    pub ciphertext_size: u64,
    pub content_hash: String,
    pub thumbhash: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub mime: Option<String>,
}

/// What a finished sync reported: the counts and the donor that served
/// them. Read from `/sync/status`, so it covers both runtimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCompletion {
    pub messages: u64,
    pub conversations: u64,
    pub device_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RingStatus {
    pub ring_group_id: Option<String>,
    pub coord_group_count: usize,
    /// This device's own MLS view of ring membership (0 if not in a ring).
    /// Lets a scenario assert a bystander sibling actually converged after
    /// another device's pairing, not just that "a ring exists."
    #[serde(default)]
    pub ring_member_count: usize,
    /// The ring's members, read from their MLS leaf credentials.
    #[serde(default)]
    pub devices: Vec<RingDevice>,
}

/// One ring member, as `/ring-status` lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct RingDevice {
    pub device_id: String,
    pub device_name: String,
    pub is_self: bool,
}

#[derive(Debug, Deserialize)]
pub struct PollStats {
    pub new_messages: usize,
    pub new_conversations: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateConversationResponse {
    pub group_id: String,
}

/// Response to `POST /pair/new`.
#[derive(Debug, Deserialize)]
pub struct PairNewResponse {
    /// The text form of the pairing code (Crockford base32,
    /// hyphen-grouped). The `moat-pair:` URI / QR form is a client-side
    /// concern (Dart), not part of this HTTP surface.
    pub code: String,
}

/// Response to `GET /pair/status` — a tagged mirror of
/// `moat_core::PairingUiState`, matching both `moat-cli` and
/// `moat_dart_server`'s wire format exactly (`#[serde(tag = "phase",
/// rename_all = "snake_case")]` on the Rust side — see
/// `crates/moat-core/src/pairing.rs`). `ring_id` is a base64 string on the
/// wire, matching that struct's `#[serde_as(as = "Base64")]` field.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum PairingUiState {
    /// No pairing in flight.
    Idle,
    /// New device: code generated, waiting for the peer to enter it.
    ShowingCode { code: String, uri: String },
    /// Existing device: code accepted, waiting for the peer's `Enroll`.
    AwaitingPeer,
    /// Existing device: `Enroll` received, waiting on the approve/reject
    /// decision. No host — including this one — auto-approves anymore;
    /// see `MoatCliClient::pair_approve`.
    AwaitingApproval { device_name: String, did: String },
    /// Enroll/Admit exchange complete. Says nothing about history sync —
    /// see `GET /sync/status` for that.
    Done { ring_id: String },
    /// Terminal failure, with a reason retained on the session rather than
    /// thrown away.
    Failed { reason: String },
}

impl PairingUiState {
    /// `true` once this session has reached its terminal `Done` phase.
    /// Matches `PairingSession::is_done()`'s semantics.
    pub fn is_done(&self) -> bool {
        matches!(self, PairingUiState::Done { .. })
    }

    /// `true` once this session has reached a terminal `Failed` phase.
    pub fn is_failed(&self) -> bool {
        matches!(self, PairingUiState::Failed { .. })
    }
}

/// The `request` half of `GET /sync/status` — a tagged mirror of
/// `moat_core::SyncRequestUiState` (see
/// `crates/moat-core/src/sync_request.rs`).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SyncRequestUiState {
    /// No sync request in flight.
    Idle,
    /// Waiting on the rendezvous, in either role.
    AwaitingPeer,
    /// A sibling asked for history; this device's user has not decided.
    AwaitingApproval { device_name: String },
    /// Channel up, transfer running.
    Active,
    /// Transfer finished.
    Complete,
    /// Terminal failure, with the structured reason retained.
    Failed { reason: SyncFailure },
}

/// Mirror of `moat_core::SyncFailure` — a tagged object rather than prose,
/// so a scenario matches on the outcome instead of parsing a message that
/// is deliberately worded differently on each side.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncFailure {
    NoAnswer,
    RequestExpired,
    Declined,
    ChannelClosed { detail: String },
    PublishFailed { detail: String },
}

impl SyncRequestUiState {
    pub fn is_complete(&self) -> bool {
        matches!(self, SyncRequestUiState::Complete)
    }

    pub fn is_awaiting_approval(&self) -> bool {
        matches!(self, SyncRequestUiState::AwaitingApproval { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, SyncRequestUiState::Failed { .. })
    }
}

// ── MoatCliClient impl ────────────────────────────────────────────────────────

impl MoatCliClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.into(),
        }
    }

    /// `POST /login`
    pub async fn login(&self, handle: &str, password: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/login", self.base_url))
            .json(&json!({ "handle": handle, "password": password }))
            .send()
            .await
            .context("POST /login")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("login failed ({status}): {body}");
        }
        Ok(())
    }

    /// `GET /status`
    pub async fn status(&self) -> Result<StatusResponse> {
        self.http
            .get(format!("{}/status", self.base_url))
            .send()
            .await
            .context("GET /status")?
            .json()
            .await
            .context("parse /status response")
    }

    /// `GET /conversations`
    pub async fn list_conversations(&self) -> Result<Vec<Conversation>> {
        self.http
            .get(format!("{}/conversations", self.base_url))
            .send()
            .await
            .context("GET /conversations")?
            .json()
            .await
            .context("parse /conversations response")
    }

    /// `POST /conversations` — start a conversation with `recipient_handle`.
    pub async fn start_conversation(&self, recipient_handle: &str) -> Result<String> {
        let resp = self
            .http
            .post(format!("{}/conversations", self.base_url))
            .json(&json!({ "recipient_handle": recipient_handle }))
            .send()
            .await
            .context("POST /conversations")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("start_conversation failed ({status}): {body}");
        }
        let body: CreateConversationResponse = resp.json().await.context("parse group_id")?;
        Ok(body.group_id)
    }

    /// `POST /conversations/:group_id/members` — add a member to an existing group.
    pub async fn add_member(&self, group_id: &str, handle: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/conversations/{group_id}/members",
                self.base_url
            ))
            .json(&json!({ "handle": handle }))
            .send()
            .await
            .context("POST /conversations/:group_id/members")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("add_member failed ({status}): {body}");
        }
        Ok(())
    }

    /// `GET /conversations/:group_id/messages`
    pub async fn get_messages(&self, group_id: &str) -> Result<Vec<Message>> {
        self.http
            .get(format!("{}/conversations/{group_id}/messages", self.base_url))
            .send()
            .await
            .context("GET /messages")?
            .json()
            .await
            .context("parse messages response")
    }

    /// `POST /conversations/:group_id/messages`
    pub async fn send_message(&self, group_id: &str, text: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/conversations/{group_id}/messages", self.base_url))
            .json(&json!({ "text": text }))
            .send()
            .await
            .context("POST /messages")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("send_message failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /conversations/:group_id/messages/image` — send raw image bytes.
    pub async fn send_image(&self, group_id: &str, image_bytes: &[u8]) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/conversations/{group_id}/messages/image",
                self.base_url
            ))
            .header("content-type", "application/octet-stream")
            .body(image_bytes.to_vec())
            .send()
            .await
            .context("POST /messages/image")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("send_image failed ({status}): {body}");
        }
        Ok(())
    }

    /// `GET /conversations/:group_id/messages/:message_id/image` — fetch decrypted image bytes.
    pub async fn fetch_image(&self, group_id: &str, message_id: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!(
                "{}/conversations/{group_id}/messages/{message_id}/image",
                self.base_url
            ))
            .send()
            .await
            .context("GET /messages/:message_id/image")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("fetch_image failed ({status}): {body}");
        }
        Ok(resp.bytes().await.context("read image bytes")?.to_vec())
    }

    /// `POST /conversations/:group_id/messages/:message_id/reactions`
    pub async fn send_reaction(&self, group_id: &str, message_id: &str, emoji: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/conversations/{group_id}/messages/{message_id}/reactions",
                self.base_url
            ))
            .json(&json!({ "emoji": emoji }))
            .send()
            .await
            .context("POST /reactions")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("send_reaction failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /conversations/:group_id/messages/:message_id/retry`
    pub async fn retry_send(&self, group_id: &str, message_id: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/conversations/{group_id}/messages/{message_id}/retry",
                self.base_url
            ))
            .send()
            .await
            .context("POST /retry")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("retry_send failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /poll` — triggers a fetch and waits up to 30 s.
    pub async fn poll(&self) -> Result<PollStats> {
        self.http
            .post(format!("{}/poll", self.base_url))
            .send()
            .await
            .context("POST /poll")?
            .json()
            .await
            .context("parse poll response")
    }

    /// `POST /poll/:seconds` — set auto-poll interval; `0` disables polling.
    pub async fn set_poll_interval(&self, seconds: u64) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/poll/{seconds}", self.base_url))
            .send()
            .await
            .context("POST /poll/:seconds")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("set_poll_interval failed ({status}): {body}");
        }
        Ok(())
    }

    /// `DELETE /conversations/:group_id/members/:handle` — kick a member.
    pub async fn kick_member(&self, group_id: &str, handle: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!(
                "{}/conversations/{group_id}/members/{handle}",
                self.base_url
            ))
            .send()
            .await
            .context("DELETE /conversations/:group_id/members/:handle")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("kick_member failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /ring-tick` — trigger one device-ring tick synchronously.
    pub async fn ring_tick(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/ring-tick", self.base_url))
            .send()
            .await
            .context("POST /ring-tick")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("ring_tick failed ({status}): {body}");
        }
        Ok(())
    }

    /// `GET /ring-status` — return the current ring state.
    pub async fn ring_status(&self) -> Result<RingStatus> {
        self.http
            .get(format!("{}/ring-status", self.base_url))
            .send()
            .await
            .context("GET /ring-status")?
            .json()
            .await
            .context("parse ring-status response")
    }

    /// `POST /sync/offer` — send history to the named sibling.
    pub async fn sync_offer(&self, device_id: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/sync/offer", self.base_url))
            .json(&serde_json::json!({ "device_id": device_id }))
            .send()
            .await
            .context("POST /sync/offer")?;
        if !resp.status().is_success() {
            anyhow::bail!("sync/offer failed: {}", resp.text().await.unwrap_or_default());
        }
        Ok(())
    }

    /// `GET /sync/status` — return whether a sync session is active.
    pub async fn sync_status(&self) -> Result<bool> {
        Ok(self
            .sync_status_raw()
            .await?
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    /// `GET /sync/status` — the whole document, for assertions about the
    /// sync-request projection rather than just the active flag. Both
    /// runtimes emit the same shape (serde's, which the Dart server
    /// mirrors by hand), so a test reads one thing from either.
    pub async fn sync_status_raw(&self) -> Result<serde_json::Value> {
        self.http
            .get(format!("{}/sync/status", self.base_url))
            .send()
            .await
            .context("GET /sync/status")?
            .json()
            .await
            .context("parse sync/status response")
    }

    /// The completion report a finished sync left behind: how many
    /// messages arrived, across how many conversations, and which device
    /// they came from. `None` until the request reaches `complete`.
    pub async fn sync_completion(&self) -> Result<Option<SyncCompletion>> {
        let val = self.sync_status_raw().await?;
        let request = match val.get("request") {
            Some(r) => r,
            None => return Ok(None),
        };
        if request.get("phase").and_then(|p| p.as_str()) != Some("complete") {
            return Ok(None);
        }
        let tally = request.get("tally");
        Ok(Some(SyncCompletion {
            messages: tally
                .and_then(|t| t.get("messages"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            conversations: tally
                .and_then(|t| t.get("conversations"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            device_name: request
                .get("device_name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        }))
    }

    /// `POST /sync/start` — trigger a ring-tick which initiates history sync if
    /// the caller is the offerer device (leaf index 0).
    pub async fn sync_start(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/sync/start", self.base_url))
            .send()
            .await
            .context("POST /sync/start")?;
        let status = resp.status();
        if !status.is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("sync_start failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /sync/request` — ask the user's other devices for history
    /// this one is missing. A sibling's user must accept
    /// (`sync_accept`); no host answers automatically.
    pub async fn sync_request(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/sync/request", self.base_url))
            .send()
            .await
            .context("POST /sync/request")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("sync_request failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /sync/accept` — send this device's history to the sibling
    /// that asked for it.
    pub async fn sync_accept(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/sync/accept", self.base_url))
            .send()
            .await
            .context("POST /sync/accept")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("sync_accept failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /sync/decline` — refuse a sibling's request. Local only: the
    /// requester keeps waiting for another sibling.
    pub async fn sync_decline(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/sync/decline", self.base_url))
            .send()
            .await
            .context("POST /sync/decline")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("sync_decline failed ({status}): {body}");
        }
        Ok(())
    }

    /// `GET /sync/status` — the sync-request projection, verbatim.
    pub async fn sync_request_status(&self) -> Result<SyncRequestUiState> {
        let val: serde_json::Value = self
            .http
            .get(format!("{}/sync/status", self.base_url))
            .send()
            .await
            .context("GET /sync/status")?
            .json()
            .await
            .context("parse sync/status response")?;
        let request = val
            .get("request")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("sync/status carried no request state"))?;
        serde_json::from_value(request).context("parse sync request state")
    }

    /// `POST /pair/new` — new device: generate a fresh pairing code and
    /// start listening for the existing device's `Enroll`.
    pub async fn pair_new(&self) -> Result<PairNewResponse> {
        let resp = self
            .http
            .post(format!("{}/pair/new", self.base_url))
            .send()
            .await
            .context("POST /pair/new")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("pair_new failed ({status}): {body}");
        }
        resp.json().await.context("parse /pair/new response")
    }

    /// `POST /pair/confirm` — existing device: enter a pairing code
    /// (scanned or typed). No longer implies approval of the resulting
    /// `Enroll` — see `pair_approve`.
    pub async fn pair_confirm(&self, code: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/pair/confirm", self.base_url))
            .json(&json!({ "code": code }))
            .send()
            .await
            .context("POST /pair/confirm")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("pair_confirm failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /pair/approve` — existing device: approve the `Enroll`
    /// `pair_status` reports as `awaiting_approval`. No host auto-approves
    /// anymore — the deleted `event_broadcast.is_some()` fork in
    /// `moat-cli` (and the `autoApprove` flag it mirrored in
    /// `moat_dart_server`) used to; every scenario must call this
    /// explicitly now.
    pub async fn pair_approve(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/pair/approve", self.base_url))
            .send()
            .await
            .context("POST /pair/approve")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("pair_approve failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /pair/reject` — existing device: decline the pending `Enroll`.
    pub async fn pair_reject(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/pair/reject", self.base_url))
            .send()
            .await
            .context("POST /pair/reject")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("pair_reject failed ({status}): {body}");
        }
        Ok(())
    }

    /// `POST /pair/cancel` — either role: abort an in-flight pairing
    /// before it reaches a terminal state.
    pub async fn pair_cancel(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/pair/cancel", self.base_url))
            .send()
            .await
            .context("POST /pair/cancel")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("pair_cancel failed ({status}): {body}");
        }
        Ok(())
    }

    /// `GET /pair/status` — poll pairing progress. Returns the tagged
    /// `PairingUiState` verbatim.
    pub async fn pair_status(&self) -> Result<PairingUiState> {
        self.http
            .get(format!("{}/pair/status", self.base_url))
            .send()
            .await
            .context("GET /pair/status")?
            .json()
            .await
            .context("parse /pair/status response")
    }

    /// `POST /watch`
    pub async fn watch_handle(&self, handle: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/watch", self.base_url))
            .json(&json!({ "handle": handle }))
            .send()
            .await
            .context("POST /watch")?;
        let status = resp.status();
        if !status.is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            anyhow::bail!("watch_handle failed ({status}): {body}");
        }
        Ok(())
    }
}
