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
}

#[derive(Debug, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub name: String,
    pub participant_did: String,
    pub epoch: u64,
    pub unread: usize,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub from: String,
    pub content: String,
    pub timestamp: String,
    pub is_own: bool,
    pub sender_did: Option<String>,
    pub message_id: Option<String>,
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
