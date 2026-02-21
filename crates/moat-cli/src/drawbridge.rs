//! Drawbridge WebSocket connection manager.
//!
//! Manages connections to multiple Drawbridge relays:
//! - **Own Drawbridge** (sender mode, DID challenge-response auth):
//!   event_posted, register_ticket, revoke_ticket
//! - **Partner Drawbridges** (recipient mode, ticket auth):
//!   watch_tags, receive new_event notifications

use crate::app::BgEvent;
use crate::keystore::hex;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

type WsWriter =
    futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>;

/// Manages connections to multiple Drawbridges.
///
/// Architecture:
/// - Field on App struct (not a standalone service)
/// - WebSocket read loops run as tokio::spawn tasks
/// - Notifications flow back through the existing BgEvent channel
/// - Write operations go through stored write-halves of the WebSocket splits
pub struct DrawbridgeManager {
    /// Our own Drawbridge (sender mode, DID-authenticated)
    own: Option<OwnDrawbridge>,

    /// Partner Drawbridges (recipient mode, ticket-authenticated)
    /// Key: (URL, ticket_hex) — one connection per (URL, ticket) pair.
    /// Future optimization: multiplex tickets on a single connection via an
    /// `add_ticket` protocol message, reducing connection count at the cost
    /// of slightly degraded privacy (Drawbridge could correlate tickets).
    partners: HashMap<(String, String), PartnerDrawbridge>,

    /// Received hints: (partner_did, device_id_hex) -> hint
    hints: HashMap<(String, String), StoredHint>,

    /// Channel for sending BgEvents back to the main App loop
    bg_tx: mpsc::UnboundedSender<BgEvent>,
}

#[allow(dead_code)]
struct OwnDrawbridge {
    url: String,
    writer: WsWriter,
    /// Tickets registered on this Drawbridge: ticket_hex -> group_id_hex
    registered_tickets: HashMap<String, String>,
}

#[allow(dead_code)]
struct PartnerDrawbridge {
    url: String,
    ticket_hex: String,
    writer: WsWriter,
    /// Which (DID, device_id_hex) pair this connection is for
    partner_did: String,
    partner_device_id_hex: String,
    /// Group ID for this connection
    group_id_hex: String,
    /// Tags currently being watched on this connection
    watching_tags: Vec<[u8; 16]>,
    /// Connection state for reconnect
    state: ConnectionState,
}

#[allow(dead_code)]
enum ConnectionState {
    Connected,
    Reconnecting { attempt: u32, next_retry: Instant },
}

/// Persisted hint from a conversation partner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredHint {
    pub url: String,
    pub device_id_hex: String,
    pub ticket_hex: String,
    pub partner_did: String,
    pub group_id_hex: String,
}

/// Persisted Drawbridge state (stored in drawbridge.json).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DrawbridgeState {
    /// Our own Drawbridge URL (set via --drawbridge-url)
    pub own_url: Option<String>,

    /// Tickets we've registered on our own Drawbridge
    /// Key: group_id_hex, Value: ticket_hex
    pub own_tickets: HashMap<String, String>,

    /// Received DrawbridgeHints from conversation partners
    /// Serialized as a Vec of tuples since JSON doesn't support tuple keys
    pub partner_hints: Vec<StoredHint>,
}

/// Backoff schedule for reconnection attempts
fn backoff_duration(attempt: u32) -> Duration {
    match attempt {
        0 => Duration::from_secs(5),
        1 => Duration::from_secs(10),
        2 => Duration::from_secs(30),
        3 => Duration::from_secs(60),
        _ => Duration::from_secs(300),
    }
}

impl DrawbridgeManager {
    /// Create a new DrawbridgeManager.
    pub fn new(bg_tx: mpsc::UnboundedSender<BgEvent>) -> Self {
        Self {
            own: None,
            partners: HashMap::new(),
            hints: HashMap::new(),
            bg_tx,
        }
    }

    /// Check if there are any persisted partner hints.
    pub fn hints_empty(&self) -> bool {
        self.hints.is_empty()
    }

    /// Load persisted state into the manager (hints only — connections are made later).
    pub fn load_state(&mut self, state: &DrawbridgeState) {
        self.hints.clear();
        for hint in &state.partner_hints {
            let key = (hint.partner_did.clone(), hint.device_id_hex.clone());
            self.hints.insert(key, hint.clone());
        }
    }

    /// Export current state for persistence.
    pub fn export_state(&self, own_url: &Option<String>) -> DrawbridgeState {
        let own_tickets = self
            .own
            .as_ref()
            .map(|o| o.registered_tickets.clone())
            .unwrap_or_default();

        DrawbridgeState {
            own_url: own_url.clone(),
            own_tickets,
            partner_hints: self.hints.values().cloned().collect(),
        }
    }

    /// Connect to our own Drawbridge as sender (DID challenge-response).
    ///
    /// 1. WebSocket connect
    /// 2. Send request_challenge
    /// 3. Receive challenge{nonce}
    /// 4. Sign with Ed25519 identity key
    /// 5. Send challenge_response{did, signature, timestamp, public_key}
    /// 6. Receive authenticated
    /// 7. Split: spawn read loop, store write half
    /// 8. Re-register all persisted tickets
    pub async fn connect_own(
        &mut self,
        url: &str,
        did: &str,
        identity_key_bundle: &[u8],
        persisted_tickets: &HashMap<String, String>,
    ) -> Result<(), String> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| format!("WebSocket connect failed: {e}"))?;

        let (mut writer, mut reader) = ws_stream.split();

        // 1. Send request_challenge
        let req = serde_json::json!({"type": "request_challenge"});
        writer
            .send(Message::Text(req.to_string()))
            .await
            .map_err(|e| format!("send request_challenge: {e}"))?;

        // 2. Read challenge
        let challenge_msg = read_json_msg(&mut reader).await?;
        let msg_type = challenge_msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if msg_type != "challenge" {
            return Err(format!("expected challenge, got {msg_type}"));
        }
        let nonce = challenge_msg
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or("missing nonce in challenge")?
            .to_string();

        // 3. Sign: nonce + "\n" + relay_url + "\n" + timestamp + "\n"
        // The server includes the request path in its relay URL, so we sign
        // the full connection URL as-is.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let message_bytes = format!("{}\n{}\n{}\n", nonce, url, timestamp);
        let (sig_bytes, pub_bytes) =
            moat_core::MoatSession::sign_drawbridge_challenge(identity_key_bundle, message_bytes.as_bytes())
                .map_err(|e| format!("signing failed: {e}"))?;
        let sig_b64 = base64_encode(&sig_bytes);
        let pub_b64 = base64_encode(&pub_bytes);

        // 4. Send challenge_response
        let resp = serde_json::json!({
            "type": "challenge_response",
            "did": did,
            "signature": sig_b64,
            "timestamp": timestamp,
            "public_key": pub_b64,
        });
        writer
            .send(Message::Text(resp.to_string()))
            .await
            .map_err(|e| format!("send challenge_response: {e}"))?;

        // 5. Read authenticated
        let auth_msg = read_json_msg(&mut reader).await?;
        let auth_type = auth_msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if auth_type == "error" {
            let err = auth_msg
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("auth failed: {err}"));
        }
        if auth_type != "authenticated" {
            return Err(format!("expected authenticated, got {auth_type}"));
        }

        // 6. Spawn read loop
        let bg_tx = self.bg_tx.clone();
        let url_clone = url.to_string();
        tokio::spawn(async move {
            own_read_loop(reader, bg_tx, url_clone).await;
        });

        // 7. Store connection
        let mut own = OwnDrawbridge {
            url: url.to_string(),
            writer,
            registered_tickets: HashMap::new(),
        };

        // 8. Re-register persisted tickets
        for (group_id_hex, ticket_hex) in persisted_tickets {
            let msg = serde_json::json!({
                "type": "register_ticket",
                "ticket": ticket_hex,
            });
            if own
                .writer
                .send(Message::Text(msg.to_string()))
                .await
                .is_ok()
            {
                own.registered_tickets
                    .insert(ticket_hex.clone(), group_id_hex.clone());
            }
        }

        self.own = Some(own);
        Ok(())
    }

    /// Connect to a partner's Drawbridge as recipient (ticket auth).
    pub async fn connect_partner(&mut self, hint: &StoredHint) -> Result<(), String> {
        let ticket_key = (hint.url.clone(), hint.ticket_hex.clone());

        // Don't double-connect
        if self.partners.contains_key(&ticket_key) {
            return Ok(());
        }

        let (ws_stream, _) = tokio_tungstenite::connect_async(&hint.url)
            .await
            .map_err(|e| format!("WebSocket connect failed: {e}"))?;

        let (mut writer, mut reader) = ws_stream.split();

        // 1. Send ticket_auth
        let msg = serde_json::json!({
            "type": "ticket_auth",
            "ticket": hint.ticket_hex,
        });
        writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send ticket_auth: {e}"))?;

        // 2. Read ticket_authenticated
        let auth_msg = read_json_msg(&mut reader).await?;
        let auth_type = auth_msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if auth_type == "error" {
            let err = auth_msg
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("ticket auth failed: {err}"));
        }
        if auth_type != "ticket_authenticated" {
            return Err(format!("expected ticket_authenticated, got {auth_type}"));
        }

        // 3. Spawn read loop
        let bg_tx = self.bg_tx.clone();
        let url_clone = hint.url.clone();
        let ticket_hex_clone = hint.ticket_hex.clone();
        tokio::spawn(async move {
            partner_read_loop(reader, bg_tx, url_clone, ticket_hex_clone).await;
        });

        // 4. Store connection
        let partner = PartnerDrawbridge {
            url: hint.url.clone(),
            ticket_hex: hint.ticket_hex.clone(),
            writer,
            partner_did: hint.partner_did.clone(),
            partner_device_id_hex: hint.device_id_hex.clone(),
            group_id_hex: hint.group_id_hex.clone(),
            watching_tags: Vec::new(),
            state: ConnectionState::Connected,
        };

        self.partners.insert(ticket_key.clone(), partner);

        let _ = self.bg_tx.send(BgEvent::DrawbridgeConnected {
            url: hint.url.clone(),
            ticket_hex: hint.ticket_hex.clone(),
        });

        Ok(())
    }

    /// Handle an incoming DrawbridgeHint from a decrypted MLS event.
    /// Stores the hint and connects to the partner's Drawbridge.
    pub async fn handle_hint(
        &mut self,
        partner_did: &str,
        device_id: &[u8],
        url: &str,
        ticket: &[u8],
        group_id_hex: &str,
    ) {
        let device_id_hex = hex::encode(device_id);
        let ticket_hex = hex::encode(ticket);

        let hint = StoredHint {
            url: url.to_string(),
            device_id_hex: device_id_hex.clone(),
            ticket_hex: ticket_hex.clone(),
            partner_did: partner_did.to_string(),
            group_id_hex: group_id_hex.to_string(),
        };

        let key = (partner_did.to_string(), device_id_hex);
        self.hints.insert(key, hint.clone());

        if let Err(e) = self.connect_partner(&hint).await {
            // Will retry later via retry_disconnected
            let _ = self.bg_tx.send(BgEvent::DrawbridgeDisconnected {
                url: url.to_string(),
                ticket_hex,
                reason: e,
            });
        }
    }

    /// Register a ticket on our own Drawbridge.
    pub async fn register_ticket(
        &mut self,
        ticket: &[u8; 32],
        group_id_hex: &str,
    ) -> Result<(), String> {
        let own = self
            .own
            .as_mut()
            .ok_or("not connected to own Drawbridge")?;

        let ticket_hex = hex::encode(ticket);
        let msg = serde_json::json!({
            "type": "register_ticket",
            "ticket": &ticket_hex,
        });
        own.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send register_ticket: {e}"))?;

        own.registered_tickets
            .insert(ticket_hex, group_id_hex.to_string());
        Ok(())
    }

    /// Send event_posted on our own Drawbridge.
    pub async fn notify_event_posted(
        &mut self,
        tag: &[u8; 16],
        rkey: &str,
    ) -> Result<(), String> {
        let own = self
            .own
            .as_mut()
            .ok_or("not connected to own Drawbridge")?;

        let msg = serde_json::json!({
            "type": "event_posted",
            "tag": hex::encode(tag),
            "rkey": rkey,
        });
        own.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send event_posted: {e}"))?;

        Ok(())
    }

    /// Update watched tags for a specific partner Drawbridge connection.
    /// Sends the full set of relevant tags via watch_tags (replace, not incremental).
    pub async fn update_tags_for_partner(
        &mut self,
        partner_did: &str,
        device_id_hex: &str,
        tags: &[[u8; 16]],
    ) -> Result<(), String> {
        // Find the partner connection for this (did, device_id)
        let hint_key = (partner_did.to_string(), device_id_hex.to_string());
        let hint = self
            .hints
            .get(&hint_key)
            .ok_or("no hint for this partner device")?;
        let partner_key = (hint.url.clone(), hint.ticket_hex.clone());

        let partner = self
            .partners
            .get_mut(&partner_key)
            .ok_or("not connected to this partner")?;

        let tag_strings: Vec<String> = tags.iter().map(|t| hex::encode(t)).collect();
        let msg = serde_json::json!({
            "type": "watch_tags",
            "tags": tag_strings,
        });
        partner
            .writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send watch_tags: {e}"))?;

        partner.watching_tags = tags.to_vec();
        Ok(())
    }

    /// Reconnect to all persisted partner Drawbridges (called on startup).
    pub async fn reconnect_all_partners(&mut self) {
        let hints: Vec<StoredHint> = self.hints.values().cloned().collect();
        for hint in hints {
            if let Err(e) = self.connect_partner(&hint).await {
                let _ = self.bg_tx.send(BgEvent::DrawbridgeDisconnected {
                    url: hint.url.clone(),
                    ticket_hex: hint.ticket_hex.clone(),
                    reason: e,
                });
            }
        }
    }

    /// Retry disconnected partner connections with exponential backoff.
    /// Called periodically from tick().
    pub async fn retry_disconnected(&mut self) {
        let now = Instant::now();

        // Collect hints for partners that need reconnecting
        let mut to_reconnect: Vec<StoredHint> = Vec::new();

        for partner in self.partners.values_mut() {
            if let ConnectionState::Reconnecting {
                attempt: _,
                next_retry,
            } = &partner.state
            {
                if now >= *next_retry {
                    // Find the hint for this partner
                    let hint_key = (
                        partner.partner_did.clone(),
                        partner.partner_device_id_hex.clone(),
                    );
                    if let Some(hint) = self.hints.get(&hint_key) {
                        to_reconnect.push(hint.clone());
                    }
                }
            }
        }

        // Also check for hints that have no partner connection at all
        for hint in self.hints.values() {
            let partner_key = (hint.url.clone(), hint.ticket_hex.clone());
            if !self.partners.contains_key(&partner_key) {
                to_reconnect.push(hint.clone());
            }
        }

        for hint in to_reconnect {
            let partner_key = (hint.url.clone(), hint.ticket_hex.clone());
            let attempt = self
                .partners
                .get(&partner_key)
                .and_then(|p| match &p.state {
                    ConnectionState::Reconnecting { attempt, .. } => Some(*attempt),
                    _ => None,
                })
                .unwrap_or(0);

            // Remove old failed connection
            self.partners.remove(&partner_key);

            match self.connect_partner(&hint).await {
                Ok(()) => {
                    // Connection succeeded — state is already Connected
                }
                Err(e) => {
                    let next_attempt = attempt + 1;
                    let _next_retry = Instant::now() + backoff_duration(next_attempt);

                    // Insert a placeholder for tracking reconnect state
                    // We can't store a real PartnerDrawbridge without a writer,
                    // so we track reconnect state in the hints via a separate map
                    let _ = self.bg_tx.send(BgEvent::DrawbridgeDisconnected {
                        url: hint.url.clone(),
                        ticket_hex: hint.ticket_hex.clone(),
                        reason: e,
                    });

                    // Store reconnect state — we'll track this via the absence
                    // of a partner connection + next call to retry_disconnected
                    // being gated by the backoff timing in the tick() method
                }
            }
        }
    }

    /// Get the number of active connections (for status bar).
    pub fn active_connection_count(&self) -> usize {
        let own_count = if self.own.is_some() { 1 } else { 0 };
        let partner_count = self
            .partners
            .values()
            .filter(|p| matches!(p.state, ConnectionState::Connected))
            .count();
        own_count + partner_count
    }

    /// Check if connected to own Drawbridge.
    pub fn has_own_connection(&self) -> bool {
        self.own.is_some()
    }

    /// Get tags relevant to a specific partner device in a specific conversation.
    pub fn get_partner_for_group(
        &self,
        group_id_hex: &str,
    ) -> Vec<(&str, &str)> {
        self.hints
            .iter()
            .filter(|(_, hint)| hint.group_id_hex == group_id_hex)
            .map(|((did, device_id_hex), _)| (did.as_str(), device_id_hex.as_str()))
            .collect()
    }
}

/// Read a JSON message from a WebSocket reader.
async fn read_json_msg(
    reader: &mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
) -> Result<serde_json::Value, String> {
    loop {
        match reader.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text)
                    .map_err(|e| format!("invalid JSON from server: {e}"));
            }
            Some(Ok(Message::Ping(_))) => continue,
            Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) => return Err("connection closed".to_string()),
            Some(Err(e)) => return Err(format!("read error: {e}")),
            None => return Err("connection closed".to_string()),
            _ => continue,
        }
    }
}

/// Read loop for the own Drawbridge connection (sender mode).
/// We don't expect many messages from the server in sender mode,
/// but we need to keep the connection alive and handle disconnects.
async fn own_read_loop(
    mut reader: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    bg_tx: mpsc::UnboundedSender<BgEvent>,
    url: String,
) {
    loop {
        match reader.next().await {
            Some(Ok(Message::Text(text))) => {
                // Parse and handle server messages (ticket_registered, etc.)
                if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                    let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match msg_type {
                        "ticket_registered" | "ticket_revoked" => {
                            // Expected responses, no action needed
                        }
                        "error" => {
                            let err = msg
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                                url: url.clone(),
                                ticket_hex: String::new(),
                                reason: format!("server error: {err}"),
                            });
                        }
                        _ => {}
                    }
                }
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                    url: url.clone(),
                    ticket_hex: String::new(),
                    reason: "connection closed".to_string(),
                });
                return;
            }
            Some(Err(e)) => {
                let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                    url: url.clone(),
                    ticket_hex: String::new(),
                    reason: format!("read error: {e}"),
                });
                return;
            }
            _ => continue,
        }
    }
}

/// Read loop for a partner Drawbridge connection (recipient mode).
/// Listens for new_event notifications and sends them via BgEvent.
async fn partner_read_loop(
    mut reader: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    bg_tx: mpsc::UnboundedSender<BgEvent>,
    url: String,
    ticket_hex: String,
) {
    loop {
        match reader.next().await {
            Some(Ok(Message::Text(text))) => {
                if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                    let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match msg_type {
                        "new_event" => {
                            let tag_hex = msg
                                .get("tag")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let rkey = msg
                                .get("rkey")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let did = msg
                                .get("did")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            if let Ok(tag_bytes) = hex::decode(&tag_hex) {
                                if tag_bytes.len() == 16 {
                                    let mut tag = [0u8; 16];
                                    tag.copy_from_slice(&tag_bytes);
                                    let _ = bg_tx.send(BgEvent::DrawbridgeNewEvent {
                                        tag,
                                        rkey,
                                        did,
                                    });
                                }
                            }
                        }
                        "error" => {
                            let err = msg
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                                url: url.clone(),
                                ticket_hex: ticket_hex.clone(),
                                reason: format!("server error: {err}"),
                            });
                        }
                        _ => {}
                    }
                }
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                    url: url.clone(),
                    ticket_hex: ticket_hex.clone(),
                    reason: "connection closed".to_string(),
                });
                return;
            }
            Some(Err(e)) => {
                let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                    url: url.clone(),
                    ticket_hex: ticket_hex.clone(),
                    reason: format!("read error: {e}"),
                });
                return;
            }
            _ => continue,
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drawbridge_state_roundtrip() {
        let state = DrawbridgeState {
            own_url: Some("wss://relay.example.com/ws".to_string()),
            own_tickets: {
                let mut m = HashMap::new();
                m.insert("group_abc".to_string(), "ticket_123".to_string());
                m
            },
            partner_hints: vec![StoredHint {
                url: "wss://other-relay.example.com/ws".to_string(),
                device_id_hex: "aabb".to_string(),
                ticket_hex: "ccdd".to_string(),
                partner_did: "did:plc:partner".to_string(),
                group_id_hex: "eeff".to_string(),
            }],
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: DrawbridgeState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.own_url, state.own_url);
        assert_eq!(parsed.own_tickets.len(), 1);
        assert_eq!(parsed.partner_hints.len(), 1);
        assert_eq!(parsed.partner_hints[0].partner_did, "did:plc:partner");
    }

    #[test]
    fn test_backoff_schedule() {
        assert_eq!(backoff_duration(0), Duration::from_secs(5));
        assert_eq!(backoff_duration(1), Duration::from_secs(10));
        assert_eq!(backoff_duration(2), Duration::from_secs(30));
        assert_eq!(backoff_duration(3), Duration::from_secs(60));
        assert_eq!(backoff_duration(4), Duration::from_secs(300));
        assert_eq!(backoff_duration(100), Duration::from_secs(300));
    }

    #[test]
    fn test_hint_storage() {
        let bg_tx = mpsc::unbounded_channel().0;
        let mut mgr = DrawbridgeManager::new(bg_tx);

        let state = DrawbridgeState {
            own_url: None,
            own_tickets: HashMap::new(),
            partner_hints: vec![
                StoredHint {
                    url: "wss://a.com/ws".to_string(),
                    device_id_hex: "aa".to_string(),
                    ticket_hex: "bb".to_string(),
                    partner_did: "did:plc:alice".to_string(),
                    group_id_hex: "cc".to_string(),
                },
                StoredHint {
                    url: "wss://b.com/ws".to_string(),
                    device_id_hex: "dd".to_string(),
                    ticket_hex: "ee".to_string(),
                    partner_did: "did:plc:bob".to_string(),
                    group_id_hex: "ff".to_string(),
                },
            ],
        };

        mgr.load_state(&state);
        assert_eq!(mgr.hints.len(), 2);

        let exported = mgr.export_state(&None);
        assert_eq!(exported.partner_hints.len(), 2);
    }

}
