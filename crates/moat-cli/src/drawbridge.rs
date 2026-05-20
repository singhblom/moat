//! Drawbridge WebSocket connection manager.
//!
//! Manages a single connection to the user's own Drawbridge relay.
//! The relay handles fan-out to recipient relays via relay-to-relay push.
//!
//! Architecture:
//! - Client connects only to their own Drawbridge (DID challenge-response auth)
//! - On send: client sends envelope with payload + recipient relay URLs
//! - On receive: relay delivers `new_event` with inline payload for instant decryption
//! - Drawbridge discovery: each user publishes `social.moat.drawbridgeConfig` ATProto record

use crate::app::BgEvent;
use crate::keystore::hex;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

type WsWriter =
    futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>;

type PairWsWriter =
    futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>;

/// Manages the connection to the user's own Drawbridge relay.
///
/// Architecture:
/// - Field on App struct (not a standalone service)
/// - WebSocket read loop runs as a tokio::spawn task
/// - Notifications flow back through the existing BgEvent channel
/// - Write operations go through the stored write-half of the WebSocket split
pub struct DrawbridgeManager {
    /// Our own Drawbridge connection (DID-authenticated)
    own: Option<OwnDrawbridge>,

    /// Channel for sending BgEvents back to the main App loop
    bg_tx: mpsc::UnboundedSender<BgEvent>,

    /// Number of consecutive reconnect attempts (reset on successful connect)
    reconnect_attempt: u32,

    /// Write half of the active pair WebSocket, if one is open.
    pair_writer: Option<PairWsWriter>,

    /// Abort handle for the pair_read_loop task.  Aborting it drops the read
    /// half of the pair WS, so the TCP connection is fully closed and Drawbridge
    /// detects the peer disconnect (sends `pair_closed` on the main WS).
    pair_read_task: Option<tokio::task::AbortHandle>,
}

struct OwnDrawbridge {
    writer: WsWriter,
}

/// Persisted Drawbridge state (stored in drawbridge.json).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DrawbridgeState {
    /// Our own Drawbridge URL (set via --drawbridge-url)
    pub own_url: Option<String>,
}

/// Cached Drawbridge configuration for a conversation partner.
#[derive(Debug, Clone)]
pub struct CachedDrawbridgeConfig {
    /// Drawbridge URLs for this DID, in priority order
    pub urls: Vec<String>,
}

/// In-memory cache of partner Drawbridge configs (DID -> URLs).
/// Not persisted — refetched on login.
pub type DrawbridgeConfigCache = HashMap<String, CachedDrawbridgeConfig>;

/// Backoff schedule for reconnection attempts.
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
            bg_tx,
            reconnect_attempt: 0,
            pair_writer: None,
            pair_read_task: None,
        }
    }

    /// Export current state for persistence.
    pub fn export_state(&self, own_url: &Option<String>) -> DrawbridgeState {
        DrawbridgeState {
            own_url: own_url.clone(),
        }
    }

    /// Connect to our own Drawbridge (DID challenge-response).
    ///
    /// 1. WebSocket connect
    /// 2. Send request_challenge
    /// 3. Receive challenge{nonce}
    /// 4. Sign with Ed25519 identity key
    /// 5. Send challenge_response{did, signature, timestamp, public_key}
    /// 6. Receive authenticated
    /// 7. Split: spawn read loop, store write half
    pub async fn connect_own(
        &mut self,
        url: &str,
        did: &str,
        identity_key_bundle: &[u8],
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

        // 7. Store connection, reset reconnect backoff
        self.own = Some(OwnDrawbridge { writer });
        self.reconnect_attempt = 0;

        Ok(())
    }

    /// Send event_posted envelope to our own Drawbridge with payload and relay URLs.
    ///
    /// The relay will:
    /// 1. Deliver locally to any of our other devices watching this tag
    /// 2. Fan out to each recipient's Drawbridge via POST /relay/event
    ///
    /// `did` is included in the envelope so the relay can use it for PDS
    /// verification and rate-limiting without storing it on the connection.
    pub async fn notify_event_posted(
        &mut self,
        did: &str,
        tag: &[u8; 16],
        rkey: &str,
        payload: &[u8],
        drawbridge_urls: &[String],
    ) -> Result<(), String> {
        let own = self
            .own
            .as_mut()
            .ok_or("not connected to own Drawbridge")?;

        let msg = serde_json::json!({
            "type": "event_posted",
            "did": did,
            "tag": hex::encode(tag),
            "rkey": rkey,
            "payload": base64_encode(payload),
            "relay_urls": drawbridge_urls,
        });
        own.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send event_posted: {e}"))?;

        Ok(())
    }

    /// Register watched tags on our own Drawbridge.
    ///
    /// Tags are opaque 16-byte hex strings that serve as anonymous mailboxes.
    /// The relay routes inbound relay-to-relay events to clients watching
    /// matching tags.
    pub async fn watch_tags(&mut self, tags: &[[u8; 16]]) -> Result<(), String> {
        let own = self
            .own
            .as_mut()
            .ok_or("not connected to own Drawbridge")?;

        let tag_strings: Vec<String> = tags.iter().map(|t| hex::encode(t)).collect();
        let msg = serde_json::json!({
            "type": "watch_tags",
            "tags": tag_strings,
        });
        own.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send watch_tags: {e}"))?;

        Ok(())
    }

    /// Register this device for push notifications on the relay.
    ///
    /// Called automatically after a successful `connect_own` + `watch_tags` so the
    /// relay can suppress FCM delivery while this WebSocket is live.
    /// Uses a stable device_id (from the MLS session) so the relay can match
    /// disconnects to the right push registration.
    pub async fn register_push(
        &mut self,
        device_id: &str,
        token: &str,
        tags: &[[u8; 16]],
    ) -> Result<(), String> {
        let own = self
            .own
            .as_mut()
            .ok_or("not connected to own Drawbridge")?;

        let tag_strings: Vec<String> = tags.iter().map(|t| hex::encode(t)).collect();
        let msg = serde_json::json!({
            "type": "register_push",
            "device_id": device_id,
            "platform": "moat-cli",
            "token": token,
            "tags": tag_strings,
        });
        own.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send register_push: {e}"))?;

        Ok(())
    }

    /// Send `pair_offer{token}` on the main WS.
    pub async fn send_pair_offer(&mut self, token: &[u8]) -> Result<(), String> {
        let own = self.own.as_mut().ok_or("not connected to own Drawbridge")?;
        let msg = serde_json::json!({
            "type": "pair_offer",
            "token": base64_encode(token),
        });
        own.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send pair_offer: {e}"))
    }

    /// Send `pair_join{token}` on the main WS.
    pub async fn send_pair_join(&mut self, token: &[u8]) -> Result<(), String> {
        let own = self.own.as_mut().ok_or("not connected to own Drawbridge")?;
        let msg = serde_json::json!({
            "type": "pair_join",
            "token": base64_encode(token),
        });
        own.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send pair_join: {e}"))
    }

    /// Connect to the `/pair` WebSocket, send `pair_attach{token}`, and wait for `paired`.
    ///
    /// Once `paired` is received the read loop emits `BgEvent::PairFrameReceived` for
    /// every subsequent binary frame, and `BgEvent::PairClosed` on disconnect.
    pub async fn connect_pair(&mut self, url: &str, token: &[u8]) -> Result<(), String> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| format!("pair WS connect failed: {e}"))?;

        let (mut writer, mut reader) = ws_stream.split();

        // Send pair_attach as the first (only JSON) frame
        let attach = serde_json::json!({
            "type": "pair_attach",
            "token": base64_encode(token),
        });
        writer
            .send(Message::Text(attach.to_string()))
            .await
            .map_err(|e| format!("send pair_attach: {e}"))?;

        // Wait for `paired`
        loop {
            match reader.next().await {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                        match msg.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                            "paired" => break,
                            "error" => {
                                let err = msg.get("message").and_then(|v| v.as_str()).unwrap_or("unknown");
                                return Err(format!("pair_attach rejected: {err}"));
                            }
                            _ => {}
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    return Err("pair WS closed before paired".to_string());
                }
                Some(Err(e)) => return Err(format!("pair WS read error: {e}")),
                _ => {}
            }
        }

        // Spawn binary read loop; store abort handle so clear_pair can stop it.
        let bg_tx = self.bg_tx.clone();
        let task = tokio::spawn(async move {
            pair_read_loop(reader, bg_tx).await;
        });
        self.pair_read_task = Some(task.abort_handle());

        self.pair_writer = Some(writer);
        let _ = self.bg_tx.send(BgEvent::PairConnected);
        Ok(())
    }

    /// Send a binary frame on the pair WS (ring-MLS ciphertext).
    pub async fn send_pair_binary(&mut self, data: Vec<u8>) -> Result<(), String> {
        let writer = self.pair_writer.as_mut().ok_or("no pair WS connected")?;
        writer
            .send(Message::Binary(data.into()))
            .await
            .map_err(|e| format!("send pair binary: {e}"))
    }

    /// Close the pair WS: abort the read-loop task and drop the write half.
    ///
    /// Aborting the read task drops the `SplitStream`, releasing the underlying
    /// TCP socket (combined with dropping the writer).  This causes Drawbridge
    /// to detect the disconnection and send `pair_closed` on the main WS.
    pub fn clear_pair(&mut self) {
        if let Some(handle) = self.pair_read_task.take() {
            handle.abort();
        }
        self.pair_writer = None;
    }

    /// Whether a pair WS is currently open.
    pub fn has_pair_connection(&self) -> bool {
        self.pair_writer.is_some()
    }

    /// Get the number of active connections (for status bar).
    pub fn active_connection_count(&self) -> usize {
        if self.own.is_some() { 1 } else { 0 }
    }

    /// Check if connected to own Drawbridge.
    pub fn has_own_connection(&self) -> bool {
        self.own.is_some()
    }

    /// Mark the connection as dropped (called on disconnect).
    pub fn clear_connection(&mut self) {
        self.own = None;
    }

    /// Get the backoff delay for the next reconnect attempt and increment the counter.
    pub fn next_reconnect_delay(&mut self) -> Duration {
        let delay = backoff_duration(self.reconnect_attempt);
        self.reconnect_attempt = self.reconnect_attempt.saturating_add(1);
        delay
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

/// Read loop for the own Drawbridge connection.
///
/// Handles:
/// - `new_event` with inline payload (from relay-to-relay or local multi-device)
/// - `pair_pending`, `pair_ready`, `pair_closed` pairing control messages
/// - Connection lifecycle (errors, disconnects)
async fn own_read_loop(
    mut reader: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    bg_tx: mpsc::UnboundedSender<BgEvent>,
    url: String,
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
                            let payload = msg
                                .get("payload")
                                .and_then(|v| v.as_str())
                                .and_then(|s| base64_decode(s));

                            if let Ok(tag_bytes) = hex::decode(&tag_hex) {
                                if tag_bytes.len() == 16 {
                                    let mut tag = [0u8; 16];
                                    tag.copy_from_slice(&tag_bytes);
                                    let _ = bg_tx.send(BgEvent::DrawbridgeNewEvent {
                                        tag,
                                        rkey,
                                        payload,
                                    });
                                }
                            }
                        }
                        "pair_pending" => {
                            let _ = bg_tx.send(BgEvent::PairPending);
                        }
                        "pair_ready" => {
                            if let (Some(pair_url), Some(token_b64)) = (
                                msg.get("pair_url").and_then(|v| v.as_str()),
                                msg.get("token").and_then(|v| v.as_str()),
                            ) {
                                if let Some(token) = base64_decode(token_b64) {
                                    let _ = bg_tx.send(BgEvent::PairReady {
                                        pair_url: pair_url.to_string(),
                                        token,
                                    });
                                }
                            }
                        }
                        "pair_closed" => {
                            let reason = msg
                                .get("reason")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let _ = bg_tx.send(BgEvent::PairClosed { reason });
                        }
                        "error" => {
                            let err = msg
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                                url: url.clone(),
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
                    reason: "connection closed".to_string(),
                });
                return;
            }
            Some(Err(e)) => {
                let _ = bg_tx.send(BgEvent::DrawbridgeDisconnected {
                    url: url.clone(),
                    reason: format!("read error: {e}"),
                });
                return;
            }
            _ => continue,
        }
    }
}

/// Read loop for the pair WebSocket. Forwards binary frames as `PairFrameReceived`
/// and signals `PairClosed` on disconnect.
async fn pair_read_loop(
    mut reader: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    bg_tx: mpsc::UnboundedSender<BgEvent>,
) {
    loop {
        match reader.next().await {
            Some(Ok(Message::Binary(data))) => {
                let _ = bg_tx.send(BgEvent::PairFrameReceived { data: data.into() });
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                let _ = bg_tx.send(BgEvent::PairClosed {
                    reason: "connection closed".to_string(),
                });
                return;
            }
            Some(Err(e)) => {
                let _ = bg_tx.send(BgEvent::PairClosed {
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

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drawbridge_state_roundtrip() {
        let state = DrawbridgeState {
            own_url: Some("wss://relay.example.com/ws".to_string()),
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: DrawbridgeState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.own_url, state.own_url);
    }

    #[test]
    fn test_drawbridge_state_default() {
        let state = DrawbridgeState::default();
        assert!(state.own_url.is_none());
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
    fn test_manager_connection_count() {
        let bg_tx = mpsc::unbounded_channel().0;
        let mgr = DrawbridgeManager::new(bg_tx);
        assert_eq!(mgr.active_connection_count(), 0);
        assert!(!mgr.has_own_connection());
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello world";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    /// Verify old DrawbridgeState format (with own_tickets + partner_hints)
    /// deserializes into the new format without error.
    #[test]
    fn test_drawbridge_state_backward_compat() {
        let old_json = r#"{
            "own_url": "wss://relay.example.com/ws",
            "own_tickets": {"group_abc": "ticket_123"},
            "partner_hints": [{"url": "wss://other.com/ws", "device_id_hex": "aa", "ticket_hex": "bb", "partner_did": "did:plc:x", "group_id_hex": "cc"}]
        }"#;
        // serde ignores unknown fields by default
        let parsed: DrawbridgeState = serde_json::from_str(old_json).unwrap();
        assert_eq!(parsed.own_url, Some("wss://relay.example.com/ws".to_string()));
    }
}
