//! Drawbridge WebSocket connection manager.
//!
//! Manages the connection to this device's own Drawbridge, and while a
//! pairing or sync rendezvous is live on another Drawbridge, a second connection
//! to that one. The Drawbridge fans events out to the recipients' Drawbridges via
//! relay-to-relay push.
//!
//! Architecture:
//! - Events and tags go only through the device's own Drawbridge (DID
//!   challenge-response auth); the rendezvous connection carries only
//!   `pair_offer` / `pair_join` and their replies
//! - On send: client sends envelope with payload + the Drawbridges to notify
//! - On receive: Drawbridge delivers `new_event` with inline payload for instant decryption
//! - Drawbridge discovery: each device publishes its own `social.moat.drawbridgeConfig`
//!   record, keyed by its device id

use crate::app::BgEvent;
use crate::keystore::hex;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

type WsWriter =
    futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>;

type PairWsWriter =
    futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>;

/// Manages the connections to Drawbridges: the device's own, and the
/// rendezvous connection to another Drawbridge while one is live there.
///
/// Architecture:
/// - Field on App struct (not a standalone service)
/// - WebSocket read loop runs as a tokio::spawn task
/// - Notifications flow back through the existing BgEvent channel
/// - Write operations go through the stored write-half of the WebSocket split
pub struct DrawbridgeManager {
    /// Our own Drawbridge connection (DID-authenticated)
    own: Option<DrawbridgeConnection>,

    /// A second, DID-authenticated connection to another Drawbridge, held only
    /// while a rendezvous is live there: pairing or sync with a device that
    /// sits on that Drawbridge. Never used for events or tags.
    rendezvous: Option<DrawbridgeConnection>,

    /// Channel for sending BgEvents back to the main App loop
    bg_tx: mpsc::UnboundedSender<BgEvent>,

    /// Number of consecutive reconnect attempts (reset on successful connect)
    reconnect_attempt: u32,

    /// Write half of the active pair WebSocket, if one is open.
    pair_writer: Option<PairWsWriter>,

    /// Session token the open pair WebSocket attached with.
    pair_token: Option<Vec<u8>>,

    /// Abort handle for the pair_read_loop task.  Aborting it drops the read
    /// half of the pair WS, so the TCP connection is fully closed and Drawbridge
    /// detects the peer disconnect (sends `pair_closed` on the main WS).
    pair_read_task: Option<tokio::task::AbortHandle>,
}

/// An authenticated main-WS connection to one Drawbridge: our own, or the
/// one held for a rendezvous.
struct DrawbridgeConnection {
    writer: WsWriter,
    /// Aborting closes the socket without the read loop reporting a disconnect.
    read_task: tokio::task::AbortHandle,
    /// The relay this connection is to.
    url: String,
}

/// A user's relays, as last read from their `social.moat.drawbridgeConfig` records.
#[derive(Debug, Clone)]
pub struct CachedDrawbridgeConfig {
    /// One URL per distinct relay the user's devices sit on
    pub urls: Vec<String>,
    /// When the records were read
    pub fetched_at: Instant,
}

/// How long a user's relay list is trusted before a poll re-reads it.
pub const DRAWBRIDGE_CONFIG_TTL: Duration = Duration::from_secs(30);

/// In-memory cache of partner Drawbridge configs (DID -> URLs).
/// Not persisted — refetched on login.
pub type DrawbridgeConfigCache = HashMap<String, CachedDrawbridgeConfig>;

/// How long a closing pair WS waits for its end to be confirmed: our own
/// close for the peer's reply, a relay `pair_closed` for the socket to end.
pub const PAIR_CLOSE_GRACE: Duration = Duration::from_secs(5);

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
            rendezvous: None,
            bg_tx,
            reconnect_attempt: 0,
            pair_writer: None,
            pair_token: None,
            pair_read_task: None,
        }
    }

    /// Connect to our own Drawbridge (DID challenge-response).
    pub async fn connect_own(
        &mut self,
        url: &str,
        did: &str,
        identity_key_bundle: &[u8],
    ) -> Result<(), String> {
        // Replace an existing connection rather than duplicate it.
        self.close_own();

        let (writer, reader) = authenticate(url, did, identity_key_bundle).await?;

        let bg_tx = self.bg_tx.clone();
        let url_clone = url.to_string();
        let read_task = tokio::spawn(async move {
            read_loop(reader, bg_tx, url_clone, Role::Own).await;
        })
        .abort_handle();

        self.own = Some(DrawbridgeConnection {
            writer,
            read_task,
            url: url.to_string(),
        });
        self.reconnect_attempt = 0;

        Ok(())
    }

    /// Connect to another Drawbridge, for a rendezvous there. The connection is
    /// authenticated like our own but carries only `pair_offer` / `pair_join`
    /// and their replies. Replaces any earlier rendezvous connection.
    pub async fn connect_rendezvous(
        &mut self,
        url: &str,
        did: &str,
        identity_key_bundle: &[u8],
    ) -> Result<(), String> {
        self.close_rendezvous();

        let (writer, reader) = authenticate(url, did, identity_key_bundle).await?;

        let bg_tx = self.bg_tx.clone();
        let url_clone = url.to_string();
        let read_task = tokio::spawn(async move {
            read_loop(reader, bg_tx, url_clone, Role::Rendezvous).await;
        })
        .abort_handle();

        self.rendezvous = Some(DrawbridgeConnection {
            writer,
            read_task,
            url: url.to_string(),
        });
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
    /// The Drawbridge routes inbound relay-to-relay events to clients watching
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

    /// Send `pair_offer{token}` to `drawbridge_url`. Called by the device that
    /// opened the rendezvous.
    pub async fn send_pair_offer(&mut self, drawbridge_url: &str, token: &[u8]) -> Result<(), String> {
        self.send_rendezvous_msg(drawbridge_url, "pair_offer", token).await
    }

    /// Send `pair_join{token}` to `drawbridge_url`. Called by the device joining a
    /// rendezvous opened elsewhere.
    pub async fn send_pair_join(&mut self, drawbridge_url: &str, token: &[u8]) -> Result<(), String> {
        self.send_rendezvous_msg(drawbridge_url, "pair_join", token).await
    }

    async fn send_rendezvous_msg(
        &mut self,
        drawbridge_url: &str,
        kind: &str,
        token: &[u8],
    ) -> Result<(), String> {
        let conn = self
            .connection_to(drawbridge_url)
            .ok_or_else(|| format!("not connected to {drawbridge_url}"))?;
        let msg = serde_json::json!({
            "type": kind,
            "token": base64_encode(token),
        });
        conn.writer
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send {kind}: {e}"))
    }

    /// The authenticated connection to `drawbridge_url`: our own if it is our
    /// Drawbridge, else the rendezvous connection.
    fn connection_to(&mut self, drawbridge_url: &str) -> Option<&mut DrawbridgeConnection> {
        if self.own.as_ref().is_some_and(|c| same_drawbridge(&c.url, drawbridge_url)) {
            self.own.as_mut()
        } else {
            self.rendezvous
                .as_mut()
                .filter(|c| same_drawbridge(&c.url, drawbridge_url))
        }
    }

    /// Whether an authenticated connection to `drawbridge_url` is open, own or
    /// rendezvous.
    pub fn is_connected_to_drawbridge(&self, drawbridge_url: &str) -> bool {
        self.own.as_ref().is_some_and(|c| same_drawbridge(&c.url, drawbridge_url))
            || self.rendezvous.as_ref().is_some_and(|c| same_drawbridge(&c.url, drawbridge_url))
    }

    /// Whether `drawbridge_url` is the one this device's own connection is to.
    pub fn is_own_drawbridge_url(&self, drawbridge_url: &str) -> bool {
        self.own.as_ref().is_some_and(|c| same_drawbridge(&c.url, drawbridge_url))
    }

    /// Forget a rendezvous connection that dropped.
    pub fn clear_rendezvous(&mut self) {
        self.rendezvous = None;
    }

    /// Close the rendezvous connection, if one is open.
    pub fn close_rendezvous(&mut self) {
        if let Some(conn) = self.rendezvous.take() {
            conn.read_task.abort();
        }
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
        let session_token = token.to_vec();
        let task = tokio::spawn(async move {
            pair_read_loop(reader, bg_tx, session_token).await;
        });
        self.pair_read_task = Some(task.abort_handle());

        self.pair_writer = Some(writer);
        self.pair_token = Some(token.to_vec());
        let _ = self.bg_tx.send(BgEvent::PairConnected { session_token: token.to_vec() });
        Ok(())
    }

    /// Send a binary frame on the pair WS.
    pub async fn send_pair_binary(&mut self, data: Vec<u8>) -> Result<(), String> {
        let writer = self.pair_writer.as_mut().ok_or("no pair WS connected")?;
        writer
            .send(Message::Binary(data))
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
        self.pair_token = None;
    }

    /// Close the pair WS with a close handshake, after everything already
    /// written. The read loop is left to see the peer's reply, so frames
    /// the peer sent before closing are still delivered; it is aborted if
    /// no reply comes.
    pub async fn close_pair(&mut self) {
        self.pair_token = None;
        if let Some(mut writer) = self.pair_writer.take() {
            let _ = writer.close().await;
        }
        if let Some(handle) = self.pair_read_task.take() {
            tokio::spawn(async move {
                tokio::time::sleep(PAIR_CLOSE_GRACE).await;
                handle.abort();
            });
        }
    }

    /// Whether the pair WS for `token` is open; `None` matches any.
    pub fn has_pair_socket(&self, token: Option<&[u8]>) -> bool {
        self.pair_writer.is_some()
            && token.map_or(true, |t| self.pair_token.as_deref() == Some(t))
    }

    /// Get the number of active event connections (for status bar): 1 when
    /// connected to our own Drawbridge. The rendezvous connection is not counted.
    pub fn active_connection_count(&self) -> usize {
        if self.own.is_some() { 1 } else { 0 }
    }

    /// Check if connected to own Drawbridge.
    pub fn has_own_connection(&self) -> bool {
        self.own.is_some()
    }

    /// Whether this device is connected to its own relay at [url].
    pub fn is_connected_to(&self, url: &str) -> bool {
        self.own.as_ref().is_some_and(|own| own.url == url)
    }

    /// Mark the connection as dropped (called on disconnect).
    pub fn clear_connection(&mut self) {
        self.own = None;
    }

    /// Close the connection to our own relay, if one is open.
    fn close_own(&mut self) {
        if let Some(own) = self.own.take() {
            own.read_task.abort();
        }
    }

    /// Get the backoff delay for the next reconnect attempt and increment the counter.
    pub fn next_reconnect_delay(&mut self) -> Duration {
        let delay = backoff_duration(self.reconnect_attempt);
        self.reconnect_attempt = self.reconnect_attempt.saturating_add(1);
        delay
    }
}

/// Which of the two main-WS connections a read loop serves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Own,
    Rendezvous,
}

/// Whether two spellings name one Drawbridge.
fn same_drawbridge(a: &str, b: &str) -> bool {
    match (moat_core::normalize_drawbridge_url(a), moat_core::normalize_drawbridge_url(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

type WsReader = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// Open a main WS to `url` and authenticate as `did` (challenge-response).
///
/// 1. WebSocket connect
/// 2. Send request_challenge
/// 3. Receive challenge{nonce}
/// 4. Sign with Ed25519 identity key
/// 5. Send challenge_response{did, signature, timestamp, public_key}
/// 6. Receive authenticated
async fn authenticate(
    url: &str,
    did: &str,
    identity_key_bundle: &[u8],
) -> Result<(WsWriter, WsReader), String> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {e}"))?;

    let (mut writer, mut reader) = ws_stream.split();

    let req = serde_json::json!({"type": "request_challenge"});
    writer
        .send(Message::Text(req.to_string()))
        .await
        .map_err(|e| format!("send request_challenge: {e}"))?;

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

    // Sign: nonce + "\n" + drawbridge_url + "\n" + timestamp + "\n"
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let message_bytes = format!("{}\n{}\n{}\n", nonce, url, timestamp);
    let (sig_bytes, pub_bytes) =
        moat_core::MoatSession::sign_drawbridge_challenge(identity_key_bundle, message_bytes.as_bytes())
            .map_err(|e| format!("signing failed: {e}"))?;
    let resp = serde_json::json!({
        "type": "challenge_response",
        "did": did,
        "signature": base64_encode(&sig_bytes),
        "timestamp": timestamp,
        "public_key": base64_encode(&pub_bytes),
    });
    writer
        .send(Message::Text(resp.to_string()))
        .await
        .map_err(|e| format!("send challenge_response: {e}"))?;

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

    Ok((writer, reader))
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

/// Read loop for a main-WS connection: our own Drawbridge's, or the rendezvous
/// connection to another.
///
/// Handles:
/// - `new_event` with inline payload (from relay-to-relay or local multi-device)
/// - `pair_pending`, `pair_ready`, `pair_closed` pairing control messages
/// - Connection lifecycle (errors, disconnects)
async fn read_loop(
    mut reader: WsReader,
    bg_tx: mpsc::UnboundedSender<BgEvent>,
    url: String,
    role: Role,
) {
    let disconnected = |reason: String| match role {
        Role::Own => BgEvent::DrawbridgeDisconnected { url: url.clone(), reason },
        Role::Rendezvous => BgEvent::RendezvousDisconnected { url: url.clone(), reason },
    };
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
                                .and_then(base64_decode);

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
                                        drawbridge_url: url.clone(),
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
                            let session_token = msg
                                .get("token")
                                .and_then(|v| v.as_str())
                                .and_then(base64_decode);
                            let _ = bg_tx.send(BgEvent::PairClosed {
                                session_token,
                                reason,
                                via_drawbridge: true,
                            });
                        }
                        "error" => {
                            let err = msg
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let _ = bg_tx.send(disconnected(format!("server error: {err}")));
                        }
                        _ => {}
                    }
                }
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                let _ = bg_tx.send(disconnected("connection closed".to_string()));
                return;
            }
            Some(Err(e)) => {
                let _ = bg_tx.send(disconnected(format!("read error: {e}")));
                return;
            }
            _ => continue,
        }
    }
}

/// Read loop for the pair WebSocket. Forwards binary frames as `PairFrameReceived`
/// and signals `PairClosed` on disconnect.
///
/// `clear_pair()` aborts this task, but not instantaneously: an
/// already-observed frame or close can still be queued after the session
/// is superseded, hence `session_token`.
async fn pair_read_loop(
    mut reader: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    bg_tx: mpsc::UnboundedSender<BgEvent>,
    session_token: Vec<u8>,
) {
    loop {
        match reader.next().await {
            Some(Ok(Message::Binary(data))) => {
                let _ = bg_tx.send(BgEvent::PairFrameReceived {
                    session_token: session_token.clone(),
                    data,
                });
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => {
                let _ = bg_tx.send(BgEvent::PairClosed {
                    session_token: Some(session_token),
                    reason: "connection closed".to_string(),
                    via_drawbridge: false,
                });
                return;
            }
            Some(Err(e)) => {
                let _ = bg_tx.send(BgEvent::PairClosed {
                    session_token: Some(session_token),
                    reason: format!("read error: {e}"),
                    via_drawbridge: false,
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
    fn a_manager_with_no_connection_is_connected_to_nothing() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mgr = DrawbridgeManager::new(tx);
        assert!(!mgr.is_connected_to("wss://relay.example.com/ws"));
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
}
