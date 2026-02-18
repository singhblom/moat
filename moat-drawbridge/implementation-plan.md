# Drawbridge Federation Implementation Plan

This document details the implementation steps for the federated Drawbridge model described in `drawbridge-plan.md`.

## Overview

The implementation spans four components:

| Component | Language | Changes |
|-----------|----------|---------|
| moat-drawbridge | Go | Ticket auth, new messages, dual auth modes |
| moat-core | Rust | `DrawbridgeHint` event kind |
| moat-cli | Rust | Multi-Drawbridge connection management |
| moat-flutter | Dart/Rust | Same as CLI, plus FFI bindings |

## Phase 1: Protocol Messages (moat-drawbridge)

### 1.1 New Message Types

Add to `messages.go`:

```go
// Client -> Server: Request a challenge for DID authentication
type RequestChallengeMsg struct {
    Type string `json:"type"` // "request_challenge"
}

// Client -> Server: Recipient authenticates with ticket
type TicketAuthMsg struct {
    Type   string `json:"type"`   // "ticket_auth"
    Ticket string `json:"ticket"` // 32 bytes, hex-encoded
}

// Client -> Server: Sender registers a new ticket
type RegisterTicketMsg struct {
    Type   string `json:"type"`   // "register_ticket"
    Ticket string `json:"ticket"` // 32 bytes, hex-encoded
}

// Client -> Server: Sender revokes a ticket
type RevokeTicketMsg struct {
    Type   string `json:"type"`   // "revoke_ticket"
    Ticket string `json:"ticket"` // 32 bytes, hex-encoded
}

// Server -> Client: Ticket auth succeeded
type TicketAuthenticatedMsg struct {
    Type string `json:"type"` // "ticket_authenticated"
}
```

Update `parseMessage()` to handle new types.

### 1.2 Client Auth State

Modify `Client` struct in `conn.go`:

```go
type Client struct {
    // ... existing fields ...

    // Authentication state (exactly one will be set after auth)
    did    string // set if authenticated via DID challenge-response
    ticket string // set if authenticated via ticket

    // Auth mode determines allowed operations
    authMode AuthMode // AuthModeSender or AuthModeRecipient
}

type AuthMode int

const (
    AuthModeNone AuthMode = iota
    AuthModeSender    // DID-authenticated, can event_posted + register/revoke tickets
    AuthModeRecipient // Ticket-authenticated, can watch_tags + register_push
)
```

### 1.3 Ticket Storage

Add to `relay.go`:

```go
type Relay struct {
    // ... existing fields ...

    // Ticket registry: maps ticket -> owner DID
    // Only the owner (sender) can register/revoke
    ticketsMu sync.RWMutex
    tickets   map[string]string // ticket (hex) -> owner DID
}
```

**Persistence consideration:** For MVP, tickets are in-memory and lost on restart. Alice would need to re-register tickets after Drawbridge restart. Future: persist to disk or external store.

### 1.4 Auth Flow Changes

The authentication is client-initiated. The server does NOT send a challenge on connect.
Instead, the client sends either `request_challenge` (for sender/DID auth) or `ticket_auth` (for recipient auth).

Modify `readPump()` to NOT send challenge automatically. Modify `handlePreAuth()`:

```go
func (c *Client) handlePreAuth(msgType string, msg any) {
    switch msgType {
    case "request_challenge":
        // Generate and send challenge for DID authentication
        c.nonce = generateNonce()
        c.challengeSent = true
        c.sendMsg(ChallengeMsg{Type: "challenge", Nonce: c.nonce})

    case "challenge_response":
        // Requires challenge to have been sent first
        if !c.challengeSent {
            c.sendMsg(ErrorMsg{Type: "error", Message: "must request challenge first"})
            return
        }
        // ... verify signature, set authMode = AuthModeSender

    case "ticket_auth":
        // Ticket auth flow -> sets authMode = AuthModeRecipient
        resp, ok := msg.(*TicketAuthMsg)
        if !ok {
            c.sendMsg(ErrorMsg{Type: "error", Message: "invalid ticket_auth"})
            return
        }
        if err := c.relay.authenticateTicket(c, resp.Ticket); err != nil {
            c.sendMsg(ErrorMsg{Type: "error", Message: err.Error()})
            return
        }
        c.authed = true
        c.authMode = AuthModeRecipient
        c.sendMsg(TicketAuthenticatedMsg{Type: "ticket_authenticated"})

    default:
        c.sendMsg(ErrorMsg{Type: "error", Message: "must authenticate with request_challenge or ticket_auth"})
    }
}
```

### 1.5 Operation Authorization

Modify `handlePostAuth()` in `conn.go`:

```go
func (c *Client) handlePostAuth(msgType string, msg any) {
    switch msgType {
    case "watch_tags", "update_tags", "register_push":
        // Allowed for both senders and recipients
        // (Senders might watch their own tags for multi-device sync)
        // ... existing handling ...

    case "event_posted":
        // Only allowed for senders (DID-authenticated)
        if c.authMode != AuthModeSender {
            c.sendMsg(ErrorMsg{Type: "error", Message: "event_posted requires DID authentication"})
            return
        }
        // ... existing handling ...

    case "register_ticket":
        if c.authMode != AuthModeSender {
            c.sendMsg(ErrorMsg{Type: "error", Message: "register_ticket requires DID authentication"})
            return
        }
        if m, ok := msg.(*RegisterTicketMsg); ok {
            c.relay.handleRegisterTicket(c, m)
        }

    case "revoke_ticket":
        if c.authMode != AuthModeSender {
            c.sendMsg(ErrorMsg{Type: "error", Message: "revoke_ticket requires DID authentication"})
            return
        }
        if m, ok := msg.(*RevokeTicketMsg); ok {
            c.relay.handleRevokeTicket(c, m)
        }

    default:
        c.sendMsg(ErrorMsg{Type: "error", Message: "unknown message type"})
    }
}
```

### 1.6 Ticket Management Handlers

Add to `relay.go`:

```go
func (r *Relay) authenticateTicket(c *Client, ticket string) error {
    r.ticketsMu.RLock()
    _, exists := r.tickets[ticket]
    r.ticketsMu.RUnlock()

    if !exists {
        return fmt.Errorf("invalid ticket")
    }

    c.ticket = ticket
    return nil
}

func (r *Relay) handleRegisterTicket(c *Client, msg *RegisterTicketMsg) {
    r.ticketsMu.Lock()
    defer r.ticketsMu.Unlock()

    // Check if ticket already exists
    if owner, exists := r.tickets[msg.Ticket]; exists {
        if owner != c.did {
            c.sendMsg(ErrorMsg{Type: "error", Message: "ticket already registered by another user"})
            return
        }
        // Re-registering own ticket is a no-op
    }

    r.tickets[msg.Ticket] = c.did
    r.log.Info("ticket registered", "did", c.did, "ticket_prefix", msg.Ticket[:8])
    c.sendMsg(map[string]string{"type": "ticket_registered"})
}

func (r *Relay) handleRevokeTicket(c *Client, msg *RevokeTicketMsg) {
    r.ticketsMu.Lock()
    defer r.ticketsMu.Unlock()

    owner, exists := r.tickets[msg.Ticket]
    if !exists {
        c.sendMsg(ErrorMsg{Type: "error", Message: "ticket not found"})
        return
    }
    if owner != c.did {
        c.sendMsg(ErrorMsg{Type: "error", Message: "not your ticket"})
        return
    }

    delete(r.tickets, msg.Ticket)
    r.log.Info("ticket revoked", "did", c.did, "ticket_prefix", msg.Ticket[:8])

    // Optionally: disconnect all clients using this ticket
    // For now, let them stay connected but they can't reconnect

    c.sendMsg(map[string]string{"type": "ticket_revoked"})
}
```

### 1.7 Rate Limiting Changes

Modify `RateLimiter` in `verify.go` to support per-ticket limits:

```go
type RateLimiter struct {
    mu       sync.Mutex
    failures map[string]*rateLimitEntry // key is DID or ticket
}

// In handleEventPosted, use c.did for rate limit key (senders only)
// Recipients don't send event_posted, so no change needed there
```

### 1.8 Disconnect Buffer Changes

The disconnect buffer currently keys by DID. For recipients (ticket-auth), we don't have a DID. Options:

**Option A:** Buffer by ticket instead of DID for recipients
```go
type DisconnectBuffer struct {
    key       string    // DID for senders, ticket for recipients
    messages  []NewEventMsg
    expiresAt time.Time
}
```

**Option B:** Don't buffer for recipients (they'll re-poll on reconnect)

Recommend **Option B** for simplicity. Senders need buffering because they might miss notifications about their own messages being acknowledged. Recipients can just poll the PDS.

---

## Phase 2: DrawbridgeHint Event (moat-core)

### 2.1 Event Kind

Add to `event.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    // ... existing variants ...

    /// Hint for conversation partners about which Drawbridge to use
    DrawbridgeHint {
        /// WebSocket URL of the Drawbridge
        url: String,
        /// Which device this hint applies to
        device_id: Vec<u8>,
        /// Ticket for recipient authentication (32 bytes)
        ticket: Vec<u8>,
    },
}
```

### 2.2 Helper Methods

Add to `MoatSession`:

```rust
impl MoatSession {
    /// Generate a random ticket for Drawbridge recipient auth.
    pub fn generate_drawbridge_ticket() -> [u8; 32] {
        let mut ticket = [0u8; 32];
        getrandom::getrandom(&mut ticket).expect("getrandom failed");
        ticket
    }

    /// Create a DrawbridgeHint event for the current device.
    pub fn create_drawbridge_hint(
        &self,
        group_id: &[u8],
        url: &str,
        ticket: &[u8; 32],
    ) -> Event {
        Event {
            kind: EventKind::DrawbridgeHint {
                url: url.to_string(),
                device_id: self.device_id.to_vec(),
                ticket: ticket.to_vec(),
            },
            group_id: group_id.to_vec(),
            epoch: 0, // Will be set during encryption
            payload: None,
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        }
    }
}
```

### 2.3 Tests

Add to `event.rs` tests:

```rust
#[test]
fn test_drawbridge_hint_roundtrip() {
    let event = Event {
        kind: EventKind::DrawbridgeHint {
            url: "wss://relay.example.com".to_string(),
            device_id: vec![1, 2, 3, 4],
            ticket: vec![0u8; 32],
        },
        group_id: b"test-group".to_vec(),
        epoch: 5,
        payload: None,
        message_id: None,
        prev_event_hash: None,
        epoch_fingerprint: None,
        sender_device_id: None,
    };

    let json = serde_json::to_string(&event).unwrap();
    let parsed: Event = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}
```

---

## Phase 3: CLI Multi-Drawbridge Support (moat-cli + moat-drawbridge)

Phase 3 adds full Drawbridge WebSocket support to the CLI: connecting to your own Drawbridge as a sender (DID-authenticated, `event_posted` + ticket management), and connecting to partners' Drawbridges as a recipient (ticket-authenticated, `watch_tags` + `new_event` notifications). It also includes a Drawbridge server auth change to verify signatures against MLS key packages.

**Key design decisions:**
- **Per-device tickets**: Each device generates its own ticket independently. One connection per (URL, ticket) pair. Avoids cross-device ticket coordination.
- **One connection per ticket**: A single WebSocket per (URL, ticket). Future optimization: multi-ticket per connection via an `add_ticket` message (noted but not implemented here — would slightly degrade privacy since the Drawbridge could correlate tickets on the same connection).
- **Immediate targeted fetch**: On `new_event`, fetch from the sender's PDS using the existing `fetch_events_from_did` cursor (not single-rkey fetch). Catches any events posted since last cursor.
- **Reduced polling**: Background poll interval increases from 5s to 30s when Drawbridge connections are active.
- **Self-sync deferred**: Multi-device sync via Drawbridge (watching your own other devices) is deferred to a later phase. Polling handles it for now.
- **tokio-tungstenite**: WebSocket library for async compatibility with existing Tokio runtime.

### 3.1 Drawbridge Server Auth Change (moat-drawbridge)

Replace DID document verification with MLS key package verification for sender authentication.

#### 3.1.1 Protocol Change

Extend `challenge_response` to include the Ed25519 public key:

```go
// Updated in messages.go
type ChallengeResponseMsg struct {
    Type      string `json:"type"`       // "challenge_response"
    DID       string `json:"did"`
    Signature string `json:"signature"`  // base64
    Timestamp int64  `json:"timestamp"`
    PublicKey string `json:"public_key"` // base64 Ed25519 public key (NEW)
}
```

#### 3.1.2 Auth Flow

1. Client sends `request_challenge`
2. Server sends `challenge{nonce}`
3. Client signs `nonce + "\n" + relay_url + "\n" + timestamp + "\n"` with MLS identity key (Ed25519)
4. Client sends `challenge_response{did, signature, timestamp, public_key}`
5. Server verifies signature against the provided public key (fast, local)
6. Server sends `authenticated` immediately
7. Server async-verifies the public key exists in the DID's `social.moat.keyPackage` PDS records (same pattern as existing async PDS verification for `event_posted`)

#### 3.1.3 Key Package Verification (Go)

Add to `verify.go` or new `key_verify.go`:

```go
func (r *Relay) asyncVerifyKeyPackage(did string, claimedPubKey []byte) {
    // 1. Resolve DID -> PDS endpoint (reuse existing DID resolution)
    // 2. Fetch com.atproto.repo.listRecords for social.moat.keyPackage
    // 3. For each key package record, search for the claimedPubKey bytes
    //    within the serialized key package blob (byte substring search)
    // 4. If found in any key package: verification passes
    // 5. If not found: apply soft rate limit (same as event_posted verification failure)
}
```

The Ed25519 public key is 32 bytes and appears as a raw substring in the serialized MLS key package. No MLS parsing library needed — a byte-level search suffices.

#### 3.1.4 Remove Old Auth

Remove the DID document `#atproto` verification method lookup from `auth.go`. The only verification path is now key package-based.

### 3.2 CLI Drawbridge Module

Add new dependency to `crates/moat-cli/Cargo.toml`:

```toml
tokio-tungstenite = { version = "0.21", features = ["native-tls"] }
futures-util = "0.3"
```

Add new module `src/drawbridge.rs`:

```rust
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Manages connections to multiple Drawbridges.
///
/// Architecture:
/// - Field on App struct (not a standalone service)
/// - WebSocket read loops run as tokio::spawn tasks
/// - Notifications flow back through the existing BgEvent channel
/// - Write operations (event_posted, watch_tags, etc.) go through
///   stored write-halves of the WebSocket splits
pub struct DrawbridgeManager {
    /// Our own Drawbridge (sender mode, DID-authenticated)
    own: Option<OwnDrawbridge>,

    /// Partner Drawbridges (recipient mode, ticket-authenticated)
    /// Key: (URL, ticket_hex) — one connection per (URL, ticket) pair
    /// Note: a future optimization could multiplex tickets on a single
    /// connection via an `add_ticket` protocol message. This would reduce
    /// connection count but slightly degrade privacy, since the Drawbridge
    /// operator could correlate which tickets belong to the same recipient.
    partners: HashMap<(String, String), PartnerDrawbridge>,

    /// Received hints: (DID, device_id_hex) -> hint
    /// Used to look up which partner Drawbridge to contact for a given sender device
    hints: HashMap<(String, String), StoredHint>,

    /// Channel for sending BgEvents back to the main App loop
    bg_tx: mpsc::UnboundedSender<BgEvent>,
}

struct OwnDrawbridge {
    url: String,
    /// Write half of the WebSocket (read half runs in a spawned task)
    writer: SplitSink<WebSocketStream, Message>,
    /// Tickets registered on this Drawbridge: ticket_hex -> group_id_hex
    registered_tickets: HashMap<String, String>,
}

struct PartnerDrawbridge {
    url: String,
    ticket: [u8; 32],
    /// Write half of the WebSocket
    writer: SplitSink<WebSocketStream, Message>,
    /// Which (DID, device_id_hex) pair this connection is for
    partner_did: String,
    partner_device_id: [u8; 16],
    /// Tags currently being watched on this connection
    watching_tags: Vec<[u8; 16]>,
    /// Connection state for reconnect
    state: ConnectionState,
}

enum ConnectionState {
    Connected,
    Reconnecting { attempt: u32, next_retry: Instant },
    Failed,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredHint {
    pub url: String,
    pub device_id_hex: String,
    pub ticket_hex: String,
    pub partner_did: String,
    pub group_id_hex: String,
}
```

### 3.3 Connection Lifecycle

```rust
impl DrawbridgeManager {
    /// Connect to our own Drawbridge as sender (DID challenge-response).
    ///
    /// Called after login if a Drawbridge URL is configured.
    /// 1. WebSocket connect to url
    /// 2. Send request_challenge
    /// 3. Receive challenge{nonce}
    /// 4. Sign: nonce + "\n" + url + "\n" + timestamp + "\n" with MLS identity key
    /// 5. Send challenge_response{did, signature, timestamp, public_key}
    /// 6. Receive authenticated
    /// 7. Split WebSocket: spawn read loop (sends BgEvents), store write half
    /// 8. Re-register all persisted tickets
    pub async fn connect_own(
        &mut self,
        url: &str,
        did: &str,
        identity_key: &[u8], // Ed25519 private key from KeyBundle
    ) -> Result<()>

    /// Connect to a partner's Drawbridge as recipient (ticket auth).
    ///
    /// Called when a DrawbridgeHint is received or on startup from persisted hints.
    /// 1. WebSocket connect to url
    /// 2. Send ticket_auth{ticket}
    /// 3. Receive ticket_authenticated
    /// 4. Split WebSocket: spawn read loop, store write half
    /// 5. Send watch_tags with relevant tags for this partner's device
    ///
    /// On connection failure: silent retry with exponential backoff
    /// (5s, 10s, 30s, 60s, max 5min). Continue polling PDS as fallback.
    /// No UI error unless persistent failure.
    async fn connect_partner(&mut self, hint: &StoredHint) -> Result<()>

    /// Handle incoming DrawbridgeHint from a decrypted MLS event.
    ///
    /// Stores the hint, connects to the partner's Drawbridge if not
    /// already connected, and registers tags for that partner device.
    pub async fn handle_hint(
        &mut self,
        partner_did: &str,
        device_id: &[u8; 16],
        url: &str,
        ticket: &[u8; 32],
        group_id: &str,
    ) -> Result<()>

    /// Register a ticket on our own Drawbridge.
    /// Called after creating a conversation or on reconnect.
    pub async fn register_ticket(&mut self, ticket: &[u8; 32], group_id: &str) -> Result<()>

    /// Send event_posted on our own Drawbridge.
    /// Called from the publish background task after PDS publish succeeds.
    pub async fn notify_event_posted(&mut self, tag: &[u8; 16], rkey: &str) -> Result<()>

    /// Update watched tags for a specific partner Drawbridge connection.
    /// Called after populate_candidate_tags when epoch changes.
    /// Sends the full set of relevant tags via watch_tags (replace, not incremental).
    pub async fn update_tags_for_partner(
        &mut self,
        partner_did: &str,
        device_id: &[u8; 16],
        tags: &[[u8; 16]],
    ) -> Result<()>

    /// Reconnect logic for disconnected partner Drawbridges.
    /// Called periodically from tick(). Retries with exponential backoff.
    pub async fn retry_disconnected(&mut self) -> Result<()>

    /// Get the number of active connections (for status bar).
    pub fn active_connection_count(&self) -> usize
}
```

### 3.4 BgEvent Extensions

Add new variants to `BgEvent` in `app.rs`:

```rust
pub(crate) enum BgEvent {
    // ... existing variants ...

    /// Drawbridge new_event notification received from a partner's Drawbridge.
    DrawbridgeNewEvent {
        tag: [u8; 16],
        rkey: String,
        did: String,
    },

    /// A partner Drawbridge connection was lost.
    DrawbridgeDisconnected {
        url: String,
        ticket_hex: String,
        reason: String,
    },

    /// A partner Drawbridge connection was (re)established.
    DrawbridgeConnected {
        url: String,
        ticket_hex: String,
    },
}
```

### 3.5 Integration with App

Modify `src/app.rs`:

```rust
pub struct App {
    // ... existing fields ...

    /// Drawbridge connection manager
    drawbridge: DrawbridgeManager,

    /// Drawbridge URL for this device (persisted via --drawbridge-url flag)
    drawbridge_url: Option<String>,
}
```

#### 3.5.1 Handling DrawbridgeHint Events

In `process_poll_results`, when decrypting an event with `EventKind::Control(ControlKind::DrawbridgeHint)`:

```rust
ControlKind::DrawbridgeHint => {
    if let Some(payload) = event.drawbridge_hint_payload() {
        self.drawbridge.handle_hint(
            &sender_did,
            &payload.device_id.try_into().unwrap(),
            &payload.url,
            &payload.ticket.try_into().unwrap(),
            &conv_id,
        ).await.ok();
        self.save_drawbridge_state();
    }
}
```

#### 3.5.2 Auto-Send DrawbridgeHint on Conversation Creation

In `start_new_conversation`, after publishing the Welcome:

```rust
// 10. If Drawbridge is configured, send DrawbridgeHint to the new conversation
if let Some(ref url) = self.drawbridge_url {
    let ticket = MoatSession::generate_drawbridge_ticket();

    // Register ticket on our own Drawbridge
    self.drawbridge.register_ticket(&ticket, &conv_id).await?;

    // Create and encrypt the hint
    let hint_event = self.mls.create_drawbridge_hint(&group_id, url, &ticket)?;
    let encrypted = self.mls.encrypt_event(&group_id, &key_bundle, &hint_event)?;
    self.save_mls_state()?;
    self.keys.store_group_state(&conv_id, &encrypted.new_group_state)?;

    // Publish the hint
    self.client.as_ref().unwrap()
        .publish_event(&encrypted.tag, &encrypted.ciphertext).await?;

    self.save_drawbridge_state();
}
```

#### 3.5.3 Handling new_event Notifications

In `handle_bg_event`:

```rust
BgEvent::DrawbridgeNewEvent { tag, rkey, did } => {
    self.debug_log.log(&format!(
        "drawbridge: new_event tag={:02x?} rkey={} did={}",
        &tag[..4], &rkey, &did[..20]
    ));
    // Trigger an immediate fetch from this DID using existing cursor
    // (fetch_events_from_did with last_rkey, same as poll but targeted)
    self.spawn_targeted_fetch(&did);
}

BgEvent::DrawbridgeDisconnected { url, ticket_hex, reason } => {
    self.debug_log.log(&format!(
        "drawbridge: disconnected from {} (ticket {}...): {}",
        url, &ticket_hex[..8], reason
    ));
}

BgEvent::DrawbridgeConnected { url, ticket_hex } => {
    self.debug_log.log(&format!(
        "drawbridge: connected to {} (ticket {}...)",
        url, &ticket_hex[..8]
    ));
}
```

#### 3.5.4 event_posted After Publishing

In the `tokio::spawn` task within `send_message_nonblocking`, after `publish_event` succeeds:

```rust
tokio::spawn(async move {
    match client.publish_event(&tag, &ciphertext).await {
        Ok(uri) => {
            // Extract rkey from URI (format: at://did/collection/rkey)
            let rkey = uri.split('/').last().unwrap_or("").to_string();

            // Notify Drawbridge immediately (lowest latency)
            if let Some(ref mut own) = drawbridge_writer {
                let msg = serde_json::json!({
                    "type": "event_posted",
                    "tag": hex::encode(&tag),
                    "rkey": &rkey,
                });
                let _ = own.send(Message::Text(msg.to_string())).await;
            }

            let _ = tx.send(BgEvent::SendPublished { uri, conv_id: conv_id_clone, tag });
        }
        Err(e) => {
            let _ = tx.send(BgEvent::SendFailed(format!("{e}")));
        }
    }
});
```

#### 3.5.5 Polling Interval Change

In `tick()`, increase the poll interval when Drawbridge connections are active:

```rust
let poll_interval = if self.drawbridge.active_connection_count() > 0 {
    Duration::from_secs(30) // Reduced polling when Drawbridge is active
} else {
    Duration::from_secs(5)  // Original polling interval
};
```

#### 3.5.6 Tag Updates After Epoch Change

After processing a Commit event (epoch change) in `process_poll_results`, update tags on the relevant partner Drawbridge:

```rust
ControlKind::Commit => {
    // ... existing epoch update and populate_candidate_tags ...

    // Update tags on partner Drawbridge connections for this conversation
    self.update_drawbridge_tags_for_conversation(&conv_id);
}
```

Where `update_drawbridge_tags_for_conversation` filters `tag_map` to find tags relevant to each partner device in this conversation and sends `watch_tags` to their respective Drawbridge connections.

#### 3.5.7 Startup Reconnection

After successful login (in `handle_bg_event` for `BgEvent::LoggedIn`):

```rust
BgEvent::LoggedIn { client, did, .. } => {
    // ... existing login handling ...

    // Connect to own Drawbridge if configured
    if let Some(ref url) = self.drawbridge_url {
        self.drawbridge.connect_own(url, &did, &identity_key).await.ok();
    }

    // Reconnect to all persisted partner Drawbridges
    self.drawbridge.reconnect_all_partners().await;
}
```

### 3.6 CLI Configuration

Add `--drawbridge-url` flag to `Args` in `main.rs`:

```rust
#[derive(Parser)]
struct Args {
    /// Custom storage directory (default: ~/.moat)
    #[arg(short = 's', long = "storage-dir", global = true)]
    storage_dir: Option<PathBuf>,

    /// Drawbridge WebSocket URL (e.g., wss://drawbridge.moat.social/ws)
    /// Persisted after first use.
    #[arg(long = "drawbridge-url", global = true)]
    drawbridge_url: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}
```

On first use, the URL is saved to `drawbridge.json` and reused for subsequent sessions. The flag overrides the persisted value.

### 3.7 Persistence

All Drawbridge state is stored in a single file `~/.moat/drawbridge.json`:

```rust
#[derive(Serialize, Deserialize, Default)]
pub struct DrawbridgeState {
    /// Our own Drawbridge URL (set via --drawbridge-url)
    pub own_url: Option<String>,

    /// Tickets we've registered on our own Drawbridge
    /// Key: group_id_hex, Value: ticket_hex
    pub own_tickets: HashMap<String, String>,

    /// Received DrawbridgeHints from conversation partners
    /// Key: (partner_did, device_id_hex)
    pub partner_hints: HashMap<(String, String), StoredHint>,
}
```

Methods added to `KeyStore`:

```rust
impl KeyStore {
    pub fn load_drawbridge_state(&self) -> Result<DrawbridgeState>
    pub fn store_drawbridge_state(&self, state: &DrawbridgeState) -> Result<()>
}
```

### 3.8 UI Changes

#### 3.8.1 Status Bar

Add a Drawbridge connection indicator to the status bar in `ui.rs`:

```
⚡ 3 relays | alice.bsky.social | 5 conversations
```

Shows the count of active Drawbridge connections (own + partner). When no Drawbridge is configured, the indicator is absent.

#### 3.8.2 Debug Logging

All Drawbridge connection events, auth flows, tag updates, and errors are logged to `debug.log` via the existing `DebugLog`.

### 3.9 Testing

#### 3.9.1 Go Server Tests

Add to `relay_test.go`:

```go
func TestKeyPackageAuth(t *testing.T) {
    // 1. Start relay
    // 2. Connect, request_challenge
    // 3. Sign with Ed25519 key, send challenge_response with public_key
    // 4. Verify authenticated response
    // 5. Verify async key package check runs
}

func TestTicketAuthFlow(t *testing.T) {
    // 1. Sender connects with key package auth
    // 2. Sender registers ticket
    // 3. Recipient connects with ticket
    // 4. Verify recipient can watch_tags but not event_posted
    // 5. Verify recipient receives new_event when sender posts
}

func TestTicketRevocationReconnect(t *testing.T) {
    // 1. Register ticket, recipient connects
    // 2. Revoke ticket
    // 3. Recipient disconnects
    // 4. Recipient reconnects — verify rejected
}
```

#### 3.9.2 Rust Unit Tests

Add to `crates/moat-cli/src/drawbridge.rs`:

```rust
#[cfg(test)]
mod tests {
    // Test DrawbridgeState serialization/deserialization roundtrip
    // Test hint storage and lookup
    // Test tag filtering for a specific partner device
    // Test connection state transitions
    // Test exponential backoff timing
}
```

#### 3.9.3 Integration Tests

Automated integration test that spins up a local Drawbridge server and tests the full flow:

```rust
// In crates/moat-cli/tests/drawbridge_integration.rs or similar

#[tokio::test]
async fn test_drawbridge_end_to_end() {
    // 1. Start a local Drawbridge server (Go binary or in-process mock)
    // 2. Alice CLI: connect as sender, register ticket
    // 3. Bob CLI: connect as recipient with ticket, watch tags
    // 4. Alice: publish event, send event_posted
    // 5. Bob: verify new_event received
    // 6. Bob: fetch and decrypt event
}
```

### 3.10 File Changes Summary

| File | Changes |
|------|---------|
| `moat-drawbridge/messages.go` | Add `public_key` field to `ChallengeResponseMsg` |
| `moat-drawbridge/auth.go` | Replace DID document verification with provided-pubkey verification |
| `moat-drawbridge/verify.go` | Add `asyncVerifyKeyPackage` (fetch key packages from PDS, check pubkey exists) |
| `crates/moat-cli/Cargo.toml` | Add `tokio-tungstenite`, `futures-util` dependencies |
| `crates/moat-cli/src/drawbridge.rs` | **New file**: `DrawbridgeManager`, connection lifecycle, reconnect logic |
| `crates/moat-cli/src/app.rs` | Add `drawbridge` field, handle DrawbridgeHint events, auto-send hints, handle new_event, event_posted in publish task, adjust poll interval |
| `crates/moat-cli/src/main.rs` | Add `--drawbridge-url` CLI flag, pass to App |
| `crates/moat-cli/src/keystore.rs` | Add `DrawbridgeState` persistence (load/store `drawbridge.json`) |
| `crates/moat-cli/src/ui.rs` | Add relay count to status bar |

### 3.11 Implementation Order

1. **Drawbridge server auth change** — Update Go server to accept `public_key` in `challenge_response`, remove old DID doc verification, add async key package verification
2. **CLI drawbridge module** — `DrawbridgeManager` struct, WebSocket connect/auth for both modes, read/write split, BgEvent integration
3. **Persistence** — `DrawbridgeState` in KeyStore, `drawbridge.json` file
4. **CLI flag + startup** — `--drawbridge-url`, auto-connect on login, reconnect from persisted state
5. **Sender integration** — `event_posted` in publish task, `register_ticket` on conversation creation, auto-send DrawbridgeHint
6. **Recipient integration** — Handle DrawbridgeHint events, connect to partner Drawbridges, `watch_tags`, handle `new_event`
7. **Tag updates** — Update partner Drawbridge tags after epoch changes
8. **Reconnect + backoff** — Exponential backoff for failed partner connections
9. **UI** — Status bar relay indicator
10. **Tests** — Go server tests, Rust unit tests, integration tests

---

## Phase 4: Flutter Support (moat-flutter)

### 4.1 FFI Bindings

Add to `moat-flutter/rust/src/api/simple.rs`:

```rust
/// Generate a random Drawbridge ticket
pub fn generate_drawbridge_ticket() -> Vec<u8> {
    MoatSession::generate_drawbridge_ticket().to_vec()
}

/// Create a DrawbridgeHint event
pub fn create_drawbridge_hint(
    handle: &MoatSessionHandle,
    group_id: Vec<u8>,
    url: String,
    ticket: Vec<u8>,
) -> Result<EventDto, String> {
    // ...
}
```

### 4.2 Dart Service

Create `lib/services/drawbridge_service.dart`:

```dart
class DrawbridgeService {
  // Own Drawbridge (sender mode)
  WebSocketChannel? _ownConnection;
  String? _ownUrl;

  // Partner Drawbridges (recipient mode)
  final Map<String, WebSocketChannel> _partnerConnections = {};
  final Map<String, Uint8List> _partnerTickets = {}; // url -> ticket

  // Hint storage: (did, deviceIdHex) -> hint
  final Map<(String, String), DrawbridgeHint> _hints = {};

  /// Connect to our own Drawbridge
  Future<void> connectOwn(String url, String did, Uint8List signatureKey) async {
    // ...
  }

  /// Handle incoming DrawbridgeHint
  Future<void> handleHint(DrawbridgeHint hint, String partnerDid) async {
    // ...
  }

  /// Notify that we posted an event
  Future<void> notifyEventPosted(Uint8List tag, String rkey) async {
    // ...
  }
}

class DrawbridgeHint {
  final String url;
  final Uint8List deviceId;
  final Uint8List ticket;
}
```

### 4.3 Provider Integration

Update `AuthProvider` to include Drawbridge management:

```dart
class AuthProvider extends ChangeNotifier {
  DrawbridgeService? _drawbridgeService;

  Future<void> initDrawbridge(String url) async {
    _drawbridgeService = DrawbridgeService();
    await _drawbridgeService!.connectOwn(url, did!, _signatureKey!);
  }
}
```

### 4.4 Platform Considerations

| Platform | WebSocket | Notes |
|----------|-----------|-------|
| Android | `web_socket_channel` | Works normally |
| iOS | `web_socket_channel` | Works normally |
| Web | `web_socket_channel` | Works, but CORS headers required on Drawbridge |

For web, Drawbridge needs:
```
Access-Control-Allow-Origin: *
```

---

## Phase 5: Testing

### 5.1 Unit Tests (Go)

```go
// relay_test.go

func TestTicketAuth(t *testing.T) {
    // 1. Sender connects with DID auth
    // 2. Sender registers ticket
    // 3. Recipient connects with ticket auth
    // 4. Verify recipient can watch_tags but not event_posted
}

func TestTicketRevocation(t *testing.T) {
    // 1. Register ticket
    // 2. Recipient connects
    // 3. Revoke ticket
    // 4. Recipient disconnects, tries to reconnect
    // 5. Verify reconnect fails
}

func TestSenderOnlyEventPosted(t *testing.T) {
    // Verify ticket-authenticated clients cannot send event_posted
}
```

### 5.2 Integration Tests

```bash
# Terminal 1: Start Drawbridge
cd moat-drawbridge && go run .

# Terminal 2: Alice (sender)
cargo run -p moat-cli -- --storage /tmp/alice

# Terminal 3: Bob (recipient)
cargo run -p moat-cli -- --storage /tmp/bob

# Test flow:
# 1. Alice creates conversation, invites Bob
# 2. Alice sends DrawbridgeHint
# 3. Bob receives hint, connects to Alice's Drawbridge
# 4. Alice sends message
# 5. Bob receives new_event notification
```

### 5.3 Property Tests

```rust
// In moat-core

proptest! {
    #[test]
    fn drawbridge_hint_roundtrip(
        url in "wss://[a-z]+\\.[a-z]+",
        device_id in prop::array::uniform16(any::<u8>()),
        ticket in prop::array::uniform32(any::<u8>()),
    ) {
        let event = Event {
            kind: EventKind::DrawbridgeHint {
                url,
                device_id: device_id.to_vec(),
                ticket: ticket.to_vec(),
            },
            // ...
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }
}
```

---

## Migration Path

### Backward Compatibility

The current single-Drawbridge model continues to work:
- All clients connect to one Drawbridge with DID auth
- No tickets needed (Drawbridge allows DID-auth for all operations)
- Federation is opt-in

### Rollout Phases

1. **Phase A:** Deploy Drawbridge with ticket support, but optional
   - DID-authenticated clients can still do everything
   - Tickets are additive functionality

2. **Phase B:** Update clients to send DrawbridgeHints
   - Clients that understand hints use them
   - Clients that don't ignore them (unknown event kind)

3. **Phase C:** Encourage self-hosting
   - Documentation for running your own Drawbridge
   - Default client config points to megabridge, but easy to change

---

## Open Questions

### Q1: Ticket Persistence

Should Drawbridge persist tickets to disk?

**Options:**
- In-memory only: Simple, but tickets lost on restart
- File-based: `tickets.json` with periodic save
- External store: Redis/SQLite for larger deployments

**Recommendation:** Start with file-based for single-instance. Add external store option later.

### Q2: Ticket Rotation

Should tickets rotate periodically?

**Analysis:** Tickets are shared via encrypted MLS. If MLS is compromised, the attacker can already read messages. Ticket rotation adds complexity without clear security benefit.

**Recommendation:** No automatic rotation. Alice can manually revoke and issue new ticket if needed.

### Q3: Multiple Tickets per Conversation

Should Alice be able to issue multiple tickets for the same conversation?

**Use case:** Different tickets for different recipients, allowing individual revocation.

**Tradeoff:** Reduces privacy (Drawbridge can distinguish recipients).

**Recommendation:** Support it (multiple `register_ticket` calls), but recommend single ticket per conversation in documentation.

### Q4: Drawbridge Discovery

How does Alice choose/discover a Drawbridge initially?

**Options:**
- Hardcoded default (megabridge)
- User configuration
- DNS-based discovery from DID
- PDS-based discovery

**Recommendation:** Start with hardcoded default + user override. More sophisticated discovery later.

---

## File Changes Summary

| File | Changes |
|------|---------|
| `moat-drawbridge/messages.go` | Add `TicketAuthMsg`, `RegisterTicketMsg`, `RevokeTicketMsg`, `TicketAuthenticatedMsg` |
| `moat-drawbridge/conn.go` | Add `authMode`, `ticket` fields; modify `handlePreAuth`, `handlePostAuth` |
| `moat-drawbridge/relay.go` | Add `tickets` map, `authenticateTicket`, `handleRegisterTicket`, `handleRevokeTicket` |
| `moat-drawbridge/auth.go` | No changes (DID auth unchanged) |
| `moat-drawbridge/verify.go` | Minor: rate limit key can be DID or ticket |
| `crates/moat-core/src/event.rs` | Add `DrawbridgeHint` variant |
| `crates/moat-core/src/lib.rs` | Add `generate_drawbridge_ticket`, `create_drawbridge_hint` |
| `crates/moat-cli/src/drawbridge.rs` | New file: `DrawbridgeManager` |
| `crates/moat-cli/src/app.rs` | Integrate DrawbridgeManager |
| `crates/moat-cli/src/keystore.rs` | Add hint persistence |
| `moat-flutter/rust/src/api/simple.rs` | Add FFI bindings |
| `moat-flutter/lib/services/drawbridge_service.dart` | New file |
| `moat-flutter/lib/providers/auth_provider.dart` | Integrate DrawbridgeService |

---

## Implementation Order

1. **Drawbridge protocol changes** (Go) — Can be deployed independently
2. **moat-core event kind** — Foundation for client changes
3. **moat-cli integration** — Test with terminal UI
4. **moat-flutter integration** — Mobile/web support
5. **Documentation** — Self-hosting guide, protocol spec update
