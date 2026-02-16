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

## Phase 3: CLI Multi-Drawbridge Support (moat-cli)

### 3.1 Drawbridge Connection State

Add new module `src/drawbridge.rs`:

```rust
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Manages connections to multiple Drawbridges
pub struct DrawbridgeManager {
    /// Our own Drawbridge (sender mode, DID-authenticated)
    own_drawbridge: Option<OwnDrawbridge>,

    /// Partner Drawbridges (recipient mode, ticket-authenticated)
    /// Key: Drawbridge URL
    partner_drawbridges: HashMap<String, PartnerDrawbridge>,

    /// Mapping: (DID, DeviceId) -> (URL, Ticket)
    hints: HashMap<(String, [u8; 16]), DrawbridgeHint>,
}

pub struct OwnDrawbridge {
    url: String,
    connection: WebSocketConnection,
    registered_tickets: HashMap<Vec<u8>, String>, // ticket -> conversation_id (for tracking)
}

pub struct PartnerDrawbridge {
    url: String,
    connection: WebSocketConnection,
    ticket: [u8; 32],
    watching_dids: Vec<String>, // which DIDs we're watching on this Drawbridge
}

#[derive(Clone)]
pub struct DrawbridgeHint {
    pub url: String,
    pub device_id: [u8; 16],
    pub ticket: [u8; 32],
}
```

### 3.2 Connection Lifecycle

```rust
impl DrawbridgeManager {
    /// Connect to our own Drawbridge as sender
    pub async fn connect_own(&mut self, url: &str, credential: &MoatCredential, key_bundle: &KeyBundle) -> Result<()> {
        // 1. WebSocket connect
        // 2. Receive challenge
        // 3. Sign challenge with identity key
        // 4. Send challenge_response
        // 5. Receive authenticated
    }

    /// Register a ticket on our own Drawbridge
    pub async fn register_ticket(&mut self, ticket: &[u8; 32], conversation_id: &str) -> Result<()> {
        // Send register_ticket message
    }

    /// Handle incoming DrawbridgeHint from a partner
    pub async fn handle_hint(&mut self, hint: DrawbridgeHint, partner_did: &str) -> Result<()> {
        let key = (partner_did.to_string(), hint.device_id);
        self.hints.insert(key, hint.clone());

        // Connect to this Drawbridge if not already connected
        if !self.partner_drawbridges.contains_key(&hint.url) {
            self.connect_partner(&hint.url, &hint.ticket).await?;
        }

        // Register tags for this partner on that Drawbridge
        self.update_partner_tags(&hint.url, partner_did).await?;

        Ok(())
    }

    /// Connect to a partner's Drawbridge as recipient
    async fn connect_partner(&mut self, url: &str, ticket: &[u8; 32]) -> Result<()> {
        // 1. WebSocket connect
        // 2. Send ticket_auth
        // 3. Receive ticket_authenticated
    }

    /// Send event_posted on our own Drawbridge
    pub async fn notify_event_posted(&mut self, tag: &[u8; 16], rkey: &str) -> Result<()> {
        // Only works if we have an own_drawbridge connection
    }
}
```

### 3.3 Integration with App

Modify `src/app.rs`:

```rust
pub struct App {
    // ... existing fields ...

    /// Drawbridge connection manager
    drawbridge: DrawbridgeManager,
}

impl App {
    /// Called when we decrypt a DrawbridgeHint event
    async fn handle_drawbridge_hint(&mut self, event: &Event, sender_did: &str) {
        if let EventKind::DrawbridgeHint { url, device_id, ticket } = &event.kind {
            let hint = DrawbridgeHint {
                url: url.clone(),
                device_id: device_id.clone().try_into().unwrap(),
                ticket: ticket.clone().try_into().unwrap(),
            };
            self.drawbridge.handle_hint(hint, sender_did).await.ok();
        }
    }

    /// Called after creating a new conversation
    async fn send_drawbridge_hint(&mut self, group_id: &[u8]) -> Result<()> {
        if let Some(own) = &self.drawbridge.own_drawbridge {
            // Generate ticket for this conversation
            let ticket = MoatSession::generate_drawbridge_ticket();

            // Register with our Drawbridge
            self.drawbridge.register_ticket(&ticket, &hex::encode(group_id)).await?;

            // Create and send the hint as an MLS message
            let hint_event = self.session.create_drawbridge_hint(
                group_id,
                &own.url,
                &ticket,
            );
            // ... encrypt and publish ...
        }
        Ok(())
    }
}
```

### 3.4 Persistence

Add to `KeyStore`:

```rust
/// Stored Drawbridge hints from conversation partners
#[derive(Serialize, Deserialize)]
pub struct StoredDrawbridgeHints {
    /// (DID, DeviceId hex) -> hint
    hints: HashMap<(String, String), StoredHint>,
}

#[derive(Serialize, Deserialize)]
pub struct StoredHint {
    url: String,
    ticket_hex: String,
}
```

Save to `~/.moat/drawbridge_hints.json`.

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
