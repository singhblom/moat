# Moat Notification Plan

## Overview

A relay service (Drawbridge) that provides real-time encrypted message delivery and push notifications to Moat clients. Each user connects only to their own Drawbridge. When a sender posts a message, their Drawbridge fans out the encrypted payload to each recipient's Drawbridge, which delivers it instantly over WebSocket or wakes the app via push notification. The PDS remains the durable store; polling serves as a consistency fallback.

## Goals

- Instant message delivery when the app is open (encrypted payload over WebSocket)
- Wake-up push notifications when the app is backgrounded (FCM/APNs)
- No plaintext content or conversation metadata stored on any relay
- Each client trusts only their own Drawbridge with push tokens and tag subscriptions
- Polling remains as fallback — Drawbridge is an optimization, not a requirement
- Design supports multiple relays for redundancy (implementation deferred)

## Non-Goals (MVP)

- Replacing polling entirely
- Persistent relay state (in-memory only; state lost on restart)
- Multi-relay failover implementation
- Per-group relay configuration
- Firehose subscription

## Architecture

### Components

```
                          ┌─────────────┐
                          │   Alice's   │
                          │ Drawbridge  │
                          └──────┬──────┘
                                 │ fan-out (relay-to-relay)
                    ┌────────────┼────────────┐
                    ▼            ▼             ▼
             ┌────────────┐ ┌────────────┐ ┌────────────┐
             │   Bob's    │ │  Carol's   │ │  Dave's    │
             │ Drawbridge │ │ Drawbridge │ │ Drawbridge │
             └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
                   │              │               │
              WebSocket/      WebSocket/      FCM push
               payload         payload        (wake app)
                   │              │               │
                   ▼              ▼               ▼
              ┌─────────┐  ┌──────────┐    ┌──────────┐
              │  Bob's  │  │ Carol's  │    │  Dave's  │
              │ Client  │  │  Client  │    │  Client  │
              └─────────┘  └──────────┘    └──────────┘
```

### Key Design Principles

1. **Each client connects only to their own Drawbridge.** No ticket system, no connecting to partner relays. You authenticate with your own Drawbridge via DID challenge-response and that's it.

2. **Sender's Drawbridge fans out.** When Alice sends a message, her client sends an envelope to her Drawbridge containing the encrypted payload and a list of recipient Drawbridge URLs (discovered via `social.moat.relayConfig`). Alice's Drawbridge pushes to each recipient's Drawbridge.

3. **Relay-to-relay requires no authentication.** Recipient Drawbridges accept inbound payloads from any source and deliver immediately. Async PDS verification catches abuse after the fact.

4. **Encrypted payloads flow through Drawbridge.** Messages are small (256B–4KB padded buckets). Piping the ciphertext through the relay makes delivery instant — no round-trip to the sender's PDS needed.

5. **PDS is the durable store.** Drawbridge is a fast delivery path. Polling the PDS remains as a consistency fallback for missed messages, offline catch-up, and senders not connected to any relay.

## Relay Service (Go)

### In-Memory State

The relay holds all state in memory. On restart, all state is lost. Clients re-register on next app open.

Per-connection state:
- Authenticated DID
- Set of watched tags (updated as MLS epochs advance)
- Push token (FCM or APNs), if provided
- Connection status (WebSocket active or backgrounded with push token only)

Global indexes:
- `tag -> []client` mapping for fast notification routing
- `DID -> []client` mapping for connection management (multi-device)

### Authentication: Signed Challenge

Clients authenticate with **their own** Drawbridge via DID-signed challenge. This is the only authentication mechanism — there are no tickets, no cross-relay auth tokens.

Flow:
1. Client connects via WebSocket
2. Relay sends a random nonce
3. Client signs `nonce + relay_url + timestamp` with their DID signing key
4. Client sends back: `{ did, signature, timestamp }`
5. Relay resolves DID, retrieves signing key, verifies signature
6. Connection is now authenticated for that DID

This works even if the client's PDS session has expired, and avoids credential sharing with third-party relays.

### Message Delivery Flow

**Fast path (sender connected to their Drawbridge):**
1. Alice's client encrypts a message and writes `social.moat.event` to her PDS
2. Alice's client sends her Drawbridge an envelope:
   ```json
   {
     "type": "event_posted",
     "tag": "<hex>",
     "rkey": "<rkey>",
     "payload": "<base64-encoded-ciphertext>",
     "relay_urls": ["wss://bob.relay.example", "wss://carol.relay.example"]
   }
   ```
3. Alice's Drawbridge delivers locally to any of Alice's other devices watching this tag
4. Alice's Drawbridge fans out to each recipient Drawbridge via relay-to-relay push
5. Each recipient Drawbridge matches the tag against its local `tag -> []client` index
6. For each matching client:
   - If WebSocket is active: deliver `{ type: "new_event", tag, rkey, did, payload }` immediately
   - If backgrounded with push token: send opaque push notification (see Push section)
7. Alice's Drawbridge asynchronously verifies the event exists on Alice's PDS

**Slow path (sender not connected):**
- No relay notification occurs. Recipients discover new events via normal polling.
- This is acceptable because polling remains as the fallback.

### Relay-to-Relay Protocol

Inbound endpoint for receiving fan-out from other Drawbridges:

- **Endpoint**: `POST /relay/event`
- **Payload**:
  ```json
  {
    "tag": "<hex>",
    "rkey": "<rkey>",
    "did": "<sender-did>",
    "payload": "<base64-encoded-ciphertext>"
  }
  ```
- **Response**: `202 Accepted` (fire-and-forget from sender Drawbridge's perspective)
- **No authentication required.** The recipient Drawbridge delivers immediately and verifies asynchronously.

### Two-Tier Notification Content

**WebSocket delivery (client online):**
- Rich: includes tag, rkey, sender DID, and encrypted payload
- Private: only travels between Drawbridges and client, never through Google/Apple
- Client decrypts immediately — no PDS round-trip needed

**Push notifications (client backgrounded):**
- Minimal: opaque "you have new messages" signal
- No tag, no DID, no rkey, no payload — nothing that reveals conversation metadata to Google/Apple
- App wakes, connects to own Drawbridge via WebSocket, gets pending buffered notifications, then decrypts

### Async PDS Verification

After delivering a notification, the **recipient's Drawbridge** asynchronously verifies the event:
1. Resolve sender's DID document → extract PDS service endpoint
2. Fetch `com.atproto.repo.getRecord` for `social.moat.event` at the claimed rkey from the sender's PDS
3. Verify **both** that the record exists **and** that its tag field matches the claimed tag
- **On verification failure**: Log the failure and apply a soft rate limit — temporarily cool down notifications from the sender DID for 1 minute. No hard ban for MVP.
- Verification is non-blocking — notifications are already delivered before verification completes.

### Tag Registration

Clients register their active tags with their own Drawbridge on connect and update them as MLS epochs advance:
1. On connect: client sends `{ type: "watch_tags", tags: ["<hex>", ...] }`
2. On epoch change: client sends `{ type: "update_tags", add: [...], remove: [...] }`
3. Relay updates its `tag -> []client` index

Tags are opaque 16-byte hex strings that serve as **anonymous mailboxes** on the Drawbridge. This has three important properties:

1. **Privacy from sender's relay.** Alice's Drawbridge fans out to `wss://big-public-relay.example` with a tag. That relay routes to the right user(s) internally. Alice's Drawbridge never learns which DID(s) are behind a given tag on the recipient relay — the relay-to-relay protocol carries no recipient DID, only a tag.

2. **Scalable routing.** A large public Drawbridge may serve millions of users. Tags provide O(1) lookup from inbound event to the correct client(s), without requiring the sender to know anything about the recipient relay's user base.

3. **Multi-device routing and push gating.** When a user has multiple devices, each device registers the tags for the conversations it participates in. Inbound events are delivered only to devices watching that tag, and push notifications are only sent when a matching device is backgrounded — not for every inbound event.

### Push Token Registration

Clients optionally register a push token for background notifications:
- `{ type: "register_push", platform: "fcm" | "apns", token: "<token>" }`
- Token is held in memory, associated with the client's DID
- Lost on relay restart — client re-registers on next app open
- Gap between relay restart and app re-open: no push notifications, but polling still works
- **Push tokens are only shared with your own Drawbridge** — never sent to partner relays

### Multi-Device Support

- A single DID may have **multiple simultaneous WebSocket connections** (e.g., phone + desktop).
- `DID -> []client` mapping (not `DID -> client`).
- When a relay-to-relay event arrives, the Drawbridge notifies all connected devices for the matching DID.
- When the owner sends `event_posted`, the Drawbridge notifies the sender's **other devices** (all connections for the sender's DID *except* the originating connection), in addition to fanning out to recipient Drawbridges.
- Each connection has its own watched tags and push token.

### Deduplication

- Tag+rkey combinations are debounced with a 5-second window.
- Duplicate notifications for the same tag+rkey within 5 seconds are silently dropped.
- This handles both duplicate `event_posted` from the sender and duplicate relay-to-relay deliveries.

### Disconnect Buffer

- When an authenticated client disconnects, the relay buffers notifications (including payloads) for that DID for up to 30 seconds.
- If the client reconnects within 30 seconds, buffered notifications are delivered.
- After 30 seconds, the buffer is discarded (client will catch up via polling).
- Only applies to clients that had an active WebSocket session.

### Go Service & Networking

- **Dual listen mode** controlled by `RELAY_TLS` env var:
  - `RELAY_TLS=true` (default): Listen on port 443 with built-in autocert (Let's Encrypt via `golang.org/x/crypto/acme/autocert`). Requires `RELAY_DOMAIN` env var for the domain name. Single binary, zero external dependencies.
  - `RELAY_TLS=false`: Listen on port 8080, plain HTTP/WS. For local development and behind-proxy deployments.
- **Endpoints**:
  - `GET /ws` — WebSocket endpoint for client connections
  - `POST /relay/event` — Relay-to-relay event delivery (no auth)
  - `GET /health` — HTTP health check returning 200 OK + JSON stats (connections, uptime, tags tracked)
- **WebSocket keepalive**: Relay sends ping frames every 60 seconds. If no pong within 10 seconds, connection is closed.
- **Wire format**: JSON over WebSocket text frames for client messages. JSON over HTTP POST for relay-to-relay.
- **Logging**: Structured JSON logs (using `slog`). Configurable via `LOG_FORMAT=json` (default) or `LOG_FORMAT=text` for development.
- **Configuration** via environment variables:
  - `RELAY_TLS` — Enable/disable TLS (default: `true`)
  - `RELAY_DOMAIN` — Domain for autocert (required when TLS enabled)
  - `RELAY_ADDR` — Override listen address (default: `:443` or `:8080` based on TLS)
  - `LOG_FORMAT` — `json` (default) or `text`

## Mobile Push (FCM / APNs)

### When Push Is Used

Push notifications are sent only when:
1. A client has registered a push token with their own Drawbridge
2. The client's WebSocket is disconnected (app backgrounded)
3. A notification arrives (via relay-to-relay) for one of the client's registered tags

### Push Payload

The push payload is intentionally minimal to avoid metadata leakage:

```json
{
  "notification": {
    "title": "Moat",
    "body": "You may have new messages"
  }
}
```

No tag, DID, rkey, or any conversation-identifying information is included. The notification text says "may have" because the relay cannot know if the event is actually relevant (it could be a group state update, not a message).

### App Wake Behavior

When the app receives a push notification:
1. App opens / wakes
2. Connects to own Drawbridge via WebSocket, re-authenticates, re-registers tags
3. Receives any pending rich notifications from Drawbridge (if buffered within 30s window)
4. Decrypts immediately if payloads are buffered; otherwise fetches from PDS
5. Shows actual notification content (sender name, message preview) locally

### Push Provider Requirements

- **FCM**: Drawbridge needs a Firebase service account key. Standard HTTP v1 API.
- **APNs**: Drawbridge needs an APNs auth key (.p8) or certificate. Standard APNs HTTP/2 API.
- Both are configured via Drawbridge environment variables / config file.

## Relay Discovery

### Per-User ATProto Record

Each user publishes their Drawbridge URL(s) as an ATProto record:

```
Collection: social.moat.relayConfig
RKey: self

{
  "relays": [
    { "url": "wss://relay.moat.chat", "priority": 1 },
    { "url": "wss://my-relay.example.com", "priority": 2 }
  ]
}
```

This is analogous to how the ATProto PLC directory maps DIDs to PDS service endpoints.

When sending a message, the sender's client:
1. Looks up each recipient's `social.moat.relayConfig` record (cached)
2. Includes the recipient Drawbridge URLs in the envelope sent to the sender's own Drawbridge
3. Sender's Drawbridge fans out to each recipient Drawbridge

If sender and recipient use the same Drawbridge, the fan-out is a local delivery — no network hop.

### Future: Per-Group Relay Override

Groups can optionally specify relay(s) in their encrypted MLS metadata, overriding members' default relay config for that conversation. Adding/changing the group relay advances the MLS epoch. This is deferred to post-MVP.

## Multi-Relay Design (Deferred)

The protocol supports multiple relays from day one, even though MVP uses a single relay:

- A user's `social.moat.relayConfig` lists relays in priority order
- Sender's Drawbridge fans out to all of the recipient's listed relays
- First relay to deliver wins; duplicates are handled client-side (dedup by rkey)
- If one relay is down, others still deliver

Implementation of multi-relay connection and failover is deferred.

## Abuse Prevention (Deferred Details)

The plan acknowledges the need for abuse prevention but defers specific limits:

- Rate limiting per source DID on relay-to-relay endpoint
- Maximum tags per client connection
- DID verification before allowing tag registration
- Blacklisting for repeated fake notifications (detected via async verification)
- Connection limits per IP

Exact thresholds will be determined during implementation.

## Client-Side Changes

### Overview

Both the Flutter app and CLI need changes to integrate with Drawbridge. The client only connects to its **own** Drawbridge — no cross-relay connections, no tickets.

### Connection Lifecycle

1. On app launch: connect to own Drawbridge via WebSocket, authenticate via DID signed challenge
2. Register watched tags for all active conversations
3. Optionally register push token (Flutter mobile only)
4. On MLS epoch change: update registered tags
5. On app background (mobile): WebSocket disconnects, push token remains registered on Drawbridge
6. On app foreground: reconnect WebSocket, re-register

### Notification Handling

When a WebSocket notification arrives:
- Match the tag to a conversation
- Decrypt the payload using the MLS session for that group
- On success: process and display immediately — no PDS fetch needed
- On failure: fall back to fetching the record from the sender's PDS by rkey

### Sending Flow

After writing an event to the PDS, the client sends an envelope to its own Drawbridge:
1. Look up each recipient's `social.moat.relayConfig` (cached)
2. Send envelope: `{ type: "event_posted", tag, rkey, payload, relay_urls: [...] }`
3. Fire-and-forget; if the Drawbridge is unavailable, nothing happens (recipients catch up via polling)

### Polling Adjustment

When connected to a Drawbridge, clients reduce poll frequency significantly (e.g., every 60s or longer). Polling serves as a consistency check and catches events from senders not connected to any relay.

## Implementation Milestones

### Milestone 1: Relay Core

Location: `moat-drawbridge/` directory in this repo (Go module). Binary/service name: `drawbridge`.

- Go WebSocket service with dual TLS/plain mode
- DID challenge-response authentication (Ed25519 + P-256)
- Tag registration and in-memory index
- `event_posted` with envelope (payload + relay URLs)
- Local delivery to matching clients (WebSocket)
- Relay-to-relay fan-out via `POST /relay/event`
- Relay-to-relay inbound delivery (no auth, tag matching, WebSocket delivery)
- Deduplication (5s window per tag+rkey)
- Disconnect buffer (30s TTL, includes payloads)
- Async PDS verification with soft rate limiting
- Multi-device support (DID -> []client)
- DID resolution via PLC directory with 1-hour cache
- Integration tests covering all of the above

### Milestone 2: Client Integration
- CLI: WebSocket connection to own Drawbridge, envelope sending, payload receiving
- Flutter: Same, plus push token registration
- Both: Relay discovery via `social.moat.relayConfig` record
- Both: Reduce poll frequency when Drawbridge-connected

### Milestone 3: Mobile Push
- FCM integration (Android)
- APNs integration (iOS)
- Opaque push payload
- App wake -> WebSocket reconnect -> buffered notification delivery

### Milestone 4: Hardening
- Rate limiting and abuse prevention
- Relay health monitoring
- Multi-relay connection (client connects to 2+ relays)
- Per-group relay override in MLS metadata

## Implementation Status

The previous incarnation of Drawbridge used a different architecture: recipients connected to the sender's Drawbridge via ticket-based auth, notifications were metadata-only (no payload), and relay discovery used DrawbridgeHint events inside MLS. This section maps what exists against the new plan.

### What Can Be Reused As-Is

**Go relay (moat-drawbridge/):**
- WebSocket server, dual TLS/plain mode, `/health` endpoint — unchanged
- DID challenge-response authentication (`request_challenge`, `challenge`, `challenge_response`, `authenticated`) — unchanged, this is now the only auth mechanism
- Tag registration (`watch_tags`, `update_tags`) and `tag -> []client` in-memory index — unchanged
- `DID -> []client` multi-device mapping — unchanged
- Deduplication (5s window per tag+rkey) — unchanged
- DID resolution via PLC directory with 1-hour cache — unchanged
- Rate limiting per DID — unchanged
- WebSocket keepalive (ping/pong) — unchanged
- Structured logging (slog) — unchanged

**Rust CLI (crates/moat-cli/src/drawbridge.rs):**
- DID challenge-response signing flow (`connect_own`) — unchanged
- `watch_tags` / `update_tags` sending — reusable
- Exponential backoff reconnect logic — reusable
- `DrawbridgeState` persistence pattern — reusable (fields will change)

**Dart (moat-dart/common/lib/services/drawbridge_service.dart):**
- DID challenge-response signing flow via FFI — unchanged
- `watch_tags` / `update_tags` sending — reusable
- Exponential backoff reconnect logic — reusable
- Singleton service pattern — reusable

**moat-core:**
- `MoatSession::sign_drawbridge_challenge()` — unchanged

**Go tests:**
- `TestHealthEndpoint` — unchanged
- `TestAuthFlow`, `TestAuthReject_BadSignature`, `TestAuthReject_ExpiredTimestamp` — unchanged
- Tag registration and routing property tests (`TestProp_EventRoutingExactWatchers`, `TestProp_UpdateTagsCorrectness`, `TestProp_UpdateTagsOverlap`, `TestProp_ByTagConsistency`) — unchanged
- Cross-language challenge vector tests (`TestCrossLanguage_ChallengeVectors`) — unchanged

### What Must Be Removed

**Go relay:**
- Ticket system: `AuthModeRecipient`, `register_ticket`, `revoke_ticket`, `ticket_auth`, `ticket_authenticated`, `ticket_registered`, `ticket_revoked` message types. Remove `Relay.tickets` map, `ticketsMu`, and all ticket handler functions.
- `AuthMode` enum collapses — all authenticated connections are DID-authenticated owners. No sender/recipient distinction.
- Key package verification (`asyncVerifyKeyPackage`) — was specific to ticket-based auth trust model.

**Rust CLI:**
- `PartnerDrawbridge` struct and `partner_read_loop` — no more cross-relay connections.
- `StoredHint` with `ticket_hex` and `device_id_hex` — replaced by relay discovery via ATProto record.
- `DrawbridgeState.partner_hints` and `own_tickets` — no more tickets.
- Ticket registration/revocation logic.
- `BgEvent::DrawbridgeNewEvent` — replaced by payload delivery from own Drawbridge.

**Dart:**
- `_PartnerConnection` class and all partner connection management.
- `connectPartner()`, `registerTicket()`, `reconnectPartners()`.
- `StoredDrawbridgeHint` with ticket fields.
- Ticket queue and re-registration on connect.

**moat-core:**
- `DrawbridgeHintPayload` struct and `ControlKind::DrawbridgeHint` event kind.
- All DrawbridgeHint encoding/decoding in event processing.

**Go tests:**
- All ticket-related tests and property tests (`TestProp_TicketRevokeOnlyByOwner`, `TestProp_RevokedTicketCannotAuth`, `TestProp_TicketRegistrationIdempotent`).
- Tests that assume recipient connects to sender's relay.

**moat-beacon:**
- Drawbridge integration tests that use the old ticket-based model (proptest_drawbridge, proptest_push_restart Drawbridge paths).

### What Must Be Added or Modified

#### Go Relay

1. **Extend `event_posted` message** to include `payload` (base64 string) and `relay_urls` (string array):
   ```go
   type EventPostedMsg struct {
       Type      string   `json:"type"`
       Tag       string   `json:"tag"`
       RKey      string   `json:"rkey"`
       Payload   string   `json:"payload"`     // NEW: base64-encoded ciphertext
       RelayURLs []string `json:"relay_urls"`  // NEW: recipient Drawbridge URLs
   }
   ```

2. **Add `POST /relay/event` HTTP endpoint** for relay-to-relay delivery. Accepts `{ tag, rkey, did, payload }`. No authentication — matches tag against local index, delivers to WebSocket clients, returns `202 Accepted`. Triggers async PDS verification.

3. **Modify `event_posted` handler** to:
   - Deliver locally to other devices of the sender watching this tag (with payload)
   - Fan out to each URL in `relay_urls` via HTTP POST to `/relay/event`
   - Fan-out is fire-and-forget with a short timeout per request (e.g., 5s)

4. **Extend `new_event` message** to include `payload`:
   ```go
   type NewEventMsg struct {
       Type    string `json:"type"`
       Tag     string `json:"tag"`
       RKey    string `json:"rkey"`
       DID     string `json:"did"`
       Payload string `json:"payload"`  // NEW: base64-encoded ciphertext
   }
   ```

5. **Update disconnect buffer** to store `NewEventMsg` including payload (it already stores `NewEventMsg`, so this follows automatically from #4).

6. **Move async PDS verification** — previously done by sender's Drawbridge after `event_posted`. Now also done by recipient's Drawbridge after receiving via `POST /relay/event`. Both paths verify.

7. **Remove all ticket code** — `AuthMode` distinction, ticket maps, ticket message handlers.

#### ATProto / Lexicons

8. **Add `social.moat.relayConfig` lexicon** in `lexicons/social/moat/relayConfig.json`:
   ```json
   {
     "lexicon": 1,
     "id": "social.moat.relayConfig",
     "defs": {
       "main": {
         "type": "record",
         "key": "literal:self",
         "record": {
           "type": "object",
           "required": ["relays"],
           "properties": {
             "relays": {
               "type": "array",
               "items": { "$ref": "#/defs/relayEntry" }
             }
           }
         }
       },
       "relayEntry": {
         "type": "object",
         "required": ["url"],
         "properties": {
           "url": { "type": "string" },
           "priority": { "type": "integer" }
         }
       }
     }
   }
   ```

9. **Add relay config publish/fetch to moat-atproto** — `publish_relay_config(url)` and `fetch_relay_config(did) -> Option<Vec<RelayEntry>>` methods on `MoatAtprotoClient`.

#### Rust CLI (crates/moat-cli/src/drawbridge.rs)

10. **Simplify to single connection** — remove `PartnerDrawbridge`, keep only `OwnDrawbridge`. The client maintains one WebSocket to its own Drawbridge.

11. **Send envelope on `event_posted`** — after writing to PDS, send `{ type: "event_posted", tag, rkey, payload, relay_urls }`. The payload is the ciphertext bytes (base64-encoded). Relay URLs come from cached `social.moat.relayConfig` lookups for each conversation member.

12. **Handle `new_event` with payload** — when receiving `new_event` from own Drawbridge, attempt to decrypt the payload directly. On failure, fall back to fetching from sender's PDS by rkey.

13. **Relay config cache** — cache `social.moat.relayConfig` lookups per DID. Refresh periodically or when a conversation member's relay URL is needed and not cached.

14. **Publish own relay config** — on login, publish `social.moat.relayConfig` record with the configured Drawbridge URL.

15. **Update `DrawbridgeState`** — remove `own_tickets`, `partner_hints`. Keep `own_url`.

#### Dart (moat-dart/common/lib/services/drawbridge_service.dart)

16. **Simplify to single connection** — remove `_PartnerConnection`, `connectPartner()`, `reconnectPartners()`. Keep only the own-Drawbridge connection.

17. **Send envelope on `notifyEventPosted`** — include payload and relay_urls.

18. **Handle `new_event` with payload** — decrypt inline, fall back to PDS fetch on failure.

19. **Relay config fetch/publish** — same as CLI: cache partner relay configs, publish own on login.

20. **Remove DrawbridgeHint handling** from conversation model, polling service, and storage.

#### moat-core

21. **Remove `DrawbridgeHintPayload`** and `ControlKind::DrawbridgeHint` from `event.rs`.

22. **Remove DrawbridgeHint processing** from any event handling/routing code.

#### Postern (moat-postern)

23. **Add `social.moat.relayConfig` support** — Postern already supports arbitrary record CRUD, so this should work out of the box. Verify in tests.

#### moat-beacon

24. **Update `TestWorld`** — each participant gets its own Drawbridge instance (not one shared relay). `TestWorld::new_with_drawbridge()` spawns N Drawbridge processes, one per participant.

25. **Update `DrawbridgeProcess`** — may need to support multiple instances with different ports.

26. **Remove ticket/hint plumbing** from test setup.

### Tests

#### Go Unit & Property Tests (moat-drawbridge/)

**Keep (unchanged):**
- Auth challenge-response flow tests
- Tag registration and routing property tests
- Deduplication tests
- Health endpoint test
- Cross-language challenge vector tests

**Remove:**
- All ticket-related tests and property tests

**Add:**

- `TestRelayToRelay_BasicDelivery` — Spin up two relay instances. Client A authenticates with relay 1, registers tags. External HTTP POST to relay 1's `/relay/event` with matching tag. Verify client A receives `new_event` with payload.

- `TestRelayToRelay_NoMatchingTag` — POST to `/relay/event` with a tag no client is watching. Verify 202 response but no WebSocket delivery.

- `TestRelayToRelay_MultipleClients` — Multiple clients on same relay watching same tag. POST to `/relay/event`. Verify all receive the notification.

- `TestEventPosted_FanOut` — Client sends `event_posted` with `relay_urls`. Mock HTTP server(s) at those URLs. Verify relay POSTs to each URL with correct `{ tag, rkey, did, payload }`.

- `TestEventPosted_FanOutTimeout` — One relay URL is unresponsive. Verify fan-out to other URLs still completes (no blocking).

- `TestEventPosted_FanOutPlusLocalDelivery` — Sender has two devices. One sends `event_posted` with relay_urls. Other device is watching the tag. Verify: (a) other device gets `new_event` locally, (b) fan-out HTTP requests are made to relay_urls.

- `TestEventPosted_WithPayload` — Verify payload round-trips through `event_posted` → local delivery and `event_posted` → fan-out → `/relay/event` → client delivery.

- `TestRelayToRelay_Dedup` — POST same tag+rkey to `/relay/event` twice within 5s. Verify client receives it only once.

- `TestRelayToRelay_DisconnectBuffer` — Client watches tags, disconnects. POST to `/relay/event` with matching tag. Client reconnects within 30s. Verify buffered notification (with payload) is delivered.

- `TestRelayToRelay_AsyncVerification` — POST to `/relay/event` with mock PDS verifier that fails. Verify notification is still delivered (non-blocking), but rate limit is applied to sender DID.

- `TestNoTicketMessagesAccepted` — Verify relay rejects `ticket_auth`, `register_ticket`, `revoke_ticket` messages (or that they are simply unrecognized).

**Property tests to add:**

- `TestProp_FanOutReachesAllURLs` — Random number of relay URLs (1–10). Verify POST made to each one exactly once.

- `TestProp_RelayToRelayRoutingMatchesTags` — Random set of clients with random tags. Random inbound events with random tags. Verify: every client watching a matching tag receives the event, no client watching a non-matching tag receives it.

- `TestProp_PayloadPreserved` — Random binary payloads (up to 4KB). Verify payload survives: sender → `event_posted` → fan-out → `/relay/event` → `new_event` to client, byte-for-byte identical.

- `TestProp_DedupAcrossBothPaths` — Event arrives via both local `event_posted` (sender's other device) and `/relay/event` (from another relay). Same tag+rkey. Verify client receives it only once.

#### moat-beacon Integration Tests

**Modify existing scenarios:**

- `two-party-push` / `two-party-push-restart` — Update to use per-participant Drawbridges. Each participant publishes `social.moat.relayConfig` (via Postern). Sender's Drawbridge fans out to recipient's Drawbridge. Verify end-to-end delivery with payload.

**Add new scenarios:**

- `two-party-payload-delivery` — Two participants, each with own Drawbridge. Alice sends message. Verify Bob receives it via Drawbridge (payload delivery) before any polling occurs. Verify decryption succeeds.

- `two-party-payload-fallback` — Alice sends message. Bob's Drawbridge is down. Verify Bob still receives the message via polling fallback.

- `three-party-fanout` — Three participants on three different Drawbridges. Alice sends message. Verify both Bob and Carol receive via their respective Drawbridges.

- `same-drawbridge-local` — Two participants on the same Drawbridge. Alice sends message with `relay_urls` pointing to the same relay. Verify local delivery (no external HTTP call needed, or at least delivery works).

**Property tests (moat-beacon):**

- `proptest_payload_delivery` — Random message sequences between two participants. Each message sent via PDS + Drawbridge envelope. Verify: all messages arrive, payloads decrypt correctly, message order matches PDS order.

- `proptest_mixed_delivery` — Random mix of: Drawbridge-delivered messages and polling-only messages (simulated by skipping the envelope). Verify all messages arrive regardless of delivery path.

- `proptest_drawbridge_restart` — Random message sequences interleaved with Drawbridge process restarts. Verify: messages during Drawbridge downtime are caught by polling, messages after restart are delivered via Drawbridge.

#### Rust CLI Unit Tests

- Test `event_posted` envelope construction (tag, rkey, payload, relay_urls all populated correctly).
- Test `new_event` payload handling: successful decryption path and fallback-to-PDS path.
- Test relay config caching (fetch, cache hit, cache expiry).

#### Dart Unit Tests

- Test `notifyEventPosted` sends envelope with payload and relay_urls.
- Test `new_event` handler decrypts payload inline.
- Test relay config fetch and cache.
- Remove all ticket/hint-related tests.
