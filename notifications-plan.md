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
   - If WebSocket is active: deliver `{ type: "new_event", tag, rkey, payload }` immediately (DID is included for local delivery from owner's `event_posted`, omitted for inbound relay-to-relay events)
   - If backgrounded with push token: send opaque push notification (see Push section)
7. Alice's Drawbridge asynchronously verifies the event exists on Alice's PDS (trusted DID from auth)

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
    "payload": "<base64-encoded-ciphertext>"
  }
  ```
- **Response**: `202 Accepted` (fire-and-forget from sender Drawbridge's perspective)
- **No authentication required.** The recipient Drawbridge delivers immediately. Rate-limiting is by source IP.
- **No sender DID.** The endpoint is unauthenticated, so any DID field would be untrustworthy. An attacker could claim any DID, and DID-based rate limiting would punish the victim rather than the attacker. The sender's own Drawbridge performs PDS verification (it has a trusted DID from challenge-response auth). The recipient Drawbridge rate-limits by source IP instead.

### Two-Tier Notification Content

**WebSocket delivery (client online):**
- Includes tag, rkey, and encrypted payload. Sender DID is included for local delivery (same relay), omitted for relay-to-relay forwarded events.
- Private: only travels between Drawbridges and client, never through Google/Apple
- Client decrypts immediately — no PDS round-trip needed

**Push notifications (client backgrounded):**
- Minimal: opaque "you have new messages" signal
- No tag, no DID, no rkey, no payload — nothing that reveals conversation metadata to Google/Apple
- App wakes, connects to own Drawbridge via WebSocket, gets pending buffered notifications, then decrypts

### Async PDS Verification

The **sender's Drawbridge** asynchronously verifies the event after forwarding it (it has the sender's DID from challenge-response auth):
1. Resolve sender's DID document → extract PDS service endpoint
2. Fetch `com.atproto.repo.getRecord` for `social.moat.event` at the claimed rkey from the sender's PDS
3. Verify **both** that the record exists **and** that its tag field matches the claimed tag
- **On verification failure**: Log the failure and apply a soft rate limit — temporarily cool down the sender DID's notification privileges for 1 minute. No hard ban for MVP.
- Verification is non-blocking — notifications are already delivered before verification completes.

The **recipient's Drawbridge** does not perform PDS verification — the relay-to-relay protocol carries no sender DID (see Relay-to-Relay Protocol section). Spam protection on the recipient side is via source IP rate limiting.

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
- On failure: fall back to polling (the rkey is available for targeted fetch if the sender DID is known from a local `new_event`, otherwise the next poll cycle picks it up)

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

### Phase 1: Go Relay — COMPLETE

All Go relay changes are implemented and tested. 42 tests pass in ~6s.

**Ticket system removed:**
- Removed `AuthMode` enum (`AuthModeNone`, `AuthModeSender`, `AuthModeRecipient`) from `conn.go`
- Removed `ticket` and `authMode` fields from `Client` struct
- Removed `ticketsMu`, `tickets` map, `authenticateTicket()`, `handleRegisterTicket()`, `handleRevokeTicket()` from `relay.go`
- Removed all ticket message types from `messages.go`: `TicketAuthenticatedMsg`, `TicketRegisteredMsg`, `TicketRevokedMsg`, `TicketAuthMsg`, `RegisterTicketMsg`, `RevokeTicketMsg`
- Simplified `handlePreAuth` and `handlePostAuth` — no sender/recipient distinction
- Added `TestTicketAuthRejected` and `TestTicketMessagesRejectedPostAuth` to verify old messages are rejected

**Payload piping implemented:**
- `EventPostedMsg` now includes `Payload string` and `RelayURLs []string`
- `NewEventMsg` now includes `Payload string`
- Payload flows through local delivery, disconnect buffer, and relay-to-relay
- Tests: `TestEventPostedWithPayload`, `TestEventPostedPayloadInDisconnectBuffer`

**Relay-to-relay fan-out implemented:**
- `POST /relay/event` endpoint accepts `{ tag, rkey, payload }` — no DID (untrustworthy on unauthenticated endpoint)
- `handleEventPosted` calls `fanOut()` in a goroutine for each URL in `relay_urls`
- `fanOut()` spawns goroutines per URL with WaitGroup, 5s timeout per request
- `relayEventHandler()` deduplicates, delivers to local tag watchers, buffers for disconnected clients
- No async PDS verification on inbound relay events (no DID to verify)
- Async PDS verification only on sender's Drawbridge (has trusted DID from auth)
- Tests: `TestRelayToRelay_BasicDelivery`, `TestRelayToRelay_NoMatchingTag`, `TestRelayToRelay_MultipleClients`, `TestRelayToRelay_Dedup`, `TestRelayToRelay_DisconnectBuffer`, `TestRelayToRelay_NoAsyncVerification`, `TestEventPosted_FanOut`, `TestEventPosted_FanOutTimeout`, `TestEventPosted_FanOutPlusLocalDelivery`

**Property tests added:**
- `TestProp_RelayToRelayRoutingMatchesTags` — tag-based routing for inbound relay events
- `TestProp_PayloadPreserved` — random payloads survive fan-out round-trip
- `TestProp_FanOutReachesAllURLs` — all relay URLs receive POST
- `TestProp_DedupAcrossBothPaths` — same tag+rkey via local and relay delivers only once

**Property tests removed:**
- `TestProp_TicketRevokeOnlyByOwner`, `TestProp_RevokedTicketCannotAuth`, `TestProp_TicketRegistrationIdempotent`, `TestProp_ByDIDOnlySenders`

### Phase 2: ATProto Lexicon — NOT STARTED

- Add `social.moat.relayConfig` lexicon in `lexicons/social/moat/relayConfig.json`
- Add `publish_relay_config(url)` and `fetch_relay_config(did)` to `MoatAtprotoClient`
- Postern already supports arbitrary record CRUD, so `relayConfig` should work out of the box

### Phase 3: Rust CLI — NOT STARTED

- Simplify `drawbridge.rs` to single connection (remove `PartnerDrawbridge`, `partner_read_loop`)
- Remove `StoredHint`, `DrawbridgeState.partner_hints`, `own_tickets`, ticket registration/revocation
- Send envelope on `event_posted` with `{ tag, rkey, payload, relay_urls }`
- Handle `new_event` with payload: decrypt inline, fall back to PDS fetch on failure
- Add relay config cache (fetch partner `social.moat.relayConfig`, publish own on login)
- Update `DrawbridgeState` — remove ticket fields, keep `own_url`

### Phase 4: moat-core Cleanup — NOT STARTED

- Remove `DrawbridgeHintPayload` and `ControlKind::DrawbridgeHint` from `event.rs`
- Remove DrawbridgeHint encoding/decoding from event processing
- 11 files currently reference DrawbridgeHint

### Phase 5: Dart — NOT STARTED

- Simplify `drawbridge_service.dart` to single connection (remove `_PartnerConnection`, `connectPartner()`, `reconnectPartners()`)
- Remove `StoredDrawbridgeHint`, ticket queue, re-registration
- Send envelope on `notifyEventPosted` with payload and relay_urls
- Handle `new_event` with payload: decrypt inline, fall back to PDS fetch
- Add relay config fetch/publish

### Phase 6: moat-beacon Integration Tests — NOT STARTED

- Update `TestWorld::new_with_drawbridge()` to spawn per-participant Drawbridge instances
- Update `DrawbridgeProcess` to support multiple instances with different ports
- Remove ticket/hint plumbing from test setup
- Update `two-party-push` / `two-party-push-restart` scenarios for new architecture
- Add new scenarios: `two-party-payload-delivery`, `two-party-payload-fallback`, `three-party-fanout`, `same-drawbridge-local`
- Add property tests: `proptest_payload_delivery`, `proptest_mixed_delivery`, `proptest_drawbridge_restart`

### Phase 7: Mobile Push — NOT STARTED

- FCM/APNS integration in Go relay
- `register_push` message handling
- Push notification delivery for offline clients
