# Moat Notification Plan

## Overview

A notification relay service that provides real-time message notifications to Moat clients, supplementing the existing 5-second polling mechanism. The relay is a lightweight Go service that acts as a client-to-client notification broker. It does not store messages, decrypt content, or replace polling — it makes the app feel faster when connected.

## Goals

- Real-time notifications when the app is open (WebSocket)
- Wake-up push notifications when the app is backgrounded (FCM/APNs)
- No message content or conversation metadata stored on the relay
- Polling remains as fallback — relay is an optimization, not a requirement
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
┌──────────┐     WebSocket      ┌───────────┐     WebSocket      ┌──────────┐
│  Alice's │ ─────────────────▸ │   Relay   │ ─────────────────▸ │  Bob's   │
│  Client  │  "I posted tag X"  │  (Go)     │  "new event for X" │  Client  │
└──────────┘                    └───────────┘                    └──────────┘
     │                               │                                │
     │  writes event                 │  FCM/APNs (if Bob              │  polls PDS
     ▼  to PDS                       │  is backgrounded)              ▼  for data
┌──────────┐                         ▼                          ┌──────────┐
│ Alice's  │                    ┌───────────┐                   │ Sender's │
│   PDS    │                    │ Google /  │                   │   PDS    │
└──────────┘                    │  Apple    │                   └──────────┘
                                └───────────┘
```

### The Relay is Notify-Only

The relay does **not** poll PDSes or fetch events. It only:
1. Accepts WebSocket connections from authenticated clients
2. Receives "I just posted an event" notifications from sender clients
3. Matches event tags to registered client watchlists
4. Forwards notifications to matching clients (WebSocket or push)

Clients continue to poll PDSes themselves for actual event data. The relay just tells them *when* to poll.

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
- `DID -> client` mapping for connection management

### Authentication: Signed Challenge

Clients authenticate via DID-signed challenge, not ATProto session tokens. This avoids sharing PDS credentials with the relay.

Flow:
1. Client connects via WebSocket
2. Relay sends a random nonce
3. Client signs `nonce + relay_url + timestamp` with their DID signing key
4. Client sends back: `{ did, signature, timestamp }`
5. Relay resolves DID, retrieves signing key, verifies signature
6. Connection is now authenticated for that DID

This works even if the client's PDS session has expired, and avoids credential sharing with third-party relays.

### Notification Flow

**Fast path (sender is connected to relay):**
1. Alice's client sends a message (writes `social.moat.event` to her PDS)
2. Alice's client sends relay: `{ type: "event_posted", tag: "<hex>", rkey: "<rkey>" }`
3. Relay looks up tag in its `tag -> []client` index
4. For each matching client:
   - If WebSocket is active: send `{ type: "new_event", tag, rkey, did }` (rich notification — this path is private, no Google/Apple involvement)
   - If backgrounded with push token: send opaque push notification (see Push section)
5. Relay forwards immediately, then asynchronously verifies the event exists on Alice's PDS
6. After the first notification for a given tag+rkey, further duplicates are debounced

**Slow path (sender not connected):**
- No relay notification occurs. Recipient discovers new events via normal polling.
- This is acceptable because: if the sender can't connect to the relay, they're likely on a different network/client, and the polling fallback handles it.

### Two-Tier Notification Content

**WebSocket notifications (client online):**
- Rich: includes tag, rkey, sender DID
- Private: only travels between relay and client, never through Google/Apple
- Allows client to fetch the specific record immediately without a full poll

**Push notifications (client backgrounded):**
- Minimal: opaque "you have new messages" signal
- No tag, no DID, no rkey — nothing that reveals conversation metadata to Google/Apple
- App wakes, connects to relay via WebSocket, gets pending rich notifications, then fetches from PDS

### Async Verification

After forwarding a notification, the relay verifies the event exists on the sender's PDS:
- Fetches `social.moat.event` record at the claimed rkey from the sender's PDS
- If the record doesn't exist (fake notification), the relay rate-limits or blacklists the sender
- Verification is non-blocking — notifications are already delivered

### Tag Registration

Clients register their active tags on connect and update them as MLS epochs advance:
1. On connect: client sends `{ type: "watch_tags", tags: ["<hex>", ...] }`
2. On epoch change: client sends `{ type: "update_tags", add: [...], remove: [...] }`
3. Relay updates its `tag -> []client` index

Tags are opaque 16-byte hex strings to the relay. The relay cannot determine which tags belong to the same conversation or which conversations a client is in.

### Push Token Registration

Clients optionally register a push token for background notifications:
- `{ type: "register_push", platform: "fcm" | "apns", token: "<token>" }`
- Token is held in memory, associated with the client's DID
- Lost on relay restart — client re-registers on next app open
- Gap between relay restart and app re-open: no push notifications, but polling still works

## Mobile Push (FCM / APNs)

### When Push Is Used

Push notifications are sent only when:
1. A client has registered a push token
2. The client's WebSocket is disconnected (app backgrounded)
3. A notification arrives for one of the client's registered tags

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
2. Connects to relay via WebSocket, re-authenticates, re-registers tags
3. Receives any pending rich notifications from relay (if relay has them buffered)
4. Fetches and decrypts events from PDSes
5. Shows actual notification content (sender name, message preview) locally

### Push Provider Requirements

- **FCM**: Relay needs a Firebase service account key. Standard HTTP v1 API.
- **APNs**: Relay needs an APNs auth key (.p8) or certificate. Standard APNs HTTP/2 API.
- Both are configured via relay environment variables / config file.

## Relay Discovery

### MVP: Per-User ATProto Record

Each user publishes their preferred relay URL(s) as an ATProto record:

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

This is analogous to how the ATProto PLC directory maps DIDs to PDS service endpoints. Other clients discover a user's relay by reading their `social.moat.relayConfig` record.

When sending a notification via relay, the sender's client:
1. Looks up the recipient's relay config (can be cached)
2. Connects to the recipient's relay (if different from their own)
3. Sends the notification

If sender and recipient use the same relay, the notification is a local lookup.

### Future: Per-Group Relay Override

Groups can optionally specify relay(s) in their encrypted MLS metadata, overriding members' default relay config for that conversation. Adding/changing the group relay advances the MLS epoch. This is deferred to post-MVP.

## Multi-Relay Design (Deferred)

The protocol supports multiple relays from day one, even though MVP uses a single relay:

- Clients can register with multiple relays simultaneously
- A client's `social.moat.relayConfig` lists relays in priority order
- Sender clients notify all of the recipient's listed relays
- First relay to deliver wins; duplicates are handled client-side (dedup by rkey)
- If one relay is down, others still deliver

Implementation of multi-relay connection and failover is deferred.

## Abuse Prevention (Deferred Details)

The plan acknowledges the need for abuse prevention but defers specific limits:

- Rate limiting per DID (notifications per second/minute)
- Maximum tags per client connection
- DID verification before allowing tag registration
- Blacklisting for repeated fake notifications (detected via async verification)
- Connection limits per IP

Exact thresholds will be determined during implementation.

## Client-Side Changes

### Overview

Both the Flutter app and CLI need changes to integrate with the relay. Polling remains as-is and serves as the fallback.

### Connection Lifecycle

1. On app launch: connect to relay via WebSocket, authenticate via signed challenge
2. Register watched tags for all active conversations
3. Optionally register push token (Flutter mobile only)
4. On MLS epoch change: update registered tags
5. On app background (mobile): WebSocket disconnects, push token remains registered on relay
6. On app foreground: reconnect WebSocket, re-register

### Notification Handling

When a WebSocket notification arrives:
- Parse the rich notification (tag, rkey, DID)
- Fetch the specific record from the sender's PDS
- Decrypt and process normally (same path as polling, but targeted)

### Sending Flow Change

After writing an event to the PDS, the client also sends a notification to the relay:
- `{ type: "event_posted", tag: "<hex>", rkey: "<rkey>" }`
- This is fire-and-forget; if the relay is unavailable, nothing happens (recipients will find the event via polling)

### Polling Adjustment

When connected to a relay, clients can reduce poll frequency (e.g., from every 5s to every 30-60s). Polling still catches events from senders not connected to the relay.

## Implementation Milestones

### Milestone 1: Relay Core
- Go service with WebSocket server
- Signed challenge authentication
- Tag registration and in-memory index
- Notification forwarding (WebSocket only)
- Async PDS verification

### Milestone 2: Client Integration
- CLI: WebSocket connection to relay, send notifications on post, receive notifications
- Flutter: Same, plus push token registration
- Both: Reduce poll frequency when relay-connected

### Milestone 3: Mobile Push
- FCM integration (Android)
- APNs integration (iOS)
- Opaque push payload
- App wake -> WebSocket reconnect -> rich notification flow

### Milestone 4: Hardening
- Rate limiting and abuse prevention
- Relay health monitoring
- Multi-relay connection (client connects to 2+ relays)
- Per-group relay override in MLS metadata
