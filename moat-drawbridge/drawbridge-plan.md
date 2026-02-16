# Drawbridge Federation Plan

This document describes the federation model for Drawbridge, the real-time notification relay for Moat.

## Background

Drawbridge is a WebSocket relay that provides real-time push notifications for Moat clients. When Alice posts a message, her Drawbridge notifies Bob immediately, rather than Bob waiting for the next poll cycle.

The current implementation is a single-instance, in-memory design. This document outlines how Drawbridge can scale and federate while preserving Moat's privacy properties.

## Current Architecture

```
┌─────────┐      event_posted{tag}      ┌─────────────┐
│  Alice  │ ──────────────────────────▶ │  Drawbridge │
└─────────┘                             │   (single)  │
                                        │             │
┌─────────┐      new_event{tag}         │             │
│   Bob   │ ◀────────────────────────── │             │
└─────────┘                             └─────────────┘
```

**Capacity:** A single well-tuned instance can handle ~500K concurrent WebSocket connections (~5M DAU at 10% online). Go's maps handle millions of tag subscriptions efficiently.

**Limitation:** All users must connect to the same instance for real-time notifications to work across conversations.

## The Federation Challenge

### Why Simple Sharding Doesn't Work

With per-event unique tags (introduced in the v2 tag scheme), each event has a never-before-seen tag derived from:

```
tag = HKDF(export_secret, group_id || sender_did || sender_device_id || counter)
```

This prevents clustering/correlation by observers, but also prevents routing:

- Alice posts `event_posted{tag: 0xabc123...}`
- Her Drawbridge doesn't know which other Drawbridges have clients watching that tag
- Tags are opaque — no way to determine recipients without checking everywhere
- **Only option: broadcast to ALL Drawbridges** → O(N) per event, doesn't scale

### Why DID-Based Routing Leaks Metadata

An alternative: route based on conversation membership rather than tags.

```
Alice posts → forward to Drawbridges serving Alice's conversation partners
```

**Problem:** This requires Alice's Drawbridge to know her social graph ("Alice talks to Bob, Carol, Dave"), which is exactly what tag anonymity is designed to hide.

## The Per-Partner Drawbridge Model

### Core Idea

Instead of everyone connecting to one Drawbridge, each user selects their own Drawbridge and shares it privately with conversation partners via MLS:

1. Alice chooses a Drawbridge (self-hosted or shared)
2. Alice sends an encrypted MLS message: `{type: "drawbridge_hint", url: "wss://relay.example.com"}`
3. Bob receives this, decrypts, and connects to Alice's Drawbridge
4. Bob watches only Alice's candidate tags on that Drawbridge
5. When Alice posts, her Drawbridge notifies Bob directly

### Connection Topology

Bob has conversations with Alice, Carol, and Dave:

```
           ┌─────────────────┐
     ┌────▶│ Alice's         │  (watches Alice's tags)
     │     │ Drawbridge      │
     │     └─────────────────┘
     │
┌────┴──┐  ┌─────────────────┐
│  Bob  │─▶│ Carol's         │  (watches Carol's tags)
└────┬──┘  │ Drawbridge      │
     │     └─────────────────┘
     │
     │     ┌─────────────────┐
     └────▶│ Dave's          │  (watches Dave's tags)
           │ Drawbridge      │
           └─────────────────┘
```

Bob maintains O(partners) connections, but:
- Many partners may use the same popular Drawbridge
- Mobile clients can use push notifications instead of WebSocket per partner
- The protocol already supports `register_push` for FCM/APNs

### Tag Watching is Targeted

On Alice's Drawbridge, Bob only registers candidate tags for Alice's messages:

```
tags derived from (group_*, alice_did, alice_device_*, counter_window)
```

He doesn't watch tags for other senders there — those come from their respective Drawbridges.

### No Broadcast Required

When Alice posts `event_posted{tag}`:
- Only clients connected to Alice's Drawbridge receive it
- Those clients registered because they're in conversations with Alice
- Routing is local to each Drawbridge instance
- No cross-instance communication needed

## Privacy Properties

### What's Revealed to Whom

| Entity | What they learn |
|--------|-----------------|
| Alice's Drawbridge operator | Alice's DID (she authenticates), IPs/push tokens of her conversation partners, notification timing |
| External network observer | Bob connects to some Drawbridge (not whose, not why) |
| Colluding Drawbridge operators | If Bob uses same push token on multiple Drawbridges, they can correlate "same device talks to Alice and Carol" |
| Public | Nothing — Drawbridge URLs are only shared inside encrypted MLS |

### The Drawbridge Selection is Private

This is a key insight: the mapping of "Alice uses Drawbridge A" is not public knowledge. It's shared only within encrypted MLS conversations with Alice's partners.

An adversary cannot:
- Look up "which Drawbridge does Alice use?" in any public directory
- Monitor a specific Drawbridge knowing it's "Alice's"
- Enumerate Alice's partners without operating her specific Drawbridge

### Push Token Considerations

Push tokens (FCM/APNs) are per-app, per-device. If Bob registers the same token with multiple Drawbridges, colluding operators can correlate his activity.

**Mitigations:**

| Approach | Tradeoff |
|----------|----------|
| WebSocket only | No cross-linking, but battery cost on mobile |
| Push proxy (self-hosted) | Bob runs a proxy that aggregates; Drawbridges see different endpoints |
| Web Push API | Origin-scoped tokens (different per Drawbridge domain), but web-only |
| Accept the risk | Still better than centralized; requires collusion |
| Per-conversation choice | Use push for casual chats, WebSocket for sensitive ones |

The protocol should support all of these — push registration is optional per-Drawbridge.

## Threat Model: Casual vs Sensitive

A critical insight: **privacy is per-conversation, not network-wide**.

Unlike Tor (where anonymity set size matters), Drawbridge privacy doesn't depend on what other users do:

- Alice and family on "megabridge" → operator sees their social graph, they don't care
- Snowden and source on self-hosted Drawbridge → completely isolated

The existence of a dominant centralized Drawbridge doesn't degrade privacy for users who opt out. They're independent.

### Mixed-Mode Usage

A single user can choose different Drawbridges for different conversations:

```
Journalist's client:
├── Family chat        → megabridge (convenient, don't care about metadata)
├── Work conversations → company Drawbridge (IT-managed, acceptable)
└── Source conversation → source's self-hosted Drawbridge (maximum privacy)
```

Each conversation independently selects its privacy/convenience tradeoff.

### What Centralization Affects

If 80% of users choose the same "megabridge":

**Does affect:**
- Availability for casual users (single point of failure)
- Megabridge operator's power/incentives
- Regulatory pressure on that operator

**Does NOT affect:**
- Privacy of the 20% using alternative Drawbridges
- Ability of high-risk users to self-host
- Protocol's support for federation

This is healthier than models requiring universal adoption of privacy tools.

## Implementation

### New MLS Event Kind

```rust
EventKind::DrawbridgeHint {
    url: String,           // "wss://relay.example.com"
    device_id: [u8; 16],   // which device this hint is for
}
```

Sent as a regular encrypted MLS message. Partners decrypt and store the mapping.

### Client State

```rust
// Per-partner Drawbridge mapping
drawbridge_hints: HashMap<(Did, DeviceId), DrawbridgeUrl>

// Connections to partner Drawbridges
drawbridge_connections: HashMap<DrawbridgeUrl, WebSocketConnection>
```

### Authentication Model

Senders and recipients have different authentication requirements:

| Role | Auth method | Reason |
|------|------------|--------|
| Sender (Alice on her own Drawbridge) | DID challenge-response | PDS verification needs her DID to confirm events are real |
| Recipient (Bob on Alice's Drawbridge) | Ticket (shared secret) | Proves authorization without revealing Bob's identity |

**Ticket-based recipient auth:**

Alice generates a random ticket (32-byte secret) and provisions it in two places:
1. Registers the ticket with her Drawbridge (out-of-band or via authenticated session)
2. Shares it with conversation partners inside MLS: `DrawbridgeHint { url, ticket }`

Bob connects to Alice's Drawbridge and presents the ticket. The Drawbridge verifies it matches a registered ticket, but learns nothing about Bob's identity.

**Advantages over fully unauthenticated:**
- Drawbridge rejects connections without a valid ticket — no freeloaders or scanners
- Rate limits are per-ticket instead of per-IP, which is more meaningful
- Alice controls access: revoke a ticket to cut off a conversation's recipients

**Ticket granularity:**

| Granularity | Tradeoff |
|-------------|----------|
| One ticket for all recipients | Simple, but revoking one partner revokes everyone |
| Per-conversation ticket | Alice can revoke individually; Drawbridge can rate-limit per conversation without learning recipient identities |
| Per-recipient ticket | Maximum control, but Drawbridge can correlate "this is one specific recipient" |

Per-conversation tickets are the sweet spot: Alice can revoke access to one conversation without affecting others, and the Drawbridge cannot distinguish individual recipients within the same conversation.

**What shared tickets leak (and don't):**

The Drawbridge operator can see concurrent connection count per ticket — roughly how many recipients are online for that conversation. Recipients can also be distinguished by their `watch_tags` sets, since each recipient has a different scanning window (`seen_counter` varies). This is inherent to any model where recipients connect — not caused by ticket sharing.

Shared tickets are actually *better* than per-recipient tickets for privacy: if Bob disconnects and two connections later reconnect on the same ticket, the operator can't reliably tell which is Bob and which is Carol. Per-recipient tickets would make cross-session tracking trivial.

### Client Behavior

**As sender (on your own Drawbridge):**
1. Authenticate with DID challenge-response
2. Register tickets for conversations
3. Send `event_posted{tag, rkey}` after publishing to PDS

**As recipient (on a partner's Drawbridge):**
1. Connect and present the ticket from the DrawbridgeHint
2. Register candidate tags for that partner's DID/devices via `watch_tags`
3. Receive `new_event` notifications
4. Optionally register a push token for mobile delivery

**General:**
1. **On receiving DrawbridgeHint:** Store mapping (url + ticket), connect to that Drawbridge if not already connected
2. **On DrawbridgeHint change:** Update mapping, potentially disconnect from old Drawbridge if no other partners use it

### Drawbridge Protocol Changes

- New message: `ticket_auth{ticket}` — recipient presents ticket after connecting (replaces DID challenge-response for recipients)
- `event_posted` requires DID authentication (enforced server-side)
- `watch_tags`, `update_tags`, `register_push` require a valid ticket
- Rate limits are per-ticket for recipients, per-DID for senders
- New authenticated sender message: `register_ticket{ticket}` — Alice provisions a ticket on her Drawbridge
- New authenticated sender message: `revoke_ticket{ticket}` — Alice revokes a ticket

### Multi-Device Handling

Alice has phone and laptop on different Drawbridges:

```
Alice (phone)  → DrawbridgeHint { url: "wss://mobile-relay.example", device_id: 0x1234... }
Alice (laptop) → DrawbridgeHint { url: "wss://home.alice.net", device_id: 0x5678... }
```

Bob stores both, connects to both, watches device-specific tags on each.

### Welcome Messages

When Alice invites Bob to a new conversation, the Welcome (or a follow-up message) should include her DrawbridgeHint so Bob knows where to connect immediately.

## Scaling Path

| Scale | Approach |
|-------|----------|
| 0–5M DAU | Single "megabridge" instance handles everyone who wants convenience |
| 5M+ DAU | Megabridge becomes a cluster (internal sharding by tag prefix or consistent hashing) |
| Federation | Self-hosted and alternative Drawbridges coexist; no coordination needed |
| High-risk users | Self-host or use small community Drawbridges, regardless of megabridge scale |

The per-partner model means federation is automatic — no protocol for Drawbridge-to-Drawbridge communication is needed. Each Drawbridge is independent.

## Summary

The per-partner Drawbridge model provides:

1. **Scalability** — No broadcast, routing is local to each instance
2. **Federation** — Users can run their own Drawbridges with no coordination
3. **Privacy gradient** — Casual users get convenience; sensitive users get isolation
4. **Private selection** — Drawbridge URLs shared only in encrypted MLS, not public
5. **Graceful degradation** — If Drawbridge is unavailable, falls back to polling

The key insight is that Drawbridge is an optimization, not a requirement. The underlying protocol works via PDS polling. Drawbridge adds real-time push, and users can choose their trust tradeoffs per-conversation.
