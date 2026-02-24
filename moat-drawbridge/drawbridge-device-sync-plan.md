# Drawbridge Device Sync Plan

This document describes the design for transferring conversation history to a newly-added device using Drawbridge as an ephemeral peer-to-peer transport.

## Background

Moat supports multiple devices per user. Each device has independent MLS key material and is identified by `{did, device_id}`. When a new device is set up, it is automatically added to all of the user's existing conversations via the device ring — a shared MLS group spanning all devices with the same DID. This means the new device can decrypt messages from the moment it joins, but has no access to prior conversation history.

MLS forward secrecy makes this unavoidable: old epoch keys are deleted as epochs advance. The new device receives the current epoch state but cannot retroactively decrypt messages from past epochs. History must be transferred explicitly from an existing device.

## Design Goals

- New device becomes useful for ongoing conversations immediately
- History backfills in the background, reverse-chronologically (newest first)
- Transfer is ephemeral — no history material touches the PDS
- Security is handled by the existing device ring MLS session
- Interrupted transfers can resume without re-sending already-received history
- Devices that go offline for extended periods (weeks, months) can re-sync when they reconnect

## Why Not the PDS

Posting the history bundle as a PDS blob was considered and rejected:

- History is not just pointers to existing PDS records — it includes decrypted plaintext for messages from all interlocutors, whose records live on their own PDSes
- The bundle grows linearly with conversation history and would leave sensitive material on the PDS indefinitely
- Ephemeral Drawbridge transfer leaves no trace and fits the privacy model better

## Transport: Drawbridge Pairing Mode

Drawbridge gains a new **pairing mode** alongside its existing tag-routing mode. Two devices that share a DID connect to Drawbridge, authenticate via the existing DID challenge-response flow, and register a shared pairing token. The relay matches them and forwards binary frames between the pair without inspecting content.

The relay does not need to verify that both sides share the same DID — that trust is established by the device ring MLS session layered on top. The pairing token is simply a random value used to rendezvous.

### New Relay Messages

| Message | Direction | Purpose |
|---------|-----------|---------|
| `pair_offer{token}` | Client → Relay | Announce a pairing session (source device) |
| `pair_join{token}` | Client → Relay | Join an existing pairing session (new device) |
| `paired` | Relay → Client | Both sides connected, transfer may begin |
| `sync_frame{data}` | Client → Relay → Client | Opaque binary frame, forwarded to paired peer |
| `pair_closed` | Relay → Client | Peer disconnected |

The relay holds pairing sessions in memory with a short TTL (e.g. 5 minutes). Sessions are cleaned up when either side disconnects.

## Security: Device Ring MLS Session

All history data is encrypted as MLS application messages within the device ring before being handed to Drawbridge. The relay sees opaque ciphertext. Drawbridge's TLS protects against network observers; the MLS layer protects against the relay operator.

No separate key exchange or pairing code is needed — the device ring MLS session already provides mutual authentication and confidentiality between devices that share a DID.

## Transfer Format

The two sync directions are fundamentally different and are handled separately.

### Forward sync: catching up on recent missed messages

For messages the receiving device was a member for but simply missed (e.g. the laptop was offline for a week), the peer provides a **manifest** — an ordered list of rkeys per conversation. The receiving device fetches the raw ATProto event records from the PDS itself and processes them through MLS normally, advancing the ratchet correctly. No plaintext crosses the sync channel for this case.

### Backward sync: historical backfill

For messages predating the receiving device's existence, the old epoch keys are gone — the PDS records are undecryptable by the receiving device regardless. The peer streams **decrypted plaintext** batches, reverse-chronologically, encrypted in transit by the device ring MLS session. The receiving device stores these directly for display. No MLS ratchet is involved; this is purely a display history transfer between a user's own devices.

### Ordering

Transfer proceeds **reverse-chronologically** — newest messages first. This means the receiving device is immediately current and can participate in active conversations while older history backfills behind it.

### Chunking

Messages are batched by conversation and time window. A reasonable chunk size is 50–100 messages per MLS application message to balance latency and overhead.

### Blobs

Blob transfer is **not included** in the sync. Message records contain both a reference (CID + PDS URI) and a preview/placeholder sufficient for display. The receiving device fetches full blob content on demand when the user explicitly opens the attachment. This keeps the sync fast and avoids transferring large amounts of media that may never be viewed.

### Watermark

Each device tracks a **sync watermark** per conversation: the rkey of the oldest message successfully received. On reconnect after an interrupted transfer, the peer resumes from the watermark rather than restarting. The watermark is persisted locally so it survives app restarts.

## Conversation Hash Chain

To detect and recover from divergence between devices that go offline for extended periods, each device maintains a **conversation digest** — a running hash over the canonical ordered message history of each group.

### Canonical Ordering

Messages are ordered by `rkey` (lexicographic, which is also chronological for ATProto records). This ordering is deterministic across all devices regardless of arrival order.

### Hash Construction

```
digest_0 = 0x00...00  (32 zero bytes)
digest_n = SHA256(digest_{n-1} || rkey_n || message_id_n)
```

The digest is updated each time a message is appended to local storage. It is a pure function of the ordered message set — any two devices with identical history will produce identical digests.

### Sync Check

When two devices connect via the device ring (either for initial history sync or after a period offline), they exchange their current digest and oldest-held rkey for each conversation. If digests match, they are in sync and no transfer is needed. If they differ, the source device binary-searches the history to find the divergence point and transfers only the tail the new device is missing.

This makes re-sync after a long offline period cheap — a desktop that wakes up after three months only needs the delta, not a full retransfer.

### Epoch Anchoring

The digest is also recorded at each MLS epoch boundary as part of the existing checkpoint mechanism. This provides coarse-grained sync points that can be compared quickly before doing a fine-grained binary search.

## Trigger

History sync is initiated automatically when the device ring MLS session processes a Commit that adds a new sibling device. Any online device that processes the Commit can make a pairing offer; the new device joins upon completing its Welcome processing.

## Bidirectional Merge

Sync is not a simple donor/recipient relationship. Consider a user who primarily uses their phone but occasionally turns on their laptop. If they lose their phone, use a new phone for a week, then sit down at their laptop: the laptop has deep old history the new phone lacks, and the new phone has a week of recent messages the laptop lacks. Both devices need what the other has.

Each device's history can be described as a range `(oldest_rkey, newest_rkey)` per conversation. Before transferring anything, devices exchange these ranges (plus epoch-boundary digests) via the device ring. Each device then identifies the segments it is missing and requests them from the peer.

Both devices stream simultaneously — the laptop streams old history forward, the new phone streams recent history backward — and they converge on a complete union. The pairing session is symmetric; both sides are simultaneously source and recipient for different segments.

## Phases

### Phase 1: Drawbridge Pairing Mode
- Add `pair_offer`, `pair_join`, `paired`, `sync_frame`, `pair_closed` messages to the Go relay
- Pairing sessions keyed by token with TTL cleanup
- No inspection of frame contents

### Phase 2: Conversation Digest
- Add running SHA256 digest to local message storage
- Persist digest per conversation alongside the watermark
- Expose digest comparison and binary search in moat-core

### Phase 3: CLI History Sync
- Detect new sibling device added to device ring
- Initiate or join pairing session via Drawbridge
- Forward sync: exchange rkey manifests; receiving device fetches and decrypts from PDS
- Backward sync: stream decrypted plaintext batches reverse-chronologically, encrypted via device ring MLS
- Track and persist sync watermark per conversation
- Resume interrupted transfers from watermark

### Phase 4: Flutter History Sync
- Mirror CLI implementation in the Flutter app
- Progress indicator during backfill
- Blob placeholders with tap-to-download UI

### Phase 5: Reconnect Sync
- On device ring reconnect, exchange digests
- Binary search to find divergence point
- Transfer only the missing delta
