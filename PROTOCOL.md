# Moat Protocol

Moat is end-to-end encrypted messaging on ATProto (Bluesky) using MLS group encryption. All data lives on users' existing Personal Data Servers — there is no separate messaging server.

## Core Idea

Each conversation is an MLS group. Messages are encrypted by MLS, then published as ATProto records on the sender's PDS. Recipients poll the sender's PDS, recognize their messages by a tag, and decrypt locally.

## Cryptographic Primitives

- **MLS ciphersuite**: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- **Stealth encryption**: X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305
- **Tag derivation**: HKDF-SHA256

## Identity

A user is identified by their ATProto DID. Each device has its own MLS signing keys and stealth keypair. The MLS credential embeds `{did, device_name, device_id}` where `device_id` is a random 16-byte identifier generated once per device. This enables multi-device support — multiple devices share a DID but have independent key material and tag derivation streams.

## On-PDS Records

Three ATProto lexicons, all under `social.moat.*`:

| Record | Purpose | Contents |
|--------|---------|----------|
| `keyPackage` | MLS key distribution (cross-user only) | TLS-serialized MLS KeyPackage + expiry |
| `stealthAddress` | Receiving invites privately | X25519 public key + device name + 16-byte device id (v3) |
| `event` | All encrypted payloads | 16-byte tag + ciphertext + timestamp |

Every event record looks identical — messages, commits, welcomes, reactions, and same-user key distribution all use the same `event` schema, hiding the operation type from observers.

`keyPackage` records form a **public, shared pool**: they are published with `createRecord` (a new rkey each time), never deleted, and any user may fetch them. A consumed key package therefore stays visible on the PDS alongside its replacement, so consumers must select the **most recently published** record (highest rkey) — the older entries may already have had their init keys consumed. Same-user key distribution uses `social.moat.event` instead; see [Same-user Key Distribution](#same-user-key-distribution).

`stealthAddress` carries a stable 16-byte `device_id` (v3), which lets a device address a specific sibling's stealth key. The number of `stealthAddress` records under a DID already exposes the device count, so a stable per-record id reveals nothing that was not already inferable. Records predating v3 decode with an all-zero `device_id` and are ignored as stealth-addressing targets.

## Envelope Buckets & Off-Chain Payloads

Polling contacts' repos should not require downloading multi-megabyte ciphertexts just to see whether a tag belongs to one of our conversations. To cap per-event bandwidth, every padded ciphertext lands in one of three fixed buckets:

| Bucket | Size | Typical contents |
|--------|------|------------------|
| Small | 512 B | Emoji reactions and short text |
| Standard | 1024 B | Most user-visible messages plus previews for media/long text |
| Control | 4096 B | Rare overflow for commits, welcomes, or checkpoints that exceed 1 KB |

Padding still prepends a 4-byte big-endian length and fills the remainder with random bytes, so the observable leak is reduced to "short vs not short vs control." The `social.moat.event` record continues to hold `{tag, ciphertext}`, but the 1 KB/4 KB buckets can now embed either inline text or a preview bundle that references an external blob.

Large payloads (full-resolution images, long text, video) live off-chain as repo blobs referenced by `uri` pointers inside the encrypted payload. MVP restricts `uri` to repo-local addresses resolved through normal ATProto auth against the sender's PDS, keeping availability identical to in-band ciphertexts. Future revisions can add capability URLs or alternate storage tiers without changing the envelope.

## Sending a Message

1. Serialize the event to JSON: `{kind: "message", group_id, epoch, payload, message_id}` — all binary fields (`group_id`, `payload`, `message_id`, `prev_event_hash`, `epoch_fingerprint`, `sender_device_id`) are encoded as standard base64 strings (RFC 4648)
2. Pad to a fixed bucket (512B, 1KB, or 4KB control) with a 4-byte length prefix and random fill
3. MLS-encrypt using the group's current epoch keys
4. Derive a unique 16-byte tag (see [Tag Derivation](#tag-derivation) below)
5. Publish as `social.moat.event {tag, ciphertext}` on the sender's PDS

## Receiving Messages

1. Poll each contact's PDS for new `social.moat.event` records (cursor-based, using TID ordering)
2. For each group, generate candidate tags for all members using the scanning window (see [Tag Derivation](#tag-derivation))
3. Match the event's tag against candidate tags; on match, advance the seen counter for that sender
4. MLS-decrypt, unpad, deserialize the inner JSON event
5. If it's a commit, merge it to advance the local epoch and regenerate candidate tags

## Starting a Conversation (Stealth Invite)

This is the most complex part. The goal: Alice invites Bob without revealing to observers who the invite is for.

**Setup (once per device):** Bob generates an X25519 stealth keypair and publishes the public key, his device name, and his stable 16-byte device id as a `stealthAddress` record on his PDS.

**Alice invites Bob:**

1. Fetch Bob's stealth public keys (one per device) and an MLS key package from his PDS
2. Create an MLS group, add Bob → MLS produces a Welcome message
3. Encrypt the Welcome for all of Bob's devices:
   - Generate a random content encryption key (CEK)
   - Encrypt the Welcome with the CEK (XChaCha20-Poly1305)
   - For each of Bob's devices: ECDH with a fresh ephemeral key and Bob's stealth pubkey → HKDF → wrap the CEK
   - Pack: `num_devices || [ephemeral_pub + nonce + wrapped_CEK]... || nonce || encrypted_welcome`
4. Publish as an event with a **random** tag (not derived — Bob doesn't know the group ID yet)

**Bob receives:**

1. While polling Alice's PDS, attempt stealth decryption on unrecognized events
2. ECDH with own stealth private key → unwrap CEK → decrypt Welcome
3. Process the MLS Welcome to join the group; immediately upload a **fresh key package** (reusing the existing signing key) so Bob can be re-invited in the future
4. Generate candidate tags for all group members and register them for future message routing

## Adding Members to an Existing Group

When an existing member (Alice) adds a new member (Carol) to a group that already contains other members (Bob):

**Alice (adder):**

1. Resolve Carol's handle → DID, fetch her stealth public keys and MLS key package — use the **most recently published** key package (highest rkey). `listRecords` returns ascending rkey order and consumed packages are never deleted, so any earlier entry may already have had its init key consumed; picking one produces a Welcome Carol can never process
2. Derive a commit tag using the **current** epoch (pre-advance), since existing members scan for tags at this epoch
3. Call MLS `add_member` → produces a Welcome (for Carol) and a Commit (for existing members). The epoch advances.
4. Stealth-encrypt the Welcome for Carol's devices, publish with a **random** tag (same as the initial invite flow)
5. Publish the raw Commit with the **pre-advance tag** so existing members (Bob) can find and process it
6. Publish a Drawbridge hint bundle alongside the Welcome — this contains the Drawbridge hints of all existing group members (see [Drawbridge Hints for New Members](#drawbridge-hints-for-new-members)). Carol can use these to immediately connect to every existing member's relay without waiting for them to come online.

**Carol (new member):**

1. Detect the Welcome via stealth decryption while polling Alice's PDS
2. Process the Welcome to join the group; immediately upload a **fresh key package** (reusing the device's one signing key — see [Signing-key Identity](#signing-key-identity)) to the PDS so Carol can be re-invited in the future. MLS key packages are single-use: the init key is consumed and dropped from local storage once a Welcome uses it. The consumed *record* stays on the PDS, which is why consumers must take the newest
3. Call `get_group_dids` to discover **all** current members (not just the Welcome author), and store the full member list
4. Process the Drawbridge hint bundle from Alice to connect to all existing members' relays
5. Generate candidate tags for all members and register them
6. Send a reciprocal Drawbridge hint (encrypted as a group event, visible to all members) so existing members can discover Carol's relay

**Bob (existing member):**

1. Detect the Commit via tag scanning (it uses the pre-advance epoch tag Bob is scanning for)
2. Process the Commit — MLS advances the epoch, the new member appears in the group roster
3. Update the local member list by querying MLS for all group DIDs
4. Regenerate candidate tags for the new epoch (now includes Carol's tags)
5. Receive Carol's reciprocal Drawbridge hint via normal group event scanning — no action required from Bob

**Event count:** Adding a member produces exactly 3 published events regardless of group size: the stealth-encrypted Welcome (with hint bundle), the Commit, and Carol's reciprocal hint. Existing members publish nothing.

## Privacy Properties

| Mechanism | What it hides |
|-----------|--------------|
| **MLS encryption** | Message content, event type, group metadata |
| **Stealth addresses** | Invite recipient identity; fresh ephemeral keys make invites unlinkable |
| **Per-event unique tags** | Conversation identity — every event gets a unique tag, preventing clustering |
| **Padding** | Message length patterns (512B/1KB/4KB control buckets) |
| **Unified event schema** | Operation type — messages, commits, welcomes, and same-user key distribution all look the same on-chain |
| **Stealth-borne key distribution** | The multi-device relationship — sibling key packages travel as ordinary encrypted events rather than as records naming a `device_id` in the clear |

### Known Privacy Limitation: Image Messages Are Distinguishable

Image messages are **not** hidden by the unified event schema. Two observable signals allow a passive PDS observer to identify events carrying images:

1. **Blob upload timing** — a `com.atproto.repo.uploadBlob` call from the sender's DID immediately precedes the corresponding `com.atproto.repo.createRecord` call. The time gap is typically under one second and is highly correlated.
2. **Blob ref in record** — the `social.moat.event` record includes an optional `blob` field. Its presence is required to pin the uploaded blob to permanent storage (per the ATProto spec; unreferenced blobs are garbage-collected). This field reveals that the event carries an image.

The `blob.size` field further reveals the encrypted blob size, which correlates with image resolution or quality even after content-based padding.

**The `blob` field is intentionally included despite the leak** because omitting it causes blob garbage-collection and makes images unretrievable. The timing leak makes the presence/absence of the field a secondary concern — the correlation is already observable from network activity alone.

**Future mitigation — dedicated blob storage service:** The correct fix is to upload blobs to a separate service that:
- Accepts blobs under a secret URL with no reference to the uploader's DID or ATProto account
- Publishes blobs with a random delay (up to ~2 minutes) to break timing correlation with message send
- Hosts blobs under stable, content-addressed URLs independent of the sender's PDS

Until such a service exists, image messages should be considered metadata-leaky: an observer can determine that a conversation includes images, approximate when they were sent, and estimate their size. Message *content* remains fully encrypted.

## Tag Derivation

Every event gets a unique 16-byte tag, derived hierarchically from the MLS group state. This is analogous to BIP-32 HD key derivation: group members who know the export secret can reconstruct all valid tags, while observers see random-looking values.

### Derivation

```
export_secret = MLS.export_secret("moat-event-tag-v2", &[], 32)
ikm = group_id || sender_did || sender_device_id || counter_BE
tag = HKDF-SHA256(salt=export_secret, ikm=ikm, info="moat-event-tag-v2", len=16)
```

The `export_secret` is epoch-bound — it changes when the MLS epoch advances (member add/remove, key update). The `counter` is a per-device, per-epoch monotonic counter starting at 0, pre-incremented before publishing for crash safety.

### Sender Side

The sender maintains an outgoing counter per `(group_id, epoch)`. For each event (message, commit, or reaction), the sender:

1. Pre-increments the counter (crash safety — skipping a counter is harmless, reusing one is not)
2. Derives the tag using the current epoch's export secret and the counter value
3. Publishes the event with the derived tag

When the epoch advances, the counter resets to 0 (the counter map is keyed by epoch). Stale epoch entries are pruned on state export.

### Recipient Side

Recipients generate **candidate tags** for each group member's device using a scanning window. To handle messages stranded across epoch boundaries (e.g. a message sent just before an `AddMember` advances the epoch), recipients retain export secrets from recent prior epochs and generate tags with a **decaying gap limit**:

```
# Current epoch: full scanning window
for each member (did, device_id) in group:
    from = seen_counter[(group_id, did, device_id)] + 1   (or 0 if never seen)
    generate tags for counters [from, from + GAP_LIMIT)

# Prior epochs: decreasing windows, always from counter 0
for each (age, prior_secret) in prior_export_secrets[group_id]:
    gap = decaying_gap(age)   # 5, 3, 2, 1, 1, 1, ...
    for each member (did, device_id) in group:
        generate tags for counters [0, gap) using prior_secret
```

The decay schedule:

| Epoch age | Gap limit | Purpose |
|-----------|-----------|---------|
| 0 (current) | 10 | Normal operation — covers in-flight messages between polls |
| 1 | 5 | Recent epoch change — catches stragglers from membership operations |
| 2 | 3 | |
| 3 | 2 | |
| 4–19 | 1 | Canary coverage — detects stranded messages at counter 0 |

**Total tags per sender-device per conversation: 36** (10 + 5 + 3 + 2 + 16×1). The budget is comparable to a single-epoch window of 50 but covers 20 epochs of history.

The `GAP_LIMIT` (10) is the maximum number of consecutive missed events tolerated per sender device in the current epoch. When a tag matches an incoming event, the recipient calls `mark_tag_seen` to advance the seen counter, sliding the scanning window forward. On epoch change, seen counters are cleared (senders reset their counters per epoch).

The `seen_counters` map is persisted across sessions. The `tag_metadata` reverse lookup (tag → sender identity + counter) is ephemeral and rebuilt each polling cycle. The `prior_export_secrets` ring buffer (up to 19 entries per group) is persisted across sessions.

### Stealth Invites

Stealth invite tags are random (not derived) since the recipient doesn't yet know the group ID.

## Event Types (Inside Encryption)

Every event’s `kind` is now namespaced as `<domain>.<variant>`:

| Domain | Variants | Purpose |
|--------|----------|---------|
| `control.*` | `control.commit`, `control.welcome`, `control.checkpoint` | MLS state management and coordination; payload is TLS-serialized bytes. No `message_id` is present. |
| `message.*` | `message.short_text`, `message.medium_text`, `message.long_text`, `message.image` | User-visible content plus optional previews/external blobs. Each carries a 16-byte `message_id`. |
| `modifier.*` | `modifier.reaction` (more to follow) | Small toggles or annotations that reference an existing `message_id`. |
| `coord` | — | Multi-device coordination, as an MLS application message over a `DeviceCoord` group. Payload is `CoordMsg` JSON. See [Coordination Messages](#coordination-messages). |
| `sync.app` | — | History-sync frames over the Drawbridge pair WebSocket, encrypted to the device ring. |
| `sibling.msg` | — | Steady-state same-user coordination addressed to one sibling. Payload is `CoordMsg` JSON (`kp_batch` / `kp_request` / `user_conv_welcome`); the sender's device id travels in `Event.sender_device_id`. Stealth-encrypted, not MLS-framed. `group_id` empty, `epoch` 0. |

`sibling.msg` is the only event kind that is stealth-encrypted rather than MLS-framed, and the only one whose `group_id`/`epoch` carry no meaning. It is recognised by attempting stealth decryption during the [Own-PDS Stealth Scan](#own-pds-stealth-scan).

## Message Payloads & External Blobs

All binary fields in JSON payloads (byte arrays and fixed-length byte sequences) are encoded as standard base64 strings (RFC 4648). This applies to `Event` fields (`group_id`, `payload`, `message_id`, `prev_event_hash`, `epoch_fingerprint`, `sender_device_id`), `ReactionPayload.target_message_id`, `ExternalBlob` fields (`ciphertext_hash`, `content_hash`, `key`), `MediaMessage.preview_thumbhash`, and `MoatCredential.device_id`.

When `event.kind` starts with `message.`, the payload is a structured JSON object describing the user-visible content plus any off-chain pointer. Each payload carries:

- `group_id`, `epoch`, and transcript-integrity fields (same as other events),
- `message_id` (16 random bytes, stable anchor for reactions and pointer retargets),
- Variants describing the user-visible content:
  - `message.short_text` (512 B bucket): `text`
  - `message.medium_text` (1 KB bucket): `text`
  - `message.long_text` (1 KB bucket): `preview_text`, optional `mime`, and `external`
  - `message.image` (1 KB bucket): `preview_thumbhash`, `width`, `height`, `mime`, and `external`
  - (future) `message.video`, `message.audio`, etc., extend the same pattern.
- `modifier.reaction` remains a separate event kind with `{emoji, target_message_id}`, but uses the 512 B bucket budget like `message.short_text`.

`external` entries move the heavy payload off-chain. The struct includes:

| Field | Purpose |
|-------|---------|
| `ciphertext_hash` | SHA-256 of the stored blob (`nonce || ciphertext`) |
| `ciphertext_size` | Size in bytes of the stored blob |
| `content_hash` | SHA-256 of the plaintext after decrypting |
| `uri` | Repo-local address (`at://{did}/{cid}`) fetched via `com.atproto.sync.getBlob?did=&cid=` |
| `key` | Symmetric key (XChaCha20-Poly1305) for decrypting the blob (`nonce` lives alongside the ciphertext) |
| Optional `mime`, `width`, `height`, `duration_ms` | Media metadata for UX and validation |

Blobs are stored as `nonce || ciphertext` where the nonce is a 24-byte random value. Clients compute `ciphertext_hash = SHA-256(nonce || ciphertext)` before decrypting and `content_hash = SHA-256(plaintext)` afterward. Both hashes sit inside the MLS-authenticated payload so tampering produces transcript-integrity warnings.

### Integrity & Fetch Flow

1. Attempt to decrypt every 1 KB envelope as usual. If the payload contains `external`, surface the preview immediately (e.g., ThumbHash, `preview_text`, waveform).
2. Fetch the blob lazily from the sender's PDS using existing repo auth. Hash the downloaded bytes before decrypting and compare to `ciphertext_hash`. Reject on mismatch.
3. Decrypt using the provided `key` and the nonce prefix stored with the blob (`blob = nonce || ciphertext`). After decrypting, hash the plaintext and compare to `content_hash`.
4. Cache blobs by `content_hash` (stable across re-encryptions). _(Future: maintain a secondary cache mapping `ciphertext_hash → content_hash` to avoid reprocessing duplicates.)_

_(Future: If a blob moves or is re-encrypted, the sender emits a follow-up event referencing the original `message_id` with updated `uri`/`ciphertext_hash`. Receivers keep previews visible, automatically retarget pointers, and classify transient fetch failures (`Timeout`, `Unauthorized`, `NotFound`, `RateLimited`) separately from integrity errors.)_

### Preview & Bucket Policy

- 512 B bucket: reactions and `short_text`.
- 1 KB bucket: `medium_text`, previews for long text, and all media previews.
- 4 KB control bucket: only for overflow control traffic (commit/welcome/checkpoint) that truly cannot fit in 1 KB.
- Algorithmic previews stay tiny: ThumbHash ≤ 64 B raw (≈88 Base64 chars) for media posters, waveform snippets ≤ 160 B raw, and `preview_text` capped ~240–440 ASCII chars depending on other fields.
- No cover traffic in MVP, but the envelope structure keeps ciphertexts indistinguishable until MLS decryption routes them to the proper conversation.

### Blob Retention & Forward Secrecy

The symmetric `key` inside each `external` entry is forward-secret: it lives within the MLS-encrypted payload and is deleted when MLS epochs advance and old group state is purged. However, if MLS group state is compromised (e.g., device theft before state deletion), any blobs still hosted remain decryptable with the captured keys.

**Considerations for future work:**

- Align blob retention policies with MLS epoch rotation so blobs are not available longer than the keys that protect them.
- Per-blob ephemeral keys derived from the MLS epoch secret, so compromise of one blob key does not expose others.
- Server-side blob expiry with configurable TTL.

No specific retention policy is mandated in the current protocol version.

## Drawbridge Discovery

A Drawbridge is a WebSocket relay that provides real-time push notifications for new events. Each user connects only to their own Drawbridge (authenticated via DID challenge-response).

### Selecting a Drawbridge URL

Clients resolve their own Drawbridge URL in priority order:

1. **PDS-advertised URL** — after login, the client calls `com.atproto.server.describeServer` on the user's PDS. If the response includes a `services['social.moat.drawbridge']['endpoint']` entry, that URL is used. This lets PDS operators bundle a default Drawbridge for their users with no configuration required on the client side.
2. **Client default** — if the PDS does not advertise a Drawbridge, the client falls back to its own hardcoded default (e.g. `wss://moat-drawbridge.fly.dev/ws`).

Example `describeServer` response advertising a Drawbridge:

```json
{
  "services": {
    "social.moat.drawbridge": {
      "type": "DrawbridgeService",
      "endpoint": "wss://drawbridge.example.com/ws"
    }
  }
}
```

### Drawbridge Configuration Record

Once a client has connected to a Drawbridge, it publishes that URL as an ATProto record so that conversation partners can discover it for fan-out delivery:

```
Collection: social.moat.drawbridgeConfig
RKey: self

{
  "drawbridges": [
    { "url": "wss://drawbridge.moat.chat", "priority": 1 }
  ]
}
```

This is a singleton record (upserted via `putRecord`). Clients fetch partner Drawbridge configs via `getRecord` and cache them in memory.

### Message Delivery

When a sender posts an event, their client sends an envelope to their own Drawbridge containing the encrypted payload and the recipient Drawbridge URLs (discovered from `social.moat.drawbridgeConfig`). The sender's Drawbridge fans out to each recipient's Drawbridge via `POST /relay/event`. Recipient Drawbridges deliver immediately to clients watching the matching tag.

### Drawbridge Hints for New Members

`social.moat.drawbridgeConfig` lets a member discover a *contact's* relay, but a newly-added member would have to wait for each existing member to come online before learning where to reach them. To avoid that, the adder bundles the relay coordinates of every existing member alongside the Welcome, inside the same stealth-encrypted payload.

The Welcome is wrapped in an envelope rather than published raw:

```
[4-byte magic "MWE1"][4-byte welcome_len BE][welcome][hints_json]
```

`hints_json` is an array of `{ did, url, device_id, ticket }` — one entry per existing member device. A decoder that finds no trailing bytes treats the payload as a bare Welcome, so the envelope is backward-compatible with raw-Welcome publishers.

The new member decodes the bundle, connects to each listed relay, and then publishes a **reciprocal hint** as an ordinary group event so existing members learn their relay through normal tag scanning. This is why adding a member costs exactly three published events regardless of group size: the Welcome-with-bundle, the Commit, and the reciprocal hint.

### Privacy Properties of Drawbridge

Drawbridge holds the DID transiently during the challenge-response handshake and during async PDS verification of each posted event. It is never stored in any in-memory index, never associated with a connection beyond the auth handshake, and never logged after auth. An adversary with a memory snapshot sees `(connection, tags)` per client and `(tag, payload)` in the disconnect buffer — no DIDs. The disconnect buffer is keyed by tag (not by DID or device).

### Push Notifications

When a recipient device is offline, Drawbridge delivers via FCM (Android) or APNs (iOS, via FCM HTTP v1). The push payload contains only `(tag, rkey, payload)` — no sender DID, no plaintext, no metadata beyond what is already public on the PDS. FCM/APNs therefore see:

- The push token (known to the device OS and FCM/APNs)
- The encrypted payload (same ciphertext that would appear on the PDS)
- The rotating tag (a 16-byte pseudorandom value; unlinkable across epochs)

The client app decrypts the payload in a background handler before displaying the notification. The decrypted text is never sent to FCM/APNs.

**Device ID** — Each app installation generates a random 32-byte `device_id` stored in secure storage. The device ID is used by Drawbridge to suppress FCM delivery when the device's WebSocket is live, and to identify a registration for token refresh or explicit deregistration. It is not linked to the user's DID.

**Offline detection** — Drawbridge tracks `(device_id, connection)`. FCM is only sent when `isDeviceOnline(device_id)` returns false, i.e. the device has no live WebSocket and is past a 10-second grace window (to avoid duplicates during reconnect races).

**Push registration wire schema:**
```json
{ "type": "register_push", "device_id": "<32-hex>", "platform": "fcm", "token": "<fcm-token>", "tags": ["<hex>", ...], "expiry_sec": 2592000 }
{ "type": "unregister_push", "device_id": "<32-hex>" }
```

**FCM credentials** — The FCM service account key is held by the Drawbridge operator (configured via `FCM_CREDENTIALS_FILE` env var). It is not part of the app binary. The Firebase project is tied to the app's package name (`social.moat.app`); operators running a public Drawbridge who wish to support the official app store build may request a service account key from the project maintainer.

### Pairing Mode (Multi-Device History Sync)

Drawbridge provides a **pairing mode** that lets two devices with the same DID rendezvous and stream opaque binary data between them. Bulk sync traffic runs on a dedicated `/pair` WebSocket so it never competes with live event delivery.

#### Two-Socket Architecture

Each client uses two sockets simultaneously during a sync:

- **Main WS** (`/ws`, existing DID-authed connection) — control plane only  
- **Pair WS** (`/pair`, one new socket per pairing session) — bulk binary data

#### Handshake

1. Both clients are already authenticated on `/ws`.
2. Out of band (via a ring MLS message in the device ring group), the offerer and joiner agree on a random 32-byte token (hex-encoded, 64 chars).
3. On the main WS:
   - Offerer: `→ pair_offer{token}` / Relay: `→ pair_pending{token}`
   - Joiner: `→ pair_join{token}` / Relay: `→ pair_ready{token, pair_url}` (sent to both)
4. Each client opens a new WebSocket to `pair_url` (`wss://<relay>/pair`).
5. First frame on the pair WS (JSON): `pair_attach{token}`. No DID challenge — the token is the auth.
6. Once both sides have attached, relay sends `paired` on both pair WSes. From then on, only opaque binary frames flow; the relay forwards them verbatim.
7. Either side closing its pair WS ends the session. The relay sends `pair_closed{reason}` on the main WS to the surviving peer.

#### Wire Schemas

Main WS (client → relay):
```
{ "type": "pair_offer", "token": "<64-hex>" }
{ "type": "pair_join",  "token": "<64-hex>" }
```

Main WS (relay → client):
```
{ "type": "pair_pending", "token": "<64-hex>" }
{ "type": "pair_ready",   "token": "<64-hex>", "pair_url": "wss://<relay>/pair" }
{ "type": "pair_closed",  "reason": "<peer_gone|byte_cap|ttl_expired|...>" }
```

Pair WS (client → relay, first frame only):
```
{ "type": "pair_attach", "token": "<64-hex>" }
```

Pair WS (relay → client, sent once both sides attached):
```
{ "type": "paired" }
```

Pair WS (after `paired`): raw binary WebSocket frames forwarded verbatim.

#### Limits

| Parameter | Value |
|---|---|
| Token TTL | 5 minutes from `pair_offer` |
| Max attaches per token | 2 (offer + join) |
| Max frame size (pair WS) | 1 MiB |
| Max bytes per session | 256 MiB |
| Max bytes per connection per second | 8 MiB/s |

Exceeding the byte cap closes both pair WSes and delivers `pair_closed{reason:"byte_cap"}` on the main WS.

#### Security and Privacy

- **Tokens are capabilities**: a 32-byte random token is issued only over an authenticated main WS and is valid for two attaches within 5 minutes. The relay does not verify that both sides share the same DID — that trust comes from the MLS device ring session layered on top.
- **Content opacity**: the relay sees only opaque binary frames after `pair_attach`. All payload data is encrypted as MLS application messages inside the device ring before being handed to the pair WS.
- **Tokens are never logged**: attach tokens are treated as credentials and omitted from relay logs at all severity levels.
- **Byte metrics are aggregated**: per-session byte counts are tracked internally for cap enforcement but exposed only as relay-wide totals in `/metrics`, never per-session.
- **TLS + MLS**: Drawbridge TLS protects against network observers; the device ring MLS session provides end-to-end confidentiality and mutual authentication between devices, protecting against the relay operator.

## Multi-device

A user may run Moat on multiple devices simultaneously. Each device has one MLS signing key, a stealth keypair, and a tag derivation stream, but they all share the same ATProto DID. The sections below describe how devices discover each other, establish shared encrypted channels, and coordinate without exposing the multi-device relationship to outside observers.

### Signing-key Identity

A device has exactly **one** signing key, generated at first login and stored at `~/.moat/keys/identity.key`. Every KeyPackage that device ever offers carries it — across both lanes:

| Lane | KeyPackage published to | Consumed by |
|---|---|---|
| Public pool | `social.moat.keyPackage` on the PDS (public) | Another user inviting us to a conversation, or a sibling opening a coord group / adding us to a ring |
| Same-user KP lane | `CoordMsg::KpBatch` over stealth to one sibling | That sibling, to fan us into a conversation |

Only the init and encryption keys are fresh per KeyPackage, which is what keeps every KeyPackage single-use and keeps two concurrent consumers from claiming the same one.

Reusing the signing key is required, not an optimization. A leaf's signing key is the key its device must sign with to author into that group, and a device only holds one. If a KeyPackage carried a throwaway signing key, the leaf created from it would be unusable: the device could join and decrypt, but every message it tried to send in that group would fail leaf lookup. Because the same-user lane is stealth-addressed to a single sibling and never public, sharing the key with the public pool adds no linkable public metadata.

### Device Ring

The device ring is a hidden N-party MLS group that spans all devices registered under the same DID. It serves as the shared encrypted coordination channel for sync signals and future history transfer.

- **Group ID**: 32 random bytes generated by the creating device. The ID is not derived from the DID so that independent ring creations produce distinct MLS groups, making split-brain an application-layer problem.
- **GroupKind tagging**: every MLS group is tagged locally with one of `{ User, Ring, DeviceCoord }` in group metadata. `list_conversations` filters to `User` only, so the ring and all coordination groups are invisible to the UI and to the beacon test's `list_conversations` assertion.
- **Created once**: the ring is not created until at least two sibling devices have exchanged a `Hello` coordination message. A DID with a single active device has no ring.
- **Lifecycle**: the ring is kept indefinitely. Device removal (future feature) issues an MLS Remove commit on the ring and all user conversations.

### Device Coordination Groups

For every pair of sibling devices, a hidden pairwise MLS group (`GroupKind::DeviceCoord`) is created on first discovery and kept indefinitely. Coordination groups serve as the reliable out-of-band bootstrap channel and survive arbitrary offline windows because the creator's Welcome is published as a stealth event on the PDS and persists until the sibling polls.

**Bootstrap sequence:**

1. Device `D_new` publishes a key package on its PDS.
2. On the next `ring_tick`, `D_new` fetches all key packages under its DID and discovers sibling devices `D1, D2, …` it has no coord group with yet.
3. For each new sibling, `D_new` draws that sibling's newest unburned pool record (see [Bootstrap: drawing from the public pool](#bootstrap-drawing-from-the-public-pool)), calls `create_device_coord_group`, stealth-encrypts the Welcome (same stealth scheme as regular conversation invites), and publishes it to its own PDS with a random tag. This is the first of the two draws `D_new` makes against each sibling; the ring `add_device` is the second. Coord-group creation is always driven by the onboarding device: a device already in a ring never initiates one, because every member sees the identical pool and would race for the same record. Members record the new sibling as discovered and wait for its Welcome, then reply with `Hello` + `RingInfo`.
4. `D_new` sends `CoordMsg::Hello` as an MLS application message in each new coord group (queued until the sibling joins).
5. When the sibling polls its own PDS (`ring_tick` always includes the device's own DID in the polling set), it stealth-decrypts the coord Welcome, joins the coord group, sends its own `CoordMsg::Hello` back, and replenishes its key package.
6. On the creator's next `ring_tick`, it processes the sibling's commit (joining the group) and the Hello, making the sibling "exchanged" in the driver's state.
7. Ring creation or addition proceeds as described in the Ring Bootstrap section of MULTI_DEVICE.md.

**Classification rule**: a group is `DeviceCoord` iff all its members carry `my_did` in their MLS credential and its group ID does not equal `ring_group_id`. The check is done via `classify_group_kind` in `moat-core`.

### Coordination Messages

Coordination messages are MLS application messages sent over `DeviceCoord` groups. They use `EventKind::Coord` with a JSON payload. All variants are designed to fit within the 256 B (512 B bucket) padding budget.

```json
{ "type": "hello", "sender_device_id": "<base64-16-bytes>" }

{ "type": "ring_info", "ring_id": "<base64>", "generation": 2, "created_at": 1234567890 }

{ "type": "supersede", "old_ring_id": "<base64>" }

{ "type": "ring_welcome", "ring_id": "<base64>", "welcome": "<base64-MLS-Welcome>", "generation": 2, "created_at": 1234567890 }

{ "type": "sync_offer", "token": "<base64-32-bytes>", "target_device_id": "<base64-16-bytes>" }
```

| Variant | Sender | Purpose |
|---------|--------|---------|
| `hello` | coord group creator AND coord group joiner | Signals presence so each side can detect `Hello` exchange |
| `ring_info` | ring member | Informs a sibling that a ring already exists, and at which generation. Emitted alongside every `Hello`. A device that learns of an existing ring it is not in creates the next generation rather than a competing one at the same level |
| `supersede` | losing ring member | Tells the recipient to abandon an old ring during split-brain recovery |
| `ring_welcome` | ring creator/adder | Delivers the MLS ring Welcome inline so the recipient can classify the group as `Ring` without a separate `RingInfo` round-trip. A Welcome for a higher generation displaces the recipient's current ring |
| `sync_offer` | the smaller `device_id` of a pair | Carries the Drawbridge pairing token; `target_device_id` names the sole intended recipient and other ring members MUST ignore the offer |

Three further `CoordMsg` variants — `kp_batch`, `kp_request`, and `user_conv_welcome` — share this schema but travel the stealth lane as `sibling.msg` events; see [Same-user Key Distribution](#same-user-key-distribution). The handlers are transport-agnostic, which is why they share the enum.

**Choosing which device acts.** Two rules, each scoped to a single pair:

- **Sync offers**: within a pair, the device with the smaller `device_id` issues the offer. Both sides mark each other as owing one, so the tiebreak keeps a pair to a single session.
- **First-ring formation**: when no ring exists for the DID, the device with the smallest `device_id` among those that have exchanged `Hello` creates it.
- **Joining an existing ring**: the smallest-leaf member of the current ring adds the joiner to that ring; other members stand down. Only if no member acts does the onboarding device create the next generation itself.

**Commit tags are derived at the pre-add epoch.** Receivers scan for tags at the epoch they are currently on, and candidate tags cover the current and prior epochs. Deriving the tag before the MLS add is what keeps the resulting commit findable by the members who still need to process it.

**Why `RingWelcome` instead of stealth delivery for ring Welcomes**: delivering the ring Welcome over the ordered coord channel means the recipient always has the `ring_id` available at processing time, enabling correct `GroupKind::Ring` classification. Stealth delivery would arrive in an unordered namespace and could be processed before the recipient knows which group ID is the ring.

### Same-user Key Distribution

Adding a sibling device to the ring, and later to every existing user conversation, requires a fresh MLS KeyPackage from that sibling for each add — and each KeyPackage must have exactly one consumer, since MLS burns the init secret on the first successful `process_welcome` and any second Welcome against it is permanently undeliverable.

Two lanes exist:

| Scope | Transport | KeyPackage source |
|---|---|---|
| Cross-user (bob ↔ alice) | Stealth event under a random tag | Public `social.moat.keyPackage` pool |
| Same-user bootstrap (opening a coord group, joining a ring) | Stealth event under a random tag | Public `social.moat.keyPackage` pool |
| Same-user steady state (fanning a sibling into conversations) | Stealth event addressed to one sibling | Consumer-held pool, refilled via `kp_batch` |

Bootstrap has no lane of its own. Before two sibling devices share a ring there is no authenticated channel between them, so the only KeyPackage source available is the same public pool a cross-user inviter reads. Once they do share a ring, the steady-state lane takes over and gives each KeyPackage a single named consumer.

#### Why the stealth lane carries this traffic

Every message in this lane is **unicast** — addressed to one sibling, dropped by everyone else — and its payloads need no MLS confidentiality: KeyPackages are public values, and MLS Welcomes are already encrypted to the target's init key. What the lane needs is addressing, authenticity, and single-use accounting, and the stealth transport supplies all three while remaining epoch-free and order-insensitive. Order-insensitivity is the decisive property here: ring epochs churn precisely when key-package traffic peaks, since a join triggers an Add commit immediately followed by fan-out in both directions.

The ring's own roles are device-set membership, the trust root mapping `device_id → signature key` for siblings, the session layer for bulk history sync over the live ordered pair WebSocket, and loss-tolerant broadcast state sync.

#### Bootstrap: drawing from the public pool

When a device first comes online and discovers siblings, it reads the public `social.moat.keyPackage` pool under its own DID. Two rules govern every draw:

1. **Take the newest record for that device.** The pool accumulates — records are created with `createRecord` and never deleted, because a `deleteRecord` shortly after would be a distinctive firehose pattern. A spent record therefore stays visible next to its replacement, and nothing on the wire distinguishes them. Older records are the likely-spent ones.
2. **Skip records this device has already burned.** A device needs *two* KeyPackages from each sibling during bootstrap — one to open the pairwise coord group, one for the ring `add_device` — and rule 1 alone would hand back the record the first draw killed. Implementations MUST persist the burned set (`used_pool_kps`, keyed by a hash of the record bytes); losing it across a restart re-creates exactly this failure.

A draw that finds nothing usable is an ordinary wait, not an error: the owner replenishes on every consumption, including on processing the coord Welcome, so a fresh record normally lands within a tick or two and the caller retries.

Neither rule makes **concurrent** draws by different devices safe, and no local rule can: two readers see the identical pool and select the identical record, so only one of the resulting Welcomes is processable and the other fails permanently and silently. Two different mechanisms keep draws serialised:

- **Coord-group creation**: only the onboarding device draws. A device already in a ring never initiates a coord group with a new sibling, so there is no race to arbitrate.
- **Ring `add_device`**: the smallest-leaf ring member is elected. Here the race cannot be designed away — an established member reaches the add path for an onboarding peer over the coord group that peer created, and a ring creator legitimately adds late-arriving peers — so multiple potential adders genuinely coexist and one is chosen.

Before any ring exists neither applies, and the symmetric two-device race resolves by ring reconciliation instead.

#### Steady state

Once a sibling is in the ring, key packages flow as `sibling.msg` events carrying `CoordMsg` JSON, addressed per sibling via the `scan_pubkey` from its `stealthAddress` record. Ring membership still gates the lane: batches are only shipped to and accepted from confirmed ring members.

```json
{
  "type": "kp_batch",
  "recipient_device_id": "<base64-16-bytes>",
  "kps": [ { "rkey": "<base64-16-bytes>", "seq": 12, "key_package": "<base64>" } ]
}

{ "type": "kp_request", "owner_device_id": "<base64-16-bytes>", "count": 8 }

{
  "type": "user_conv_welcome",
  "owner_device_id": "<base64-16-bytes>",
  "group_id": "<base64>",
  "welcome": "<base64-MLS-Welcome>"
}
```

| Variant | Sender | Purpose |
|---|---|---|
| `kp_batch` | Owner of the KeyPackages | Pushes fresh key packages with monotonic per-owner sequence numbers to one sibling |
| `kp_request` | Consumer | Asks the owner to top up the consumer's pool when it runs low |
| `user_conv_welcome` | Consumer | Delivers a Welcome built from a pool KeyPackage, addressed to that KeyPackage's owner |

**Pool maintenance.** Each consumer keeps a pool per owner, targeting `KP_POOL_TARGET` = 8 entries and refilling when it drops to `KP_POOL_LOW_WATER` = 2. A single `kp_batch` carries at most `KP_BATCH_CAP` = 4 entries so it fits the 4 KB control bucket; larger refills split across several messages. Refill is consumer-driven only — there is no owner-side wake-up top-up and no pre-emptive high-water trigger, because user-visible latency is dominated by MLS Add work and PDS propagation, not by refill.

**Consumer-side state**, per `(consumer, owner)` pair:

| Field | Purpose |
|---|---|
| `local_pool` | KeyPackages received but not yet consumed |
| `highest_seq_observed` | Replay defence for `kp_batch` |
| `used_kps` | Set of seqs already consumed — single-use enforcement |

`used_kps` is the irreducible piece of state. Even if a buggy refill, a malicious replay, or out-of-order delivery reinserts an already-used KeyPackage into the pool, the consumer refuses to claim it again. It is a full set of consumed `seq` values, so the invariant holds under any consumption order. It grows monotonically and slowly — roughly 80 KB per pair after 10k consumptions.

**Owner-side counter discipline.** The owner assigns `seq` strictly monotonically across *all* recipients (one global counter per owner), never reuses a value, and persists the counter alongside ring state. Gaps in any single consumer's view are harmless — dedupe only needs `seq <= highest_seq_observed` to reject replays.

**Fan-out.** To add an owner to a conversation, the consumer claims one unused KeyPackage from its pool, marks its `seq` used, derives the commit tag at the *current* epoch, calls `add_device`, publishes the Commit under that tag (so cross-user members see it), and sends the Welcome as a `user_conv_welcome` sibling message. If the pool is empty the add is deferred and one `kp_request` is emitted per sibling per cycle; the next poll retries once a batch arrives.

**Authenticity.** The ring provides sender authentication for free; the stealth lane does not. Two anchors replace it. First, the own-PDS scan reads only the user's *own* repo, so injecting a forged sibling message requires repo write authority — the same trust boundary bootstrap already assumes. Second, on `kp_batch` ingest the consumer MUST verify each KeyPackage's signature against the signature key it holds for that `device_id` from the ring leaf credential. A forged `kp_request` is at most a top-up nuisance, and a forged `user_conv_welcome` cannot be built without the pool KeyPackage's public init key, which only ever travels inside a stealth-encrypted batch.

**Delivery properties.** Decryption is a single ECDH against the recipient's scan key: no epoch binding, no ordering requirement, no mark-own bookkeeping (one's own publishes simply fail to trial-decrypt). Duplicates and replays are absorbed by `highest_seq_observed`, `used_kps`, and MLS's own consume-once init-key semantics.

### Ring Generations and Reconciliation

Rings carry a monotonic `generation`. A device forming the first ring for a DID uses generation 1. A device joining a DID that already has a ring *can* create generation `N+1` containing every sibling it knows of and invite them — it is the only participant guaranteed to be online, which is what lets onboarding complete while an existing device is asleep or permanently lost. It does so only after waiting for an established member to add it first (see [Ring Generations and Reconciliation](#ring-generations-and-reconciliation) on which path is normal).

Reconciliation, whether from a `RingInfo` exchange or an incoming `RingWelcome`, applies the same ordering:

- **Highest generation wins.**
- **Tiebreaker**: equal generations are broken by the earlier `created_at` (Unix timestamp, milliseconds), then by the lexicographically smallest `ring_id`. This is the case of two devices independently forming a *first* ring after a partition.
- **`Supersede`**: a device on a losing ring receives `CoordMsg::Supersede { old_ring_id }`, drops that ring's MLS state locally, and joins the winning ring. A `RingWelcome` for a superseding generation displaces the current ring directly; one for a lower generation is ignored.
- **`generation` / `created_at` propagation**: set at ring-creation time, persisted alongside `ring_group_id`, and carried in both `CoordMsg::RingInfo` and `CoordMsg::RingWelcome`.

Supersession is the **recovery** path, not the normal one. In the ordinary case — an existing ring member online and responsive — that member adds the joiner to the current generation and no new generation is formed at all; the joiner waits. Generation N+1 is created by the joiner only when no established member acts, which is exactly the case where the device that would have added it is asleep or permanently gone. If the member is merely slow, both can happen and the two rings are reconciled by the ordering above.

A device that stops responding leaves its leaf in an abandoned ring, and the next generation forms without it.

### Own-PDS Stealth Scan

Every `ring_tick` call polls the device's own PDS for stealth-encrypted events (in addition to the normal per-conversation polling of contacts' PDS records). This is the mechanism by which:

- Coord group Welcomes (published by a sibling discovering this device) are found and joined.
- `sibling.msg` events (`kp_batch` / `kp_request` / `user_conv_welcome`) are found.
- The device's own DID is always included in the polling set, even when the device has no user conversations.

All of these carry random tags (same as stealth invite tags in regular conversation flow) and are identified by attempting stealth decryption, then dispatching on the decrypted event's `kind`. Because a device's own publishes do not trial-decrypt as its own, no mark-own bookkeeping is needed on this path. Successfully decrypted coord Welcomes are processed, the joining device sends `CoordMsg::Hello`, and key packages are replenished immediately to avoid exhaustion on the next cycle.

The scan is cursor-based (`own_events_cursor`, an rkey), so events are fetched incrementally rather than re-scanned. Delivery here is order-insensitive by construction: a `sibling.msg` arriving before or after unrelated ring commits decrypts identically.

Ring Welcomes are delivered via `CoordMsg::RingWelcome` over the coord channel, not via the stealth scan. This ensures the `ring_id` is present at processing time.

## Transcript Integrity

MLS provides confidentiality and authenticity for individual messages, but the PDS (as an untrusted relay) can still withhold, reorder, or replay events without detection by MLS alone. Moat adds two mechanisms on top of MLS to detect these attacks:

### Per-Device Hash Chains

Each device maintains a hash chain for its outgoing messages. Before encrypting, the sender sets:

- `sender_device_id` — the sender's 16-byte device ID (inside the encryption boundary, invisible to PDS)
- `prev_event_hash` — SHA-256 hash of the sender's previous serialized event (`None` for the first event)

After serialization, the sender computes `SHA-256(event_bytes)` and stores it for the next message.

On the receiving side, the recipient maintains a map `(group_id, sender_device_id) → last_hash` and validates that each incoming event's `prev_event_hash` matches the stored hash. Mismatches produce a `HashChainMismatch` warning. Duplicate hashes produce a `ReplayDetected` warning.

Hash chains are keyed per-device (not per-user), so multiple devices from the same DID maintain independent chains.

### Epoch Fingerprints

Each encrypted event includes an `epoch_fingerprint` — 16 bytes derived via MLS `export_secret("moat-epoch-fingerprint-v1", &[], 16)`. Since `export_secret` is deterministic for all members sharing the same epoch state, the recipient can independently derive the fingerprint and compare. A mismatch (`EpochFingerprintMismatch` warning) indicates that the sender and receiver have diverged MLS state — evidence of a fork or state manipulation.

### Backward Compatibility

All transcript integrity fields (`prev_event_hash`, `epoch_fingerprint`, `sender_device_id`) are optional with `#[serde(default)]`. Events from older clients that lack these fields are processed normally without triggering validation.

### Multi-Device Commit Conflict Recovery

When two devices create commits concurrently at the same epoch, only one commit can be applied — the other becomes stale. Moat detects this scenario and automatically recovers:

1. Each commit-producing operation (add member, remove member, kick user, leave group) records a `PendingOperation` in memory before merging.
2. When `decrypt_event` receives a remote commit that conflicts with a local pending operation, it discards the local commit, merges the remote one, and retries the pending operation at the new epoch (up to 2 retries).
3. Successful recovery produces a `ConflictRecovered` warning so callers can notify the user.
4. If retries are exhausted, the pending operation is dropped.

### State Format

Session state uses a versioned binary format (currently version 5):

```
[4 bytes: "MOAT" magic]
[2 bytes: version (LE u16, currently 5)]
[16 bytes: device_id]
[8 bytes: mls_state_length]
[variable: MLS provider state]
[variable: hash chain state]         — v3+
[variable: tag counter state]        — v3+
[variable: seen counter state]       — v3+
[variable: prior export secrets]     — v4+
[variable: conversation digest state] — v5+
[variable: watermark state]          — v5+
[variable: inbox range state]        — v5+
```

Hash chain state:
```
[8 bytes: entry_count]
For each entry:
  [4 bytes: group_id_length]
  [variable: group_id]
  [16 bytes: device_id]
  [32 bytes: last_event_hash (SHA-256)]
```

Tag counter state (sender-side outgoing counters):
```
[8 bytes: entry_count]
For each entry:
  [4 bytes: group_id_length]
  [variable: group_id]
  [8 bytes: epoch (LE u64)]
  [8 bytes: counter (LE u64)]
```

Seen counter state (recipient-side scanning window):
```
[8 bytes: entry_count]
For each entry:
  [4 bytes: group_id_length]
  [variable: group_id]
  [4 bytes: sender_did_length]
  [variable: sender_did (UTF-8)]
  [16 bytes: sender_device_id]
  [8 bytes: counter (LE u64)]
```

Conversation digest state (v5):
```
[8 bytes: entry_count]
For each entry:
  [4 bytes: group_id_length]
  [variable: group_id]
  [32 bytes: tip_digest]
  [8 bytes: append_count (LE u64)]
  [4 bytes: anchor_count (LE u32)]
  For each anchor:
    [2 bytes: rkey_len (LE u16)]
    [rkey_len bytes: rkey (UTF-8)]
    [32 bytes: anchor_digest]
```

Watermark state (v5) — oldest synced rkey per conversation:
```
[8 bytes: entry_count]
For each entry:
  [4 bytes: group_id_length]
  [variable: group_id]
  [2 bytes: rkey_len (LE u16)]
  [rkey_len bytes: rkey (UTF-8)]
```

Inbox range state (v5) — local (oldest, newest) rkey range per conversation:
```
[8 bytes: entry_count]
For each entry:
  [4 bytes: group_id_length]
  [variable: group_id]
  [2 bytes: oldest_len (LE u16)]
  [oldest_len bytes: oldest_rkey (UTF-8)]
  [2 bytes: newest_len (LE u16)]
  [newest_len bytes: newest_rkey (UTF-8)]
```

Versions 1 and 2 are rejected with a `StateVersionMismatch` error. Older v3/v4 states load with empty v5 tables.

### Conversation Digest

Each device maintains a running SHA-256 digest chain per user conversation for efficient sync comparison with sibling devices.

**Chain formula:**
```
digest_0 = 0x00...00  (32 zero bytes)
digest_n = SHA256(digest_{n-1} || rkey_n || message_id_n)
```

Only events whose kind starts with `message.` (user-visible content) contribute to the digest. Control events (commits, welcomes) and reaction modifiers are excluded.

**Anchors:** A `DigestAnchor { rkey, digest }` is saved every `DIGEST_ANCHOR_STRIDE = 64` appended messages and immediately after the first append in a new MLS epoch. Per-group anchor lists are capped at 256 entries (oldest dropped on overflow). Anchors allow fast bisection when comparing two devices' histories without a full message scan.

**`diff_anchors(ours, theirs) -> DiffRange`:** Compares two anchor lists pairwise from the start and returns:
- `common_prefix_rkey` — `rkey` of the last matching anchor (`None` if no common prefix)
- `our_tail` — anchors we hold beyond the common prefix
- `their_tail` — anchors they hold beyond the common prefix

**Watermark:** A per-conversation `watermark` is the `rkey` of the oldest message successfully received from a sync peer. On reconnect, the peer resumes transfer from the watermark rather than restarting.

**Inbox range:** `(oldest_rkey, newest_rkey)` tracks the local history span per conversation. Updated on every `append_to_digest` call.

## Local Storage

All private material stays on the device, never on the PDS:

```
~/.moat/
├── mls.bin              # MLS group state (all groups, all epochs)
└── keys/
    ├── credentials.json # ATProto session tokens
    ├── identity.key     # MLS signing key bundle (one per device, reused by every KeyPackage)
    ├── stealth.key      # X25519 stealth private key
    ├── ring.json        # Device ring state: peers, ring membership, KP pools, used_kps
    └── conversations/   # Per-group metadata and sent message history
```

`ring.json` holds the single-use accounting described in [Same-user Key Distribution](#same-user-key-distribution). Losing it does not compromise confidentiality, but it discards `used_kps` and `used_pool_kps`, so a device that restores an older copy can re-consume a key package it has already used and emit an undeliverable Welcome.

## What Goes Where

| Data | Location | Encrypted? |
|------|----------|-----------|
| MLS group state | Local filesystem | No (local trust boundary) |
| Private keys (signing, stealth) | Local filesystem | No |
| Device ring state (`ring.json`) | Local filesystem | No |
| Key packages (cross-user pool) | Owner's PDS | No (public by design) |
| Key packages (same-user steady-state lane) | Owner's PDS, inside a stealth event | Yes (stealth, addressed to one sibling) |
| Stealth addresses | Recipient's PDS | No (public key + device id) |
| Messages, commits, welcomes | Sender's PDS | Yes (MLS or stealth) |
