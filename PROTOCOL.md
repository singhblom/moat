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

1. Poll each contact's PDS for new `social.moat.event` records (cursor-based, using TID ordering). A DID watched for invites keeps a cursor separate from its conversation cursor: a watch fetch can read messages from a group whose Welcome has not arrived yet, and those must be fetched again once the device joins
2. For each group, generate candidate tags for all members using the scanning window (see [Tag Derivation](#tag-derivation))
3. Match the event's tag against candidate tags; on match, advance the seen counter for that sender
4. MLS-decrypt, unpad, deserialize the inner JSON event
5. If it's a commit, merge it to advance the local epoch and regenerate candidate tags
6. Park any event whose tag is not a candidate tag, under that tag: the commit that reaches its epoch, or its group's Welcome, may be fetched after it. Generating candidate tags (on joining, on a commit, on startup, or when the scanning window advances) moves the events parked under them back into the queue, which is processed in rkey order; an event is never attempted before its tag exists. Parked events are persisted before the cursors move past them. Events nothing wakes are dropped by storage bound only: beyond 1000 parked (oldest first) or after 24 hours (`moat_core::inbox`). A message dropped this way predates the device's membership and reaches it through history sync

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

The `GAP_LIMIT` (10) is the maximum number of consecutive missed events tolerated per sender device in the current epoch. When a tag matches an incoming event, the recipient calls `mark_tag_seen` to advance the seen counter, sliding the scanning window forward. On epoch change, seen counters are cleared (senders reset their counters per epoch) — including an epoch change the device made itself by committing, which it never processes from the PDS.

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
| `sync.app` | — | History-sync frames over the Drawbridge pair WebSocket, encrypted to the device ring. |
| `sibling.msg` | — | Steady-state same-user coordination addressed to one sibling. Payload is `CoordMsg` JSON (`kp_batch` / `kp_request` / `user_conv_welcome`); the sender's device id travels in `Event.sender_device_id`. Stealth-encrypted, not MLS-framed. `group_id` empty, `epoch` 0. |
| `ring.msg` | — | Same-user coordination broadcast to *every* sibling at once, as an MLS application message on the device ring and published to the PDS under a ring tag. Payload is `RingMsg` JSON (`sync_request`). The sender is authenticated by its MLS leaf credential, not declared in the payload. |

The two same-user lanes differ deliberately. `sibling.msg` is unicast, stealth-addressed, epoch-free and order-insensitive, which is what key-package traffic needs because it peaks exactly when ring epochs churn. `ring.msg` is the opposite trade: one publish reaches every sibling and MLS authenticates the sender, at the cost of being epoch-bound like any group message — so it carries only traffic that a device far enough behind may simply miss.

`sibling.msg` is the only event kind that is stealth-encrypted rather than MLS-framed, and the only one whose `group_id`/`epoch` carry no meaning. It is recognised by attempting stealth decryption during the [Own-PDS Stealth Scan](#own-pds-stealth-scan).

## Message Payloads & External Blobs

All binary fields in JSON payloads (byte arrays and fixed-length byte sequences) are encoded as standard base64 strings (RFC 4648). This applies to `Event` fields (`group_id`, `payload`, `message_id`, `prev_event_hash`, `epoch_fingerprint`, `sender_device_id`), `ReactionPayload.target_message_id`, `ExternalBlob` fields (`ciphertext_hash`, `content_hash`, `key`), `MediaMessage.preview_thumbhash`, and `MoatCredential.device_id`.

When `event.kind` starts with `message.`, the payload is a structured JSON object describing the user-visible content plus any off-chain pointer. Each payload carries:

- `group_id`, `epoch`, and transcript-integrity fields (same as other events),
- `message_id` (16 random bytes, stable anchor for reactions and pointer retargets). A sender retrying a failed send republishes under the same `message_id`, and the earlier attempt may also have landed, so receivers keep the first record with a given `message_id` and drop later ones,
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

- 512 B bucket: reactions and `short_text`.
- 1 KB bucket: `medium_text`, previews for long text, and all media previews.
- 4 KB control bucket: only for overflow control traffic (commit/welcome/checkpoint) that truly cannot fit in 1 KB.
- Algorithmic previews stay tiny: ThumbHash ≤ 64 B raw (≈ 88 Base64 chars) for media posters, waveform snippets ≤ 160 B raw, and `preview_text` capped ~240–440 ASCII chars depending on other fields.
- No cover traffic in MVP, but the envelope structure keeps ciphertexts indistinguishable until MLS decryption routes them to the proper conversation.

Bucketing rounds *up* to a fixed size, so 4 KB is a ceiling and not merely
the largest common case: a serialized event above 4092 bytes has no bucket
to round to. Padding it to something else would leak the exact length the
buckets exist to hide, so oversizing is an error, and the way to carry more
is an external blob with only the reference in the event — the shape
`message.long_text` and `message.image` already take.

Padding answers a question about *PDS records*: how long is the record an
observer can see. Frames that never become records do not inherit it.
Sync traffic on the pair WebSocket (`EventKind::SyncApp`) is framed with
the same 4-byte length prefix but no bucket, since the relay observes those
frame sizes either way and a 4 KB ceiling would cap a channel that carries
1 MiB. The length prefix is what both framings share, so the receiving side
unpads both without needing to tell them apart.

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
2. Both sides already share a token: it is carried in the pairing code the user scanned or typed (see [Live Pairing](#live-pairing)). The relay treats it as an opaque string.
3. On the main WS:
   - Offerer: `→ pair_offer{token}` / Relay: `→ pair_pending{token}`
   - Joiner: `→ pair_join{token}` / Relay: `→ pair_ready{token, pair_url}` (sent to both)
4. Each client opens a new WebSocket to `pair_url` (`wss://<relay>/pair`).
5. First frame on the pair WS (JSON): `pair_attach{token}`. No DID challenge — the token is the auth.
6. Once both sides have attached, relay sends `paired` on both pair WSes. From then on, only opaque binary frames flow; the relay forwards them verbatim.
7. Either side closing its pair WS ends the session. The relay first writes every frame it has already accepted for the surviving peer, then closes that peer's pair WS with a normal close, and sends `pair_closed{token, reason}` on the main WS. Error terminations (`byte_cap`, `ttl_expired`, `write_error`) close both sockets at once.

A client closing its pair WS after its last send MUST do so behind those sends, with a close handshake: the last frame before a close is often the one that confirms a transfer. Once its pair WS is open, a client treats the pair WS's own end as the close signal, not `pair_closed` — the main-WS notice travels on a different connection and can overtake frames still on the pair WS.

`pair_ready.pair_url` is derived per recipient from the address that recipient used to reach the relay, not from a single relay-wide value: two devices on the same relay may legitimately reach it at different addresses (an Android emulator via `10.0.2.2` while a desktop client uses `127.0.0.1`).

`pair_closed` carries the `token` of the session it refers to. A device pairs sequentially, and a close notice for round N-1 routinely arrives *after* round N has begun — it is emitted when the previous pair WS closes, which is part of normal completion. Clients MUST match the token against the session currently in flight and ignore non-matching notices; acting on a stale one tears down a healthy successor.

#### Wire Schemas

Main WS (client → relay):
```
{ "type": "pair_offer", "token": "<base64-16-bytes>" }
{ "type": "pair_join",  "token": "<base64-16-bytes>" }
```

Main WS (relay → client):
```
{ "type": "pair_pending", "token": "<base64-16-bytes>" }
{ "type": "pair_ready",   "token": "<base64-16-bytes>", "pair_url": "wss://<relay>/pair" }
{ "type": "pair_closed",  "token": "<base64-16-bytes>", "reason": "<peer_gone|byte_cap|ttl_expired|...>" }
```

Pair WS (client → relay, first frame only):
```
{ "type": "pair_attach", "token": "<base64-16-bytes>" }
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
| Token length | 16 bytes (`PAIRING_TOKEN_LEN`), base64 on the wire |
| Max attaches per token | 2 (offer + join) |
| Max frame size (pair WS) | 1 MiB |
| Max bytes per session | 256 MiB |
| Max bytes per connection per second | 8 MiB/s |

Exceeding the byte cap closes both pair WSes and delivers `pair_closed{reason:"byte_cap"}` on the main WS.

#### Security and Privacy

- **Tokens are capabilities**: a 32-byte random token is issued only over an authenticated main WS and is valid for two attaches within 5 minutes. The relay does not verify that both sides share the same DID — that trust comes from the MLS device ring session layered on top.
- **Content opacity**: the relay sees only opaque binary frames after `pair_attach`. Onboarding traffic is sealed under the pairing channel AEAD (see [Channel crypto](#channel-crypto)); traffic between already-established devices is encrypted as MLS application messages inside the device ring. Either way the relay holds no key.
- **Tokens are never logged**: attach tokens are treated as credentials and omitted from relay logs at all severity levels.
- **Byte metrics are aggregated**: per-session byte counts are tracked internally for cap enforcement but exposed only as relay-wide totals in `/metrics`, never per-session.
- **TLS + end-to-end**: Drawbridge TLS protects against network observers; the pairing AEAD (onboarding) or the device ring MLS session (established devices) provides end-to-end confidentiality against the relay operator.
- **Challenge binding**: the main-WS auth challenge is signed over the relay URL *as the client dialled it*. The relay reconstructs that string from `RELAY_PUBLIC_URL`, then proxy headers, then the request's own `Host` header — never a fixed relay-wide default, which would reject any client reaching the relay by another address.

## Multi-device

A user may run Moat on multiple devices simultaneously. Each device has one MLS signing key, a stealth keypair, and a tag derivation stream, but they all share the same ATProto DID. A device joins the set through an explicit, user-driven pairing — there is no asynchronous discovery or negotiation between devices — after which they share a hidden MLS group and coordinate over it without exposing the multi-device relationship to outside observers.

### Signing-key Identity

A device has exactly **one** signing key, generated at first login and stored at `~/.moat/keys/identity.key`. Every KeyPackage that device ever offers carries it — across both lanes:

| Lane | KeyPackage published to | Consumed by |
|---|---|---|
| Public pool | `social.moat.keyPackage` on the PDS (public) | Another user inviting us to a conversation |
| Same-user KP lane | `CoordMsg::KpBatch` over stealth to one sibling | That sibling, to fan us into a conversation |
| Pairing channel | `Enroll.ring_kp` / `Enroll.conv_kps`, handed over the pairing channel | The approving device, for the ring Add and conversation fan-out |

Only the init and encryption keys are fresh per KeyPackage, which is what keeps every KeyPackage single-use and keeps two concurrent consumers from claiming the same one.

Reusing the signing key is required, not an optimization. A leaf's signing key is the key its device must sign with to author into that group, and a device only holds one. If a KeyPackage carried a throwaway signing key, the leaf created from it would be unusable: the device could join and decrypt, but every message it tried to send in that group would fail leaf lookup. Because the same-user lane is stealth-addressed to a single sibling and never public, sharing the key with the public pool adds no linkable public metadata.

### Device Ring

The device ring is a hidden N-party MLS group spanning all devices registered under the same DID. It is the shared encrypted channel between a user's own devices, and the trust root mapping `device_id → signature key` for siblings.

- **Group ID**: 32 random bytes generated by the creating device — not derived from the DID.
- **GroupKind tagging**: every MLS group is tagged locally as `User` or `Ring` in group metadata. `list_conversations` filters to `User`, so the ring is invisible to the UI.
- **Created by the first pairing**: no ring exists while a DID has one device. The ring is created by the approving device inside `PairingSession::approve` (see [Live Pairing](#live-pairing)); every later device is added to that same ring by whichever device approves it.
- **Lifecycle**: kept indefinitely. Device removal (future feature) issues an MLS Remove commit on the ring and all user conversations.

Rings cannot compete. A ring only ever comes into existence through an approved pairing, and a device that pairs into an existing ring is *added* to it rather than forming its own — so there is no generation counter, no reconciliation ordering, and no supersession path. Concurrent commits on the single ring are the ordinary MLS case, handled by `PendingOperation` conflict recovery.

### Live Pairing

Onboarding a device is an explicit, user-driven act: the new device displays a code, the user enters it on a device already signed in, and that device approves. Both devices are in the user's hands at the same time, which is what lets the exchange be synchronous and authenticated without any prior shared channel.

#### The pairing code

The code carries exactly two secrets — everything else either side needs is already known or derivable.

| Field | Size | Purpose |
|---|---|---|
| version | 1 byte | `0x01`. A mismatch is rejected outright. |
| token | 16 bytes | Drawbridge rendezvous identifier |
| secret | 16 bytes | Channel key material (128-bit) |

The 33-byte payload is Crockford base32-encoded (alphabet excludes `I`, `L`, `O`, `U` to avoid visual confusion on manual entry) and hyphen-grouped in fives, giving a 53-character text form:

```
06PE7-8NC4X-FCFS2-YSPS9-TWK83-F24KB-B0QHR-RFKWT-47SVN-ZCSG0-GDG
```

The secret is 128-bit rather than a short human-memorable code because the AEAD frames transit the relay: a captured frame permits offline brute force of the secret, so its entropy sets the channel's security level directly. Shortening it to a 6–8 digit code would require replacing HKDF-of-the-secret with a PAKE.

The QR form is that same text behind a `moat-pair:` URI scheme, so a scanner can reject foreign QRs cheaply. Decoding is case-insensitive and ignores hyphens and whitespace, so a user retyping the text form need not reproduce the grouping.

The code deliberately carries **no DID and no relay URL**. Both devices already know their own DID — equality is verified inside the encrypted channel — and the relay is discoverable from that DID's PDS.

#### Channel crypto

Both directional keys derive from the code alone:

```
k_new_to_old = HKDF-SHA256(ikm = secret, salt = token, info = "moat-pair-v1 n2o")[0..16]
k_old_to_new = HKDF-SHA256(ikm = secret, salt = token, info = "moat-pair-v1 o2n")[0..16]
```

Frames are AES-128-GCM. The 12-byte nonce is four zero bytes followed by a 64-bit big-endian counter, maintained per direction; a counter value is never reused under the same key. Each side seals with its own direction's key and opens with the peer's, so a reflected frame fails to open. The receiver advances its counter only on a successful open, so a rejected frame does not desynchronise a legitimate retry.

The channel is **not** re-keyed to ring MLS once the exchange completes: the same AEAD carries the history sync that follows, continuing the same counter sequences. A newly-onboarded device has no ring-MLS traffic history to fall back on, and mixing two wire formats on one socket is the failure this avoids.

#### Session protocol

Two messages, JSON-encoded and then sealed whole:

| Message | Direction | Contents |
|---|---|---|
| `Enroll` | new → existing | `credential`, `stealth_scan_pubkey`, `ring_kp` (fresh KeyPackage for the ring Add), `conv_kps` (seeded pool for conversation fan-out) |
| `Admit` | existing → new | `ring_id`, `welcome`, `roster` |

The exchange:

1. Both devices attach to the pair WS (see [Pairing Mode](#pairing-mode-multi-device-history-sync)). The new device sends `Enroll`.
2. The existing device checks the DID in `Enroll.credential` against its own — a mismatch is a hard abort — and surfaces an approval prompt naming the device.
3. On approval it creates the ring (first pairing) or adds the joiner to the existing one, seeds the newcomer's KP pool from `conv_kps`, publishes the ring Add commit to the PDS, and sends `Admit`.
4. The new device processes the Welcome, then verifies that every member credential in the resulting ring carries its own DID — the only anchor available, since `Admit` carries no DID field. It persists ring membership.
5. Both sides hand the open channel to history sync, which completes on its own `Fin` exchange.

**Approval is always explicit.** No host auto-approves an incoming `Enroll` — not the TUI, not the headless HTTP servers used in testing. A session rests in its awaiting-approval state until a decision is made, and `reject` is a first-class outcome rather than a timeout.

**The ring Add commit is published to the PDS** under a tag derived at the *pre-add* epoch. A sibling that was asleep during the pairing picks that commit up on its next poll and advances its own view; deriving the tag after the add would tag it at an epoch no bystander is scanning for.

#### Roster

`Admit.roster` is `[approver] ++ known_siblings`, each entry carrying `device_id`, `device_name`, and `stealth_pubkey`. It seeds the newcomer's sibling-stealth table so it can address same-user traffic to every sibling from its first tick, without waiting to discover `stealthAddress` records.

Entries carry **no DID**. A same-user ring's DID is not roster data — it is an MLS-authenticated fact read from the ring's own member credentials once the Welcome is processed. A redundant unauthenticated copy would be a second, weaker source of the same truth.

#### Session state

A pairing session exposes one projection of its state, which every host renders and none re-derives:

| Phase | Meaning |
|---|---|
| `idle` | No pairing in flight |
| `showing_code` | New device: code generated, awaiting the peer (carries both text and URI forms) |
| `awaiting_peer` | Existing device: code accepted, awaiting `Enroll` |
| `awaiting_approval` | Existing device: `Enroll` received, awaiting the approve/reject decision (carries the peer's device name and DID) |
| `done` | Enroll/Admit complete (carries `ring_id`) |
| `failed` | Terminal failure, **carrying the reason** |

`failed` is retained on the session rather than discarded. A failed pairing must be distinguishable from a slow one — reporting "not done" forever with no reason is the behaviour this replaces. Terminal states are final: a stray reject or cancel arriving after `done` does not overwrite it.

### Requested Sync

Pairing hands a new device its history over the pairing channel, and that
covers a device's first moments only. A device already in the ring can
still be missing history: the sibling it paired with may not have held all
of it, a conversation may have reached it as a membership-only
`user_conv_welcome` after its pairing sync had finished, or a transfer may
have been cut short — and the pairing channel cannot be reopened, because
its secret is ephemeral by design.

Recovering that is an explicit gesture, shaped like pairing. There is no
election, no liveness detector, and no policy guessing which sibling holds
the deepest history: the person holding the devices decides.

1. The device that wants history mints a 16-byte rendezvous token,
   registers it with the relay (`pair_offer`), and publishes
   `RingMsg::SyncRequest { token, target_device_id }` as a `ring.msg`
   event on the device ring. Siblings watch the ring's tags with
   Drawbridge, so an online one sees it at once rather than on its next
   poll. `target_device_id` names one sibling when the user has picked a
   device to ask, and is absent for a broadcast. A sibling that is named but is not the
   target ignores the message rather than prompting about another device's
   business.
2. Every sibling that decrypts it prompts its user, naming the requesting
   device **from its MLS leaf credential** — the payload carries only the
   token. **No host auto-accepts**, matching pairing's rule.
3. Whichever sibling the user approves calls `pair_join` with the token
   and both ends run the ordinary history-sync session (below), encrypted
   to the ring: both are already members, so unlike onboarding there is no
   user-carried secret to derive a channel key from.

Declining is local and sends nothing. With several siblings prompted, one
refusal must not cancel the request — the requester keeps waiting for
another sibling, or for the token to expire.

The relay admits exactly two attaches per token, so if the user approves
on two devices the second `pair_join` is refused. That refusal is
ordinary, not a connection fault.

A request expires with the relay's own 5-minute token TTL, since a prompt
that outlived its token would offer a rendezvous nobody can join. Only the
*rendezvous* is bounded: once the channel is up the transfer runs to
completion however long it takes.

Expiry is a real transition to `failed`, not merely a fact about elapsed
time: a request nobody answers must say so rather than reporting "waiting"
forever. Nobody answering is the most likely way a request ends — the other
device is asleep, its app is closed, its user declined, or it was busy with
another sync — and the protocol deliberately does not distinguish those,
because the user's next move is the same for all of them. The session
carries no clock, so each host drives the check from its own polling tick
and from every read of the status.

A failure carries a **structured reason**, not a message:

| Reason | Meaning |
|---|---|
| `no_answer` | We asked; nobody joined the rendezvous before it expired |
| `request_expired` | We were prompted; the request expired before we answered |
| `declined` | This device's user refused a sibling's request |
| `channel_closed` | The pair channel dropped before the transfer finished |
| `publish_failed` | The request never reached the ring |

The same underlying event reads differently depending on which device is
looking at it — a rendezvous nobody joined is "no device answered" to the
device that asked and "this expired before you answered it" to the device
that was prompted — so the protocol carries the fact and each screen
supplies its own wording. `no_answer` and `request_expired` are the two
halves of one expiry, named for their reader. A device drives one sync session at a
time; a request arriving while one is in flight, or while a pairing is,
is ignored rather than allowed to supersede a decision the user is
already looking at.

Because the lane is `ring.msg`, a device that has fallen too far behind
the ring's epochs to send or read ring traffic cannot use this. Its
recourse is to pair again, which is a first-class affordance.

#### Offered Sync

A request asks the user to walk to the device that holds the history and
approve there. That is the wrong way round whenever the device already in
their hands is the one with the history.
`RingMsg::SyncOffer { token, target_device_id }` is the mirror: the user
picks another device to send to, the holder opens the rendezvous, and the
recipient joins it.

Both gestures are manual. Nothing publishes what a device holds and nothing
prompts on its own: the device that lacks history shows the gap, and the
user asks from it or sends from the device that has it.

The rule that keeps this from becoming an election is **exactly one human
approval per session, on the side that can judge**:

| Direction | Who approves | The other side |
|---|---|---|
| Request | the donor, who knows whether it has the history | the requester waits |
| Offer | the offerer, who has the history | the recipient joins without prompting |

The recipient does not prompt because there is nothing left to judge: the
offer comes from an authenticated ring member that can already read
everything it is about to send, so a second prompt would be asking the
user to approve receiving their own messages.

An offer is always targeted. The relay admits exactly two attaches per
token, so an untargeted offer would have every sibling race and the winner
would be arbitrary. Concurrent offers simply fail with the same refusal any
second attach gets, and the offerer learns through the answer deadline that
already exists — same person, same pocket.

A device drives one sync at a time, so an offer arriving while a sync or a
pairing is in flight is ignored rather than allowed to supersede a decision
the user is already looking at.

### History Sync

Both onboarding sync and requested sync run the same session. Each side
opens with a `Hello` declaring, per conversation, the rkeys it holds; each
then sends the peer exactly the complement. Both directions run in the one
session, so a laptop with deep old history and a phone with a recent week
converge on the union without either being designated donor.

The inventory is deliberately exact rather than clever. A span cannot
describe a hole in the *middle* of a device's history, which is the shape
a device ends up with after being offline past the point where it can
still decrypt what it missed. At roughly 13 bytes per rkey an inventory is
far cheaper than re-sending the messages it saves, so no digest comparison
or bisection is needed to decide what to transfer.

Each conversation declares one of three things, so that "I hold nothing"
and "I am not listing what I hold" can never be read as each other — they
call for opposite responses:

| Inventory | Meaning |
|---|---|
| `complete` | Every rkey held, enumerated; the peer sends exactly the complement |
| `range` | Only the span `(oldest, newest, count)`; the peer serves what falls outside it, and cannot see holes within |
| `empty` | Nothing held at all |

A synced message carries **everything a host persists about it** — text,
sender, timestamps, the blob reference including its ThumbHash placeholder,
and any emoji reactions. This is not a convenience: a field held on one
side and not carried is lost permanently on the other, because the events
that would rebuild it predate the receiving device's membership and are not
decryptable to it. Reactions in particular arrive as their own PDS events,
so for history moved by sync there is no second route by which they can
appear.

A `Hello` carries *every* conversation in one frame, against the pair WS's
hard 1 MiB limit — which closes the connection rather than truncating. The
byte budget is therefore spent across the whole message, not per
conversation: a per-conversation cap would let fifty ordinary
conversations exceed the frame with none of them individually large.
Inventories are downgraded `complete` → `range`, largest first, until the
total fits, so the fewest conversations lose precision and both sides make
the same deterministic choice from the same data.

Transfer is pulled: a side sends `BatchReq` per conversation it is
missing history for, the peer answers page by page, and ends each
conversation with `Done`. Every `Batch` states the `total` the sender will serve
for that conversation, so the receiver can show progress against a known
count from the first page on. Once every `Done` a side is waiting for has
arrived, it sends `Fin` — once per session — confirming that everything
owed to it was delivered. A side expecting nothing sends `Fin` straight
after the `Hello`.

A session is complete when a side has both sent and received `Fin`. The
peer's `Fin` follows the last `Done` it was waiting for, so it also
confirms this side's sends arrived; history the peer never asked for does
not hold the session open. Whichever side completes closes the pair WS,
behind its final sends. A channel that ends before `Fin` has been received
is a `channel_closed` failure on that side, however much was transferred —
without the peer's `Fin` there is no evidence its last frames arrived.

Two devices whose inventories already agree exchange nothing but `Fin`.

A finished session reports what it took: how many messages arrived, across
how many conversations, and which device served them. It also reports what
it served, confirmed by the peer's `Fin`, so the donor's report says what
it delivered rather than reading as "nothing new". This is not
decoration. With one donor per gesture, "nothing new — that device didn't
have more than you" is the outcome that tells the user to go and approve on
a *different* sibling, and without counts it is indistinguishable from a
transfer that moved everything. The donor is named from its MLS leaf
credential on the frames it sent, so the name is authenticated rather than
claimed. The counts are of what the peer *delivered*: the inventory diff
means it sent only the complement, so this matches what was stored except
where a `range` inventory forced it to serve across a span whose interior
it could not see.

An implementation that declares no inventory at all is interoperable: its
peer serves whole histories and rkey dedupe absorbs the overlap. That
fallback is what `rkeys: null` means on the wire.

#### History Ahead of Membership

A session plans for every conversation the peer declares and this side
does not, so a donor serves history for groups the requester has not been
added to yet. This is deliberate: when the fan-out `Add` arrives, the
history is already in place.

The receiving device registers such a conversation **read-only**. Its
messages are readable, but there is no local MLS group to encrypt into, so
the composer is replaced by "Waiting to be connected to this
conversation." Membership needs no separate flag — a conversation with no
local MLS state is exactly one this device has not joined. Participants are
inferred from the senders of the messages themselves, there being no group
to ask; they are replaced with the group's real membership when the `Add`
lands and the conversation stops being read-only.

The state is normally brief, because the device that served the history is
in the conversation and adds its siblings on its next ring tick. It is not
guaranteed to be brief: an MLS `Add` can only come from a member, so if the
donor was the group's only member and it goes offline immediately after the
transfer, nothing adds the requester until it returns. The wording is
chosen accordingly — it does not promise imminent resolution.

### Same-user Key Distribution

Adding a sibling device to a conversation requires a fresh MLS KeyPackage from that sibling for each add, and each KeyPackage must have exactly one consumer — MLS burns the init secret on the first successful `process_welcome`, and any second Welcome against it is permanently undeliverable.

| Scope | Transport | KeyPackage source |
|---|---|---|
| Cross-user (bob ↔ alice) | Stealth event under a random tag | Public `social.moat.keyPackage` pool |
| Same-user onboarding | Pairing channel | `Enroll.ring_kp` (ring Add) and `Enroll.conv_kps` (seed pool) |
| Same-user steady state | Stealth event addressed to one sibling | Consumer-held pool, refilled via `kp_batch` |

Onboarding needs no pool draw at all: the joining device mints its own KeyPackages and hands them over the authenticated pairing channel, to a single named consumer. This is what removes the concurrent-draw hazard that a shared public pool creates — two readers seeing the identical pool would select the identical record, and only one of the resulting Welcomes would be processable.

#### Why the stealth lane carries steady-state traffic

Every message in this lane is **unicast** — addressed to one sibling, dropped by everyone else — and its payloads need no MLS confidentiality: KeyPackages are public values, and MLS Welcomes are already encrypted to the target's init key. What the lane needs is addressing, authenticity, and single-use accounting, and the stealth transport supplies all three while remaining epoch-free and order-insensitive. Order-insensitivity is decisive: ring epochs churn precisely when key-package traffic peaks, since a join triggers an Add commit immediately followed by fan-out in both directions.

#### Steady state

Key packages flow as `sibling.msg` events carrying `CoordMsg` JSON, addressed per sibling via the `scan_pubkey` from its `stealthAddress` record. Ring membership gates the lane: batches are only shipped to and accepted from confirmed ring members.

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

**Pool maintenance.** Each consumer keeps a pool per owner, targeting `KP_POOL_TARGET` = 8 entries and refilling when it drops to `KP_POOL_LOW_WATER` = 2. A single `kp_batch` carries at most `KP_BATCH_CAP` = 4 entries so it fits the 4 KB control bucket; larger refills split across several messages. Refill is consumer-driven only — user-visible latency is dominated by MLS Add work and PDS propagation, not by refill.

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

### Own-PDS Stealth Scan

Every `ring_tick` polls the device's own PDS for stealth-encrypted events, in addition to the normal per-conversation polling of contacts' records. This is how `sibling.msg` events (`kp_batch` / `kp_request` / `user_conv_welcome`) are found. The device's own DID is always in the polling set, even with no user conversations.

These carry random tags, identical in form to stealth invite tags, and are identified by attempting stealth decryption and dispatching on the decrypted event's kind. A device's own publishes do not trial-decrypt as its own, so no mark-own bookkeeping is needed here.

The scan is cursor-based (`own_events_cursor`, an rkey), so events are fetched incrementally. Delivery is order-insensitive by construction: a `sibling.msg` arriving before or after unrelated ring commits decrypts identically.

Ring Welcomes do **not** travel this lane. They ride the pairing channel raw, inside `Admit`, where the `ring_id` is present at processing time and the group can be classified correctly on arrival.

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

### Retired v5 Tables

Two tables that v5 once carried are gone, and a state file written before
their removal simply ends with bytes nothing parses:

- A per-conversation **sync watermark** — the oldest rkey received from a
  peer — recorded as each batch landed, so an interrupted transfer would
  have a durable resume point. Nothing ever read it. The rkey inventory
  (see [History Sync](#history-sync)) resumes at the same granularity by
  declaring what the requester now holds, so a retry costs only the
  remainder either way.
- A running SHA-256 **digest chain** per conversation, with epoch-boundary
  anchors for bisecting two devices' histories. The inventory answers the
  same question exactly and more cheaply, so nothing consumed the digests.

Both were state every device maintained and none read.

## Local Storage

All private material stays on the device, never on the PDS:

```
~/.moat/
├── mls.bin              # MLS group state (all groups, all epochs)
└── keys/
    ├── credentials.json # ATProto session tokens
    ├── identity.key     # MLS signing key bundle (one per device, reused by every KeyPackage)
    ├── stealth.key      # X25519 stealth private key
    ├── ring.json        # Device ring state: ring membership, KP pools, used_kps, scan cursor
    └── conversations/   # Per-group metadata and sent message history
```

`ring.json` holds the single-use accounting described in [Same-user Key Distribution](#same-user-key-distribution). Losing it does not compromise confidentiality, but it discards `used_kps`, so a device that restores an older copy can re-consume a key package it has already used and emit an undeliverable Welcome.

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
