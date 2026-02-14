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
| `keyPackage` | MLS key distribution | TLS-serialized MLS KeyPackage + expiry |
| `stealthAddress` | Receiving invites privately | X25519 public key + device name |
| `event` | All encrypted payloads | 16-byte tag + ciphertext + timestamp |

Every event record looks identical — messages, commits, welcomes, and reactions all use the same `event` schema, hiding the operation type from observers.

## Sending a Message

1. Serialize the event to JSON: `{kind: "message", group_id, epoch, payload, message_id}`
2. Pad to a fixed bucket (256B, 1KB, or 4KB) with a 4-byte length prefix and random fill
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

**Setup (once per device):** Bob generates an X25519 stealth keypair and publishes the public key as a `stealthAddress` record on his PDS.

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
3. Process the MLS Welcome to join the group
4. Generate candidate tags for all group members and register them for future message routing

## Privacy Properties

| Mechanism | What it hides |
|-----------|--------------|
| **MLS encryption** | Message content, event type, group metadata |
| **Stealth addresses** | Invite recipient identity; fresh ephemeral keys make invites unlinkable |
| **Per-event unique tags** | Conversation identity — every event gets a unique tag, preventing clustering |
| **Padding** | Message length patterns (3 fixed buckets) |
| **Unified event schema** | Operation type — messages, commits, welcomes all look the same on-chain |

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

Recipients generate **candidate tags** for each group member's device using a scanning window:

```
for each member (did, device_id) in group:
    from = seen_counter[(group_id, did, device_id)] + 1   (or 0 if never seen)
    generate tags for counters [from, from + GAP_LIMIT)
```

The `GAP_LIMIT` (currently 5) is the maximum number of consecutive missed events tolerated per sender device per epoch. When a tag matches an incoming event, the recipient calls `mark_tag_seen` to advance the seen counter, sliding the scanning window forward.

The `seen_counters` map is persisted across sessions. The `tag_metadata` reverse lookup (tag → sender identity + counter) is ephemeral and rebuilt each polling cycle.

### Stealth Invites

Stealth invite tags are random (not derived) since the recipient doesn't yet know the group ID.

## Event Types (Inside Encryption)

| Kind | Payload | Purpose |
|------|---------|---------|
| `message` | UTF-8 text + 16-byte `message_id` | Chat messages |
| `commit` | TLS-serialized MLS Commit | Membership/key changes |
| `welcome` | TLS-serialized MLS Welcome | Group join (via stealth invite) |
| `checkpoint` | Serialized group state | Fast sync (not yet implemented) |
| `reaction` | `{emoji, target_message_id}` | Emoji reactions (toggle semantics) |

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

Session state uses a versioned binary format (currently version 3):

```
[4 bytes: "MOAT" magic]
[2 bytes: version (currently 3)]
[16 bytes: device_id]
[8 bytes: mls_state_length]
[variable: MLS provider state]
[variable: hash chain state]
[variable: tag counter state]
[variable: seen counter state]
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

Versions 1 and 2 are rejected with a `StateVersionMismatch` error.

## Local Storage

All private material stays on the device, never on the PDS:

```
~/.moat/
├── mls.bin              # MLS group state (all groups, all epochs)
└── keys/
    ├── credentials.json # ATProto session tokens
    ├── identity.key     # MLS signing key bundle
    ├── stealth.key      # X25519 stealth private key
    └── conversations/   # Per-group metadata and sent message history
```

## What Goes Where

| Data | Location | Encrypted? |
|------|----------|-----------|
| MLS group state | Local filesystem | No (local trust boundary) |
| Private keys (signing, stealth) | Local filesystem | No |
| Key packages | Sender's PDS | No (public by design) |
| Stealth addresses | Recipient's PDS | No (public key only) |
| Messages, commits, welcomes | Sender's PDS | Yes (MLS or stealth) |
