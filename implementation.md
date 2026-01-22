# Moat Implementation Plan

An encrypted group chat on ATProto using MLS, combining metadata obfuscation techniques with a clean Ratatui-based MVP architecture.

---

## Current State

### Completed ✓

**Phase 1: Core MLS Functionality**
- ✓ Unified `Event` type with `EventKind` enum (msg, commit, welcome, checkpoint)
- ✓ Rotating conversation tags via HKDF-SHA256 (`derive_tag_from_group_id`)
- ✓ Message padding to fixed buckets (256B, 1KB, 4KB)
- ✓ `FileStorage` implementing OpenMLS `StorageProvider` trait (~50 methods)
- ✓ `MoatProvider` combining `FileStorage` + `RustCrypto`
- ✓ `MoatSession` with persistent MLS operations:
  - `generate_key_package()` - generate and persist key packages
  - `create_group()` - create and persist MLS groups
  - `load_group()` - reload groups from storage
  - `add_member()` - add members, generate welcome/commit
  - `process_welcome()` - join groups via welcome message
  - `encrypt_event()` - encrypt with padding and tag derivation
  - `decrypt_event()` - decrypt and unpad events
- ✓ Full test coverage (38 tests) including two-party messaging

**Existing Infrastructure**
- ✓ Login flow with Bluesky handle + app password
- ✓ Key package publishing to PDS (`social.moat.keyPackage`)
- ✓ Ratatui UI structure with conversation list and message panes
- ✓ Local keystore at `~/.moat/keys/`

### In Progress

- Phase 2: ATProto Integration (wire up `MoatSession` to CLI)
- Phase 3: CLI Conversation Flows

### Not Started

- Phase 4: Local Storage expansion
- Phase 5: Privacy Hardening

---

## Architecture Overview

```
moat/
├── crates/
│   ├── moat-core/       # Pure MLS logic, no IO (exists, needs work)
│   ├── moat-atproto/    # PDS interaction (exists, needs expansion)
│   └── moat-cli/        # Ratatui UI (exists, needs conversation flows)
└── lexicons/            # JSON lexicon definitions (to be created)
```

**Key principle:** The Rust MLS core is pure—bytes in, bytes out, no storage or network. All IO happens in the CLI layer.

---

## Phase 1: Core MLS Functionality ✓ COMPLETE

### Step 1.1: Define the unified event lexicon ✓

Instead of separate collections for messages, commits, and state, use a **single unified record type** that hides event types from observers.

**Collection:** `social.moat.event`

**Plaintext fields (minimal):**
- `v`: int (schema version)
- `tag`: bytes (16 bytes, rotating per-epoch conversation tag)
- `createdAt`: datetime
- `nonce`: bytes (12-24 bytes, for dedup)

**Encrypted payload (inside MLS ciphertext):**
- `kind`: enum (`msg`, `commit`, `checkpoint`, `welcome`)
- `groupStableId`: internal identifier
- `epoch`: actual MLS epoch
- `senderDeviceId`: device identifier
- `payload`: the actual content

**Why unified?** Observers can't distinguish "Alice sent a message" from "Alice added a member"—they just see ciphertext blobs with opaque tags.

### Step 1.2: Implement rotating conversation tags ✓

Implemented in `moat-core/src/tag.rs`:

```rust
// Actual implementation
pub fn derive_tag_from_group_id(group_id: &[u8], epoch: u64) -> Result<[u8; 16]> {
    let hk = Hkdf::<Sha256>::new(Some(TAG_LABEL), group_id);
    let info = epoch.to_be_bytes();
    let mut tag = [0u8; 16];
    hk.expand(&info, &mut tag).expect("16 bytes is valid");
    Ok(tag)
}
```

**Client behavior:**
- Maintain a set of "active tags" for current + recent epochs of each group
- When a record arrives, check if its tag matches any known tag
- If match found, attempt MLS decrypt
- On successful decrypt, learn actual group/epoch from inside ciphertext

**Win:** Outsiders can't easily cluster messages into "this is all one conversation."

### Step 1.3: Implement message padding ✓

Implemented in `moat-core/src/padding.rs`:

| Bucket | Plaintext size |
|--------|----------------|
| Small  | 256 bytes      |
| Medium | 1 KB           |
| Large  | 4 KB           |

```rust
// Actual implementation uses length-prefixed padding with random fill
pub fn pad_to_bucket(plaintext: &[u8]) -> Vec<u8> {
    let bucket = Bucket::for_size(plaintext.len());
    let mut padded = vec![0u8; bucket.size()];
    // 4-byte length prefix + content + random padding
    padded[..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    padded[4..4 + plaintext.len()].copy_from_slice(plaintext);
    rand::thread_rng().fill_bytes(&mut padded[4 + plaintext.len()..]);
    padded
}
```

**Win:** Hides whether someone sent "ok" vs a paragraph.

### Step 1.4: Clean up moat-core API ✓

Implemented with `MoatSession` for stateful persistent operations:

```rust
// MoatSession holds a MoatProvider for persistent MLS state
pub struct MoatSession {
    provider: MoatProvider,  // FileStorage + RustCrypto
}

impl MoatSession {
    pub fn new(storage_path: PathBuf) -> Result<Self>;
    pub fn in_memory() -> Self;  // For testing

    // Key package generation (persisted)
    pub fn generate_key_package(&self, identity: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    // Group operations (persisted)
    pub fn create_group(&self, identity: &[u8], key_bundle: &[u8]) -> Result<Vec<u8>>;
    pub fn load_group(&self, group_id: &[u8]) -> Result<Option<MlsGroup>>;

    // Member management
    pub fn add_member(&self, group_id: &[u8], key_bundle: &[u8],
                      new_member_key_package: &[u8]) -> Result<WelcomeResult>;
    pub fn process_welcome(&self, welcome_bytes: &[u8]) -> Result<Vec<u8>>;

    // Messaging (with padding and tag derivation)
    pub fn encrypt_event(&self, group_id: &[u8], key_bundle: &[u8],
                         event: &Event) -> Result<EncryptResult>;
    pub fn decrypt_event(&self, group_id: &[u8], ciphertext: &[u8]) -> Result<DecryptResult>;
}

// MoatCore still exists for stateless utility operations
pub struct MoatCore;
impl MoatCore {
    pub fn get_epoch(group_state: &[u8]) -> Result<u64>;
    pub fn get_group_id(group_state: &[u8]) -> Result<Vec<u8>>;
    pub fn get_current_tag(group_state: &[u8]) -> Result<[u8; 16]>;
    pub fn get_tags_for_epochs(group_state: &[u8], epochs: &[u64]) -> Result<Vec<[u8; 16]>>;
}
```

---

## Phase 2: ATProto Integration

### Step 2.1: Expand moat-atproto client

Add methods for the unified event model:

```rust
impl MoatAtprotoClient {
    // Existing
    pub async fn login(handle: &str, password: &str) -> Result<Self>;
    pub async fn publish_key_package(&self, key_package: &[u8]) -> Result<()>;
    pub async fn fetch_key_package(&self, did: &str) -> Result<Vec<u8>>;

    // New: unified events
    pub async fn publish_event(&self, tag: &[u8], ciphertext: &[u8]) -> Result<RecordUri>;
    pub async fn fetch_events_by_author(&self, did: &str, since: Option<Timestamp>) -> Result<Vec<EventRecord>>;

    // Group state (public parts, stored in user's repo)
    pub async fn publish_group_state(&self, conv_id: &str, state: &[u8]) -> Result<()>;
    pub async fn fetch_group_state(&self, conv_id: &str) -> Result<Vec<u8>>;

    // Discovery
    pub async fn resolve_handle(&self, handle: &str) -> Result<Did>;
}
```

### Step 2.2: Implement firehose filtering

For real-time message receipt, subscribe to relay firehose and filter:

```rust
pub async fn subscribe_to_events(
    relay_url: &str,
    watched_dids: &[Did],
    active_tags: &HashSet<Tag>,
) -> impl Stream<Item = EventRecord> {
    // Connect to com.atproto.sync.subscribeRepos
    // Filter commits for collection: social.moat.event
    // Filter by author DID
    // Yield matching records
}
```

**MVP alternative:** Simple polling of each participant's repo. Less efficient but simpler.

---

## Phase 3: CLI Conversation Flows

### Step 3.1: Start conversation flow

When user presses `n` and enters a handle:

1. Resolve handle to DID
2. Fetch recipient's key package from their PDS
3. `moat_core.create_group()` → initial state
4. `moat_core.create_welcome()` → welcome + commit
5. Create unified event with `kind: welcome`, publish to own repo
6. Store private key locally
7. Store group state to PDS
8. Add conversation to local list

### Step 3.2: Receive conversation flow

On poll/sync:

1. Fetch events from known contacts' repos (or firehose)
2. For each event, check if tag matches any known tag-set
3. If no match but we have a pending key package, try as welcome
4. On successful welcome processing, add new conversation
5. Store group state, update UI

### Step 3.3: Send message flow

When user types and presses Enter:

1. Load group state from local cache (backed by PDS)
2. Load private key from keystore
3. Create event: `{ kind: "msg", payload: padded_text, ... }`
4. `moat_core.encrypt_event()` → new state + tag + ciphertext
5. Publish event to own repo
6. Update local group state
7. Display message in UI

### Step 3.4: Receive message flow

On poll/firehose event:

1. Match tag against active tags
2. `moat_core.decrypt_event()` → event
3. Based on `kind`:
   - `msg`: Add to message list, display
   - `commit`: Process membership change, update state
   - `checkpoint`: Update cached state if newer
4. Update group state

### Step 3.5: Update Ratatui UI

Current layout (keep it):
```
┌─────────────────────────────────────────┐
│ Conversations          │ Messages       │
│ ────────────────────── │ ────────────── │
│ > alice.bsky.social    │ alice: hello   │
│   bob.bsky.social      │ you: hi there  │
│                        │                │
├─────────────────────────────────────────┤
│ > type message here...                  │
└─────────────────────────────────────────┘
```

Add:
- `n` to create new conversation (prompt for handle)
- Status bar showing connection state, last sync time
- Visual indicator for pending/unread messages

---

## Phase 4: Local Storage

### Step 4.1: Expand keystore

```rust
pub struct KeyStore {
    base_path: PathBuf,  // ~/.moat/keys/
}

impl KeyStore {
    // Existing
    pub fn store_credentials(&self, handle: &str, password: &str) -> Result<()>;
    pub fn load_credentials(&self) -> Result<(String, String)>;
    pub fn store_identity_key(&self, key: &[u8]) -> Result<()>;
    pub fn load_identity_key(&self) -> Result<Vec<u8>>;

    // New: per-conversation keys
    pub fn store_group_key(&self, group_id: &str, key: &[u8]) -> Result<()>;
    pub fn load_group_key(&self, group_id: &str) -> Result<Vec<u8>>;

    // Group state cache (mirrors PDS, for offline/fast access)
    pub fn cache_group_state(&self, group_id: &str, state: &[u8]) -> Result<()>;
    pub fn load_cached_group_state(&self, group_id: &str) -> Result<Vec<u8>>;

    // Conversation metadata
    pub fn list_groups(&self) -> Result<Vec<String>>;
    pub fn store_group_metadata(&self, group_id: &str, meta: &GroupMetadata) -> Result<()>;
}
```

File structure:
```
~/.moat/
├── keys/
│   ├── credentials        # handle\npassword
│   └── identity.key       # MLS identity private key
├── groups/
│   ├── {group_id}/
│   │   ├── private.key    # MLS group private key
│   │   ├── state.bin      # Cached group state
│   │   └── meta.json      # Participants, name, etc.
│   └── ...
└── sync/
    └── cursors.json       # Last-seen timestamps per DID
```

---

## Phase 5: Privacy Hardening (Post-MVP)

These can be added incrementally after basic functionality works:

### 5.1: Remove senderDeviceId from plaintext
Move into encrypted payload only.

### 5.2: Stealth addresses for invites
Instead of publishing welcomes that reveal "Alice invited Bob":
- Bob publishes a stealth meta-address
- Alice derives one-time conversation ID from it
- Only Bob can recognize invites to him

### 5.3: Cover traffic (optional, expensive)
Periodically publish dummy events indistinguishable from real ones.

---

## Build Order

1. ✓ **moat-core**: Implement `encrypt_event`/`decrypt_event` with tag derivation and padding
2. ✓ **moat-core**: Add tests for full group lifecycle (38 tests, including two-party messaging)
3. **moat-atproto**: Add `publish_event`, `fetch_events_by_author`
4. **moat-cli**: Implement "new conversation" flow (n key)
5. **moat-cli**: Implement message send flow
6. **moat-cli**: Implement polling/receive flow
7. **moat-cli**: Wire up UI updates
8. **Test**: Two terminals, two accounts, exchange encrypted messages

---

## First Milestone

Two terminals running moat, logged into different Bluesky accounts, successfully exchange one encrypted message. The message content is E2E encrypted, and the conversation tag rotates with each epoch.

---

## Privacy Guarantees (Be Honest)

**Protected:**
- Message content (MLS E2E encryption)
- Conversation identity from casual observers (rotating tags)
- Message length patterns (padding buckets)

**Not hidden:**
- Who is posting events (author DID is public in ATProto)
- Timing of activity
- That you're using moat (key packages are public)

**Caveat for users:**
> "Your messages are end-to-end encrypted. Who you're talking to is obscured from casual observers but visible to your PDS operator and anyone who can correlate your activity patterns."
