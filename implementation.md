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

**Phase 2: ATProto Client (mostly complete)**
- ✓ `publish_event(tag, ciphertext)` - publish encrypted events
- ✓ `fetch_events_from_did(did, cursor)` - fetch events with pagination
- ✓ `fetch_events_by_tag(did, tag)` - filter events by conversation tag
- ✓ `resolve_did(handle)` - handle-to-DID resolution
- ✓ `publish_key_package()` / `fetch_key_packages()` - key package CRUD

**Phase 2.5: Wire MoatSession to CLI ✓**
- ✓ `MoatSession` integrated into App struct with persistent storage at `~/.moat/mls.bin`
- ✓ `send_message()` uses MLS encryption via `encrypt_event()`
- ✓ `poll_messages()` fetches and decrypts incoming messages
- ✓ `start_new_conversation()` full flow: resolve handle → fetch key package → create group → publish welcome
- ✓ Welcome detection for incoming conversation invites
- ✓ Watch handle feature (`w` key) to receive invites from new contacts

**Phase 3: CLI Conversation Flows ✓**
- ✓ New conversation UI popup (press `n`, enter handle)
- ✓ Watch for invites UI popup (press `w`, enter handle)
- ✓ Message polling every 5 seconds
- ✓ Unread message count display
- ✓ Tag-based conversation routing

### Not Started

- Phase 4: Local Storage expansion (cursor-based pagination, offline sync)
- Phase 5: Privacy Hardening (stealth addresses, cover traffic)

---

## Architecture Overview

```
moat/
├── crates/
│   ├── moat-core/       # MLS logic with FileStorage persistence (complete)
│   ├── moat-atproto/    # ATProto client (complete)
│   └── moat-cli/        # Ratatui UI (needs MoatSession wiring)
└── lexicons/            # ATProto lexicon definitions
```

**Key principle:** MoatSession handles all MLS state persistence. CLI orchestrates MoatSession + ATProto client.

**Storage layout:**
```
~/.moat/
├── mls.bin              # MoatSession's FileStorage (MLS groups, keys)
└── keys/
    ├── credentials      # handle + app password
    ├── identity.key     # KeyBundle (for MLS operations)
    └── conversations/   # Metadata (participant handle, etc.)
```

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

## Phase 2: ATProto Integration ✓ MOSTLY COMPLETE

### Step 2.1: ATProto client methods ✓

All required methods already exist in `moat-atproto`:

```rust
impl MoatAtprotoClient {
    // Authentication
    pub async fn login(handle: &str, password: &str) -> Result<Self>;
    pub fn did(&self) -> &str;

    // Key packages
    pub async fn publish_key_package(&self, key_package: &[u8], ciphersuite: &str) -> Result<String>;
    pub async fn fetch_key_packages(&self, did: &str) -> Result<Vec<KeyPackageRecord>>;

    // Unified events
    pub async fn publish_event(&self, tag: &[u8; 16], ciphertext: &[u8]) -> Result<String>;
    pub async fn fetch_events_from_did(&self, did: &str, cursor: Option<&str>) -> Result<(Vec<EventRecord>, Option<String>)>;
    pub async fn fetch_events_by_tag(&self, did: &str, tag: &[u8; 16]) -> Result<Vec<EventRecord>>;

    // Discovery
    pub async fn resolve_did(&self, handle: &str) -> Result<String>;
}
```

### Step 2.2: Firehose filtering (deferred)

MVP will use simple polling instead of firehose subscription.

---

## Phase 2.5: Wire MoatSession to CLI

**Goal:** Replace stub implementations in moat-cli with actual MLS operations using MoatSession.

### Current State

The CLI has scaffolding but key functions are stubs:
- `app.rs:send_message()` - publishes padded plaintext, not MLS ciphertext
- `app.rs:start_new_conversation()` - just shows a status message
- `app.rs:load_messages()` - shows placeholder, doesn't fetch from PDS
- Uses `MoatCore` (stateless) instead of `MoatSession` (persistent)

### Step 2.5.1: Add MoatSession to App ✓

```rust
// In app.rs
pub struct App {
    pub keys: KeyStore,
    pub client: Option<MoatAtprotoClient>,
    pub mls: MoatSession,  // Added - non-optional, initialized on startup
    // ... rest unchanged
}
```

**Storage architecture decision:** MoatSession uses its own FileStorage at `~/.moat/mls.bin`. KeyStore continues to manage credentials and conversation metadata at `~/.moat/keys/`. This keeps MLS state (managed by OpenMLS) separate from app state.

**Implementation (completed):**
1. ✓ Create `MoatSession::new(~/.moat/mls.bin)` on app startup
2. ✓ Store key bundle in KeyStore after `generate_key_package()`
3. ✓ MLS groups persist automatically via MoatSession's FileStorage
4. ✓ Updated `do_login()` to use `MoatSession::generate_key_package()` instead of stateless `MoatCore`

### Step 2.5.2: Fix key generation flow ✓

Completed as part of Step 2.5.1. The `do_login()` now uses `MoatSession::generate_key_package()`:

```rust
// In do_login() - IMPLEMENTED
if !self.keys.has_identity_key() {
    let identity = client.did().as_bytes();
    let (key_package, key_bundle) = self.mls.generate_key_package(identity)?;

    // Store key bundle locally (needed for encryption)
    self.keys.store_identity_key(&key_bundle)?;

    // Publish key package to PDS
    client.publish_key_package(&key_package, &ciphersuite_name).await?;
}
```

### Step 2.5.3: Implement start_new_conversation() ✓

**Implementation (completed):**

1. ✓ Added `NewConversation` focus state to enable handle input mode
2. ✓ Added `new_conv_handle` field to `App` for input buffer
3. ✓ Added `GroupMetadata` type to `keystore.rs` with `store_group_metadata()`/`load_group_metadata()`
4. ✓ Implemented `handle_new_conversation_key()` for text input
5. ✓ Implemented full `start_new_conversation()` flow:
   - Resolve handle to DID
   - Fetch recipient's key package from PDS
   - Create MLS group
   - Add recipient, generate welcome
   - Encrypt and publish welcome event
   - Store conversation metadata locally
   - Update UI and register tag mapping
6. ✓ Updated `load_conversations()` to use metadata for display names

**UI Flow:**
- Press 'n' in Conversations view → enters NewConversation mode
- Type recipient handle → press Enter to start conversation
- Press Esc to cancel

### Step 2.5.4: Implement send_message() with MLS encryption ✓

**Implementation (completed):**

```rust
async fn send_message(&mut self) -> Result<()> {
    // Load key bundle and parse group_id from hex
    let key_bundle = self.keys.load_identity_key()?;
    let group_id = hex::decode(&conv.id)?;

    // Create and encrypt message event
    let event = Event::message(group_id.clone(), conv.current_epoch, self.input_buffer.as_bytes());
    let encrypted = self.mls.encrypt_event(&group_id, &key_bundle, &event)?;

    // Update stored group state and publish
    self.keys.store_group_state(&conv.id, &encrypted.new_group_state)?;
    client.publish_event(&encrypted.tag, &encrypted.ciphertext).await?;

    // Update tag mapping and display
    self.tag_map.insert(encrypted.tag, conv.id.clone());
    // ... add to messages display
}
```

### Step 2.5.5: Implement message polling ✓

**Implementation (completed):**

- Polls every 5 seconds via `tick()`
- Fetches events from all conversation participants
- Decrypts known-tag events and displays messages
- Attempts `process_welcome()` on unknown-tag events
- Tracks processed URIs to avoid duplicates (TODO: switch to cursor-based pagination)

### Step 2.5.6: Add "new conversation" UI prompt ✓

- Press `n` → `Focus::NewConversation` → popup with handle input
- Press `w` → `Focus::WatchHandle` → popup to watch for invites from a handle

### Step 2.5.7: Watch handle feature ✓

**Implementation (completed):**

Cold start problem: Bob can't receive invites from Alice if they've never talked (Bob isn't polling Alice's repo).

Solution: "Watch" a handle to poll their repo for welcomes:
- `watched_dids: HashSet<String>` tracks DIDs to poll for invites
- `poll_messages()` polls watched DIDs and tries `process_welcome()` on each event
- When a welcome is successfully processed, the DID moves from `watched_dids` to `conversations`

---

## Phase 3: CLI Conversation Flows ✓ COMPLETE

### Step 3.1: Incoming welcome detection ✓

Implemented in `poll_messages()` and `try_process_welcome()`:
- Unknown-tag events trigger `mls.process_welcome()` attempt
- Successful welcomes create new conversation entries
- Watch handle feature enables receiving invites from new contacts

### Step 3.2: UI polish (partial)

Implemented:
- ✓ Unread message count in conversation list
- ✓ Error popup for failed operations
- ✓ Status bar during network operations

Not yet implemented:
- Connection state indicator
- Loading spinner during network ops

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
3. ✓ **moat-atproto**: `publish_event`, `fetch_events_from_did`, `fetch_events_by_tag` (already existed)
4. ✓ **moat-cli**: Add `MoatSession` to App struct, initialize on startup
5. ✓ **moat-cli**: Wire `send_message()` to use MLS encryption
6. ✓ **moat-cli**: Implement `poll_messages()` with decryption
7. ✓ **moat-cli**: Implement `start_new_conversation()` with handle prompt UI
8. ✓ **moat-cli**: Add conversation metadata storage to KeyStore
9. ✓ **moat-cli**: Add watch handle feature for receiving invites from new contacts
10. **Test**: Two terminals, two accounts, exchange encrypted messages

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
