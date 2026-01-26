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
- ✓ Full test coverage (46 tests in moat-core) including two-party messaging

**Existing Infrastructure**
- ✓ Login flow with Bluesky handle + app password
- ✓ Key package publishing to PDS (`social.moat.keyPackage`)
- ✓ Ratatui UI structure with conversation list and message panes
- ✓ Local keystore at `~/.moat/keys/`

**Phase 2: ATProto Client ✓**
- ✓ `publish_event(tag, ciphertext)` - publish encrypted events
- ✓ `fetch_events_from_did(did, cursor)` - fetch events with pagination (cross-PDS via PLC directory)
- ✓ `fetch_events_by_tag(did, tag)` - filter events by conversation tag
- ✓ `resolve_did(handle)` - handle-to-DID resolution
- ✓ `resolve_handle(did)` - DID-to-handle resolution via PLC directory
- ✓ `publish_key_package()` / `fetch_key_packages()` - key package CRUD (cross-PDS)
- ✓ `fetch_stealth_address()` - cross-PDS stealth address lookup
- ✓ HTTP timeout (30s) to prevent hanging on network failures

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
- ✓ Tag registration on app startup (loads epoch from MLS group state)
- ✓ Duplicate conversation prevention (checks by participant DID)
- ✓ DID-to-handle resolution for conversation display names

**Phase 5: Stealth Addresses ✓**
- ✓ `moat-core/src/stealth.rs` with ECDH + HKDF + XChaCha20-Poly1305
- ✓ `generate_stealth_keypair()`, `encrypt_for_stealth()`, `try_decrypt_stealth()`
- ✓ 8 unit tests for stealth encryption
- ✓ `social.moat.stealthAddress` lexicon (singleton record)
- ✓ `publish_stealth_address()`, `fetch_stealth_address()` client methods
- ✓ KeyStore stealth key storage (`stealth.key`)
- ✓ `do_login()` generates and publishes stealth address on first login
- ✓ `start_new_conversation()` encrypts Welcome with stealth address
- ✓ `try_process_welcome()` uses stealth decryption before MLS processing
- ✓ Full test coverage (54 tests total)

**Phase 4: Local Storage & Pagination (partial) ✓**
- ✓ Rkey-based pagination to replace unbounded URI tracking
- ✓ Local message storage for sent messages (MLS can't decrypt own messages)
- ✓ Proper filtering for ATProto's inclusive `rkey_start` parameter
- ✓ UI auto-scroll to show newest messages

### Not Started

- Phase 4: Remaining local storage expansion (offline sync, message history export)
- Phase 6: Additional Privacy Hardening (cover traffic)

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

### Future: Mobile Apps via FFI

**moat-cli is an MVP.** After the MVP milestone, the CLI will be replaced by cross-platform mobile apps (iOS/Android). The core crates should be designed with FFI in mind:

- **moat-core**: Will be exposed via FFI (likely UniFFI) to Swift/Kotlin. All MLS cryptography stays in Rust for security and single-implementation benefits.
- **moat-atproto**: Will likely be re-implemented natively per platform. ATProto is pure HTTP/REST, and each platform has superior networking libraries (URLSession, OkHttp) with better OS integration for auth flows.

**Design implications for moat-core:**
- Keep operations synchronous (no async) — much simpler FFI story
- Prefer fixed-size arrays (`[u8; 32]`) over `Vec<u8>` where possible
- Error types should be FFI-friendly (consider error codes + message accessors)
- Storage should be controllable by the native side (see FFI Storage Considerations below)

**Storage layout:**
```
~/.moat/
├── mls.bin              # MoatSession's FileStorage (MLS groups, keys)
└── keys/
    ├── credentials      # handle + app password
    ├── identity.key     # KeyBundle (for MLS operations)
    └── conversations/   # Metadata (participant handle, etc.)
```

### FFI Storage Considerations

The current `MoatSession` writes to disk on every operation (via `FileStorage::save_to_file()`). This has FFI concerns:

1. **Blocking I/O on main thread** — Mobile platforms are sensitive to this; can cause UI jank or ANRs
2. **No control over persistence timing** — Native apps often want to batch writes or persist on app suspend
3. **Platform storage expectations** — iOS/Android have specific locations (app sandbox, `getFilesDir()`)

**Recommended refactoring (Option B: Explicit Save):**

```rust
impl MoatSession {
    /// Operations modify in-memory state only (no disk I/O)
    pub fn encrypt_event(&self, ...) -> Result<EncryptResult> { ... }

    /// Explicit persistence — native side calls when appropriate
    pub fn save(&self) -> Result<()> { ... }

    /// Export full state as bytes (for native-managed storage)
    pub fn export_state(&self) -> Result<Vec<u8>> { ... }

    /// Import state from bytes
    pub fn import_state(&mut self, data: &[u8]) -> Result<()> { ... }
}
```

This gives the native side full control over when and where to persist, while keeping MLS operations fast and non-blocking. The existing `in_memory()` constructor already supports this pattern — the refactoring would make it the default for FFI usage.

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
- Uses rkey-based pagination with persistent storage (per-DID last seen rkey)

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

## Phase 4: Local Storage (Partial) ✓

### Step 4.1: Pagination State ✓

**Implementation (completed):**

Rkey-based pagination replaces unbounded URI tracking:

```rust
/// Pagination state (per-DID last seen rkey)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaginationState {
    pub last_rkeys: HashMap<String, String>,
}

impl KeyStore {
    pub fn get_last_rkey(&self, did: &str) -> Result<Option<String>>;
    pub fn set_last_rkey(&self, did: &str, rkey: &str) -> Result<()>;
}
```

**Key insight:** ATProto's `rkey_start` parameter is **inclusive**, so we filter out events where `event.rkey <= last_rkey` client-side.

### Step 4.2: Local Message Storage ✓

**Implementation (completed):**

MLS cannot decrypt your own sent messages (by design - "Cannot create decryption secrets from own sender ratchet"). Solution: store sent messages locally.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub rkey: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub is_own: bool,
}

impl KeyStore {
    pub fn load_messages(&self, conv_id: &str) -> Result<ConversationMessages>;
    pub fn append_message(&self, conv_id: &str, message: StoredMessage) -> Result<()>;
}
```

### Step 4.3: Remaining (Not Started)

- Offline message sync
- Message history export/backup
- Multi-device sync (would require inviting each device as separate MLS member)

---

## Phase 5: Stealth Addresses for Invites ✓ COMPLETE

### Problem (Solved)

The original invitation flow was broken: Alice MLS-encrypted the Welcome, but Bob couldn't decrypt it because he wasn't in the group yet. Publishing unencrypted would reveal "Alice is starting a conversation with Bob" to observers.

**Solution:** Stealth addresses encrypt the Welcome with Bob's published X25519 public key. Only Bob can decrypt, and observers cannot determine the recipient.

---

### Step 5.1: Stealth Address Cryptography ✓

**Implemented in `moat-core/src/stealth.rs`**

Bob publishes a stealth meta-address. Alice uses it to derive a one-time shared secret, encrypts the Welcome, and publishes an ephemeral public key. Bob scans events, attempts derivation with each ephemeral key, and can decrypt only his invites.

**Cryptographic scheme (ECDH + HKDF + XChaCha20-Poly1305):**

```
Bob's stealth meta-address:
  - scan_privkey (s) : X25519 private key (kept secret)
  - scan_pubkey (S)  : X25519 public key (published)

Alice sending an invite:
  1. Generate ephemeral keypair: (r, R) where R = r·G
  2. Compute shared secret: shared = ECDH(r, S) = r·S
  3. Derive encryption key: key = HKDF-SHA256(shared, "moat-stealth-v1")
  4. Encrypt Welcome: ciphertext = XChaCha20-Poly1305(key, nonce, welcome_bytes)
  5. Publish event with:
     - tag: random 16 bytes (not derived from group - invite has no group yet for recipient)
     - payload: R || nonce || ciphertext

Bob scanning for invites:
  1. For each event from watched DIDs with unknown tag:
     a. Parse R || nonce || ciphertext from payload
     b. Compute shared = ECDH(s, R) = s·R
     c. Derive key = HKDF-SHA256(shared, "moat-stealth-v1")
     d. Attempt decrypt: if success, it's an invite for Bob
  2. On successful decrypt, process the Welcome bytes via MLS
```

**Why this works:**
- Only Bob (who knows `s`) can compute the same shared secret Alice used
- Each invite uses a fresh ephemeral `R`, so invites are unlinkable
- The tag is random, not derived from any group ID (since Bob doesn't know the group yet)

---

### Step 5.2: New Lexicon for Stealth Meta-Address ✓

**Implemented in `lexicons/social/moat/stealthAddress.json`**

**Collection:** `social.moat.stealthAddress`

```json
{
  "lexicon": 1,
  "id": "social.moat.stealthAddress",
  "defs": {
    "main": {
      "type": "record",
      "key": "self",
      "record": {
        "type": "object",
        "required": ["v", "scanPubkey", "createdAt"],
        "properties": {
          "v": { "type": "integer", "description": "Schema version" },
          "scanPubkey": { "type": "bytes", "maxLength": 32, "description": "X25519 public key for stealth address derivation" },
          "createdAt": { "type": "string", "format": "datetime" }
        }
      }
    }
  }
}
```

**Key:** `self` (singleton record per user, like a profile)

---

### Step 5.3: Storage Layout Changes ✓

```
~/.moat/
├── keys/
│   ├── credentials
│   ├── identity.key        # MLS KeyBundle
│   └── stealth.key         # NEW: scan_privkey (32 bytes)
└── ...
```

**KeyStore additions:**

```rust
impl KeyStore {
    // Stealth address keys
    pub fn store_stealth_key(&self, privkey: &[u8; 32]) -> Result<()>;
    pub fn load_stealth_key(&self) -> Result<[u8; 32]>;
    pub fn has_stealth_key(&self) -> bool;
}
```

---

### Step 5.4: moat-core Stealth Module ✓

**Implemented in `moat-core/src/stealth.rs`** with 8 unit tests.

```rust
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit}};

const STEALTH_LABEL: &[u8] = b"moat-stealth-v1";

/// Generate a new stealth keypair
pub fn generate_stealth_keypair() -> ([u8; 32], [u8; 32]) {
    let privkey = StaticSecret::random();
    let pubkey = PublicKey::from(&privkey);
    (privkey.to_bytes(), pubkey.to_bytes())
}

/// Encrypt a Welcome for a recipient's stealth address
pub fn encrypt_for_stealth(
    recipient_scan_pubkey: &[u8; 32],
    welcome_bytes: &[u8],
) -> Result<Vec<u8>> {
    // Generate ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH
    let recipient_pubkey = PublicKey::from(*recipient_scan_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);

    // Derive key
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(STEALTH_LABEL, &mut key).unwrap();

    // Encrypt
    let cipher = XChaCha20Poly1305::new(&key.into());
    let nonce = rand::random::<[u8; 24]>();
    let ciphertext = cipher.encrypt(&nonce.into(), welcome_bytes)?;

    // Pack: ephemeral_pubkey (32) || nonce (24) || ciphertext
    let mut result = Vec::with_capacity(32 + 24 + ciphertext.len());
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Try to decrypt a stealth-encrypted Welcome
pub fn try_decrypt_stealth(
    scan_privkey: &[u8; 32],
    payload: &[u8],
) -> Option<Vec<u8>> {
    if payload.len() < 32 + 24 + 16 {  // min: pubkey + nonce + auth tag
        return None;
    }

    // Unpack
    let ephemeral_public = PublicKey::from(<[u8; 32]>::try_from(&payload[..32]).ok()?);
    let nonce: [u8; 24] = payload[32..56].try_into().ok()?;
    let ciphertext = &payload[56..];

    // ECDH
    let privkey = StaticSecret::from(*scan_privkey);
    let shared_secret = privkey.diffie_hellman(&ephemeral_public);

    // Derive key
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(STEALTH_LABEL, &mut key).ok()?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new(&key.into());
    cipher.decrypt(&nonce.into(), ciphertext).ok()
}
```

---

### Step 5.5: moat-atproto Client Additions ✓

```rust
impl MoatAtprotoClient {
    /// Publish stealth address (singleton record)
    pub async fn publish_stealth_address(&self, scan_pubkey: &[u8; 32]) -> Result<String>;

    /// Fetch a user's stealth address
    pub async fn fetch_stealth_address(&self, did: &str) -> Result<Option<[u8; 32]>>;
}
```

---

### Step 5.6: Updated Invitation Flow ✓

**Implemented in `moat-cli/src/app.rs`**

**Alice starting a conversation with Bob:**

```rust
async fn start_new_conversation(&mut self, recipient_handle: &str) -> Result<()> {
    // 1. Resolve handle to DID
    let recipient_did = client.resolve_did(recipient_handle).await?;

    // 2. Fetch Bob's stealth address (NOT key package yet)
    let recipient_stealth_pubkey = client
        .fetch_stealth_address(&recipient_did)
        .await?
        .ok_or_else(|| AppError::Other("Recipient has no stealth address".into()))?;

    // 3. Fetch Bob's MLS key package
    let recipient_kp = client.fetch_key_packages(&recipient_did).await?...;

    // 4. Create MLS group and add Bob
    let group_id = self.mls.create_group(&identity, &key_bundle)?;
    let welcome_result = self.mls.add_member(&group_id, &key_bundle, &recipient_kp)?;

    // 5. Encrypt Welcome with stealth address (NOT MLS encryption)
    let stealth_ciphertext = stealth::encrypt_for_stealth(
        &recipient_stealth_pubkey,
        &welcome_result.welcome,
    )?;

    // 6. Publish with random tag (not group-derived)
    let random_tag: [u8; 16] = rand::random();
    client.publish_event(&random_tag, &stealth_ciphertext).await?;

    // 7. Store conversation metadata locally
    // ...
}
```

**Bob scanning for invites:**

```rust
fn try_process_welcome(&mut self, payload: &[u8], author_did: &str, tag: [u8; 16]) -> Result<bool> {
    // Load our stealth private key
    let stealth_privkey = self.keys.load_stealth_key()?;

    // Try stealth decryption
    let Some(welcome_bytes) = stealth::try_decrypt_stealth(&stealth_privkey, payload) else {
        return Ok(false);  // Not for us
    };

    // Process the MLS Welcome
    let group_id = self.mls.process_welcome(&welcome_bytes)?;

    // Create conversation entry
    // ...

    Ok(true)
}
```

---

### Step 5.7: Key Generation Flow Update ✓

**Implemented in `moat-cli/src/app.rs:do_login()`**

On first login, generate both MLS key package AND stealth address:

```rust
async fn do_login(&mut self) -> Result<()> {
    // ... existing login code ...

    // Generate MLS identity key if needed (existing)
    if !self.keys.has_identity_key() {
        let (key_package, key_bundle) = self.mls.generate_key_package(identity)?;
        self.keys.store_identity_key(&key_bundle)?;
        client.publish_key_package(&key_package, &ciphersuite_name).await?;
    }

    // NEW: Generate stealth address if needed
    if !self.keys.has_stealth_key() {
        let (stealth_privkey, stealth_pubkey) = stealth::generate_stealth_keypair();
        self.keys.store_stealth_key(&stealth_privkey)?;
        client.publish_stealth_address(&stealth_pubkey).await?;
    }

    // ...
}
```

---

### Step 5.8: Implementation Order ✓ COMPLETE

1. ✓ **moat-core**: Add `stealth.rs` with `generate_stealth_keypair()`, `encrypt_for_stealth()`, `try_decrypt_stealth()`
2. ✓ **moat-core**: Add tests for stealth encryption round-trip (8 tests)
3. ✓ **moat-atproto**: Add `publish_stealth_address()`, `fetch_stealth_address()`
4. ✓ **moat-atproto**: Add lexicon file `social.moat.stealthAddress`
5. ✓ **moat-cli/keystore**: Add `store_stealth_key()`, `load_stealth_key()`, `has_stealth_key()`
6. ✓ **moat-cli/app**: Update `do_login()` to generate and publish stealth address
7. ✓ **moat-cli/app**: Update `start_new_conversation()` to use stealth encryption
8. ✓ **moat-cli/app**: Update `try_process_welcome()` to use stealth decryption
9. **Test**: Two terminals, verify invites work with unlinkable stealth addresses

---

### Privacy Analysis

**After stealth addresses:**

| What observers see | What they learn |
|--------------------|-----------------|
| Alice publishes event with random tag | Alice is active |
| Event contains ephemeral pubkey + ciphertext | Nothing about recipient |
| Bob later joins a group | Bob is active |

**Cannot determine:**
- That Alice's event was an invite to Bob
- That multiple invites are for the same person
- The relationship between Alice and Bob from the invite alone

**Still visible:**
- That Alice and Bob both use Moat (key packages and stealth addresses are public)
- Timing correlations (Alice posts, Bob joins shortly after)
- Once messaging starts, conversation participants can be correlated by who's posting to the same tags

---

## Phase 6: Additional Privacy Hardening (Post-Stealth)

### 6.1: Remove senderDeviceId from plaintext
Move into encrypted payload only.

### 6.2: Cover traffic (optional, expensive)
Periodically publish dummy events indistinguishable from real ones.

---

## Build Order ✓ COMPLETE

1. ✓ **moat-core**: Implement `encrypt_event`/`decrypt_event` with tag derivation and padding
2. ✓ **moat-core**: Add tests for full group lifecycle (46 tests, including two-party messaging)
3. ✓ **moat-atproto**: `publish_event`, `fetch_events_from_did`, `fetch_events_by_tag`
4. ✓ **moat-cli**: Add `MoatSession` to App struct, initialize on startup
5. ✓ **moat-cli**: Wire `send_message()` to use MLS encryption
6. ✓ **moat-cli**: Implement `poll_messages()` with decryption
7. ✓ **moat-cli**: Implement `start_new_conversation()` with handle prompt UI
8. ✓ **moat-cli**: Add conversation metadata storage to KeyStore
9. ✓ **moat-cli**: Add watch handle feature for receiving invites from new contacts
10. ✓ **moat-core**: Implement stealth address module (`stealth.rs`)
11. ✓ **moat-atproto**: Add stealth address lexicon and client methods
12. ✓ **moat-cli**: Integrate stealth addresses into login and invitation flows
13. ✓ **Test**: Two terminals, two accounts, exchange encrypted messages

---

## First Milestone ✓ ACHIEVED

Two terminals running moat, logged into different Bluesky accounts, successfully exchange encrypted messages. The message content is E2E encrypted, and the conversation tag rotates with each epoch.

**Verified:**
- Cross-PDS communication via PLC directory resolution
- Bidirectional message exchange
- Stealth address-based invitations

---

## Privacy Guarantees (Be Honest)

**Protected:**
- Message content (MLS E2E encryption)
- Conversation identity from casual observers (rotating tags)
- Message length patterns (padding buckets)
- Invitation recipients (stealth addresses - observers can't tell who an invite is for)
- Invitation correlation (each invite uses fresh ephemeral keys, so multiple invites to the same person are unlinkable)

**Not hidden:**
- Who is posting events (author DID is public in ATProto)
- Timing of activity
- That you're using moat (key packages and stealth addresses are public)
- Timing correlations (if Alice posts an invite and Bob joins shortly after, observers may infer a relationship)

**Caveat for users:**
> "Your messages are end-to-end encrypted. Invitation recipients are hidden from observers. Conversation participants are obscured from casual observers but may be inferrable by your PDS operator and anyone who can correlate activity timing patterns."
