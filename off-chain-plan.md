# Off-Chain Implementation Plan

## Overview & Purpose

Moat's polling model requires every participant to download all events from their contacts' PDS. Off-chain blobs keep the on-chain envelope small (max 1 KB for user messages) while allowing arbitrarily large payloads — long text and images — to be fetched separately.

**Primary motivation**: Image sharing. Long text is implemented first because it builds the blob infrastructure that images reuse.

**Scope**: moat-core + moat-atproto + moat-cli only. Flutter implementation is a separate effort.

## Current State

The codebase already has substantial infrastructure:

| Component | Status |
|-----------|--------|
| `EventKind::LongText`, `EventKind::Image` | Defined in `moat-core/src/event.rs` |
| `MessagePayload::LongText(LongTextMessage)` | Defined in `moat-core/src/message.rs` |
| `MessagePayload::Image(MediaMessage)` | Defined in `moat-core/src/message.rs` |
| `ExternalBlob` struct (uri, key, hashes, size) | Defined in `moat-core/src/message.rs` |
| Padding (512B / 1KB / 4KB buckets) | Complete in `moat-core/src/padding.rs` |
| Event encryption/decryption (MLS) | Complete in `moat-core/src/lib.rs` |
| CLI display for long_text and image | Complete in `moat-cli/src/message_helpers.rs` |
| Flutter display stubs | Complete in `moat-flutter/lib/utils/message_payload.dart` |
| Lexicon schemas for all message types | Complete in `lexicons/social/moat/internal/eventPayloads.json` |
| Protocol documentation | Complete in `PROTOCOL.md` |
| Property tests for message types | Complete in `moat-core/tests/proptest_message_event.rs` |

**What's missing** (the work to be done):

| Component | Location |
|-----------|----------|
| Blob encryption/decryption (XChaCha20-Poly1305) | New `moat-core/src/blob.rs` |
| Blob integrity verification (SHA-256) | New `moat-core/src/blob.rs` |
| Blob upload (`com.atproto.repo.uploadBlob`) | `moat-atproto/src/client.rs` |
| Blob download (`com.atproto.sync.getBlob`) | `moat-atproto/src/client.rs` |
| Blob cache (disk, keyed by content_hash) | `moat-cli` or `moat-atproto` |
| CLI long text sending (promote to blob) | `moat-cli/src/message_helpers.rs` |
| CLI image sending (`/image` command) | `moat-cli` |
| Image processing (resize, WebP encode, ThumbHash) | New module, likely `moat-core` or `moat-cli` |
| Terminal image rendering (`ratatui-image` widget) | `moat-cli` |

## Phase 1 — Long Text (with blob infrastructure)

### 1.1 Blob Crypto (`moat-core/src/blob.rs`)

Following the "all crypto in moat-core" principle. Reuses the `chacha20poly1305` crate (v0.10, already in workspace for stealth encryption).

**Functions:**

- `blob_encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32], Vec<u8>, Vec<u8>)>`
  - Generate random 32-byte symmetric key
  - Generate random 24-byte nonce
  - Encrypt with XChaCha20-Poly1305
  - Compute `content_hash = SHA-256(plaintext)`
  - Assemble blob = `nonce || ciphertext`
  - Compute `ciphertext_hash = SHA-256(blob)`
  - Return `(blob, key, ciphertext_hash, content_hash)`

- `blob_decrypt(blob: &[u8], key: &[u8; 32], expected_ciphertext_hash: &[u8], expected_content_hash: &[u8]) -> Result<Vec<u8>>`
  - Verify `SHA-256(blob) == expected_ciphertext_hash` (reject: `CiphertextHashMismatch`)
  - Split blob into 24-byte nonce + ciphertext
  - Decrypt with XChaCha20-Poly1305 (reject: `DecryptionFailed`)
  - Verify `SHA-256(plaintext) == expected_content_hash` (reject: `ContentHashMismatch`)
  - Return plaintext

**New error variants** in moat-core's Error type:
- `CiphertextHashMismatch`
- `BlobDecryptionFailed`
- `ContentHashMismatch`

### 1.2 Blob I/O (`moat-atproto/src/client.rs`)

New methods on `MoatAtprotoClient`:

- `upload_blob(data: &[u8]) -> Result<String>`
  - POST to `com.atproto.repo.uploadBlob` with content type `application/octet-stream`
  - Returns the blob ref (CID) used to construct the `at://` URI
  - The blob must be referenced by a record within the PDS time window or it gets garbage collected

- `fetch_blob(did: &str, cid: &str) -> Result<Vec<u8>>`
  - GET from `com.atproto.sync.getBlob` against the sender's PDS
  - Returns raw bytes (`nonce || ciphertext`)
  - Classify errors: transient (`Timeout`, `Unauthorized`, `NotFound`, `RateLimited`) vs integrity

**Note on blob lifecycle**: ATProto blobs are garbage-collected if not referenced by a record. The encrypted event record referencing the blob (via `external.uri`) serves as the reference. The blob must be uploaded *before* the event record is created.

### 1.3 Text Promotion Logic

**Threshold**: Promote `medium_text` to `long_text` when the serialized event payload (with full text inline) would not fit in the 1 KB Standard bucket after padding. This is determined dynamically based on the serialized JSON size including all envelope fields (`group_id`, `epoch`, `message_id`, `kind`, `payload`, transcript integrity fields).

**Preview generation**: Truncate to ~240 characters (respecting UTF-8 char boundaries), append "..." if truncated.

**Send flow**:
1. Attempt to build a `MediumText` payload
2. Serialize the full event to JSON, check if `padded_size <= 1024`
3. If no: encrypt plaintext as blob, upload blob, build `LongText` payload with `preview_text` + `ExternalBlob`
4. Serialize the `LongText` event, pad to 1 KB bucket, MLS-encrypt, publish

### 1.4 Blob Fetch & Retry

**Strategy**: Eager fetch on decrypt. When a received event contains `external`:

1. Check blob cache (`~/.moat/data/blobs/{hex(content_hash)}`) — if hit, use cached
2. If miss: fetch from sender's PDS
3. On transient failure: retry up to 3 times with exponential backoff (1s, 5s, 30s)
4. On success: decrypt, verify integrity, cache plaintext by `content_hash`
5. On permanent failure or integrity error: surface error inline

### 1.5 Blob Cache

**Location**: `~/.moat/data/blobs/` (under the CLI data directory)

**Key**: hex-encoded `content_hash` (SHA-256 of the plaintext)

**Format**: Decrypted plaintext stored directly as file contents. No metadata wrapper.

**No auto-deletion**: Cache grows indefinitely. Manual cleanup by the user.

**Secondary index**: In-memory `ciphertext_hash → content_hash` mapping to avoid reprocessing duplicates during a session.

### 1.6 CLI Integration

**Sending**: No UX change — users type messages normally. Long messages are automatically promoted to `long_text` with blob upload. The TODO in `message_helpers.rs` (line 11) is resolved.

**Receiving**: Full text displayed after blob fetch. While fetching, show inline spinner. On error, show inline error message (e.g., `[download failed: timeout]`). Status bar shows download progress.

### 1.7 Tests

- **Unit tests** (`moat-core/src/blob.rs`): encrypt/decrypt roundtrip, hash verification failures (wrong ciphertext_hash, wrong content_hash, corrupted ciphertext), empty plaintext, large plaintext
- **Property tests**: arbitrary plaintext roundtrips, ciphertext_hash determinism, key uniqueness
- **Integration tests** (`moat-atproto`): blob upload/download roundtrip (requires PDS — may need mock or integration test flag)
- **End-to-end**: Alice sends long text → Bob receives preview immediately → Bob fetches blob → Bob sees full text

### 1.8 Success Criteria

- [ ] Alice types a message > 900 bytes in the CLI
- [ ] Message is automatically promoted to `long_text`
- [ ] Blob is encrypted (XChaCha20-Poly1305), uploaded to PDS, referenced in the event
- [ ] Bob receives the event, sees `preview_text` immediately
- [ ] Bob's client eagerly fetches the blob, verifies both hashes, decrypts
- [ ] Full text is displayed in Bob's CLI
- [ ] Blob is cached locally; second view does not re-download
- [ ] Integrity errors (corrupted blob, wrong hash) are detected and reported inline

## Phase 2 — Images

### 2.1 Image Processing

**New dependencies** (in moat-core or moat-cli as appropriate):
- `image` crate — JPEG/PNG decode, resize, WebP encode
- `thumbhash` crate — generate ThumbHash previews (~28 bytes)

**Pipeline** (on send):
1. Read file from local path (no URL fetching)
2. Validate format: JPEG or PNG only (reject others with clear error)
3. Decode image, extract dimensions (width, height)
4. If longest edge > 2048px: resize proportionally so longest edge = 2048px
5. Re-encode to WebP (lossy, reasonable quality — e.g., 80%)
6. Generate ThumbHash from the (possibly resized) image
7. Encrypt WebP bytes as blob, upload to PDS
8. Build `Image` payload: `preview_thumbhash`, `width`, `height`, `mime: "image/webp"`, `ExternalBlob`

**Note**: The `image` crate is a heavy dependency. Since this processing is I/O-bound and CLI-specific, it could live in `moat-cli` rather than `moat-core` to keep core lean. However, ThumbHash generation might be needed by Flutter's Rust FFI bridge too — revisit when Flutter is in scope.

### 2.2 CLI Send UX

**Command**: `/image <path>` in the message input

- Path supports `~` expansion and relative paths
- One image per command (no multi-image)
- Show progress: "Encoding image...", "Uploading blob...", "Sending..."
- On success: message appears in chat as sent
- On error: inline error (e.g., "Unsupported format", "File not found", "Upload failed")

### 2.3 CLI Receive & Display

**Display approach**: `ratatui-image` widget — a native ratatui widget that handles all terminal graphics protocols. Used by iamb (a Matrix messaging client) for the same use case.

Protocol support (auto-detected via `Picker`):
- Kitty graphics protocol
- Sixel graphics
- iTerm2 protocol
- Unicode half-block fallback for unsupported terminals

Integration: create a `Picker` once at startup (queries the terminal for supported protocol and font pixel dimensions), then call `picker.new_resize_protocol(image)` to produce a `StatefulImage` state. Offload resize/encoding to a Tokio task (the crate has a `tokio` feature for this) to avoid blocking the render thread.

**Receive flow**:
1. Event decrypted, `Image` payload extracted
2. ThumbHash decoded and rendered inline as blurry placeholder (Unicode half-blocks, works in any terminal)
3. Blob fetched eagerly in a Tokio task (same retry policy as long_text)
4. Full image decoded, `ratatui-image` widget rendered in the chat view
5. Cached by `content_hash`

### 2.4 Tests

- **Unit tests**: image resize logic, WebP encode roundtrip, ThumbHash generation, format validation (reject GIF/BMP/etc.)
- **Integration**: full image send/receive roundtrip
- **Edge cases**: very small images (don't upscale), already-WebP input, corrupt JPEG, zero-byte file

### 2.5 Success Criteria

- [ ] Alice runs `/image ~/photo.jpg` in the CLI
- [ ] Image is resized if > 2048px, re-encoded to WebP
- [ ] ThumbHash is generated and embedded in the 1 KB envelope
- [ ] Blob is encrypted and uploaded to PDS
- [ ] Bob receives event, sees ThumbHash preview immediately
- [ ] Bob's client fetches blob, verifies hashes, decrypts
- [ ] Full image is rendered in Bob's terminal (iTerm/Kitty/half blocks)
- [ ] Blob is cached; repeat views don't re-download
- [ ] Invalid formats (GIF, BMP, etc.) are rejected with a clear error

## Out of Scope

- **Flutter implementation**: Covered in a separate plan
- **S3 / alternative storage tiers**: The `uri` field is extensible; PDS-only for MVP
- **URL-based image sending**: Only local file paths accepted
- **Streaming/chunked upload**: Files read entirely into memory
- **Auto-deletion of cached blobs**: Cache grows indefinitely
- **Video / audio**: Future message types, same blob infra
- **Markdown rendering**: Independent of off-chain; text is raw UTF-8
- **Multi-image sends**: One image per `/image` command
- **Cover traffic / dummy blob uploads**: Not in MVP
- **Blob retention policies**: No expiry or cleanup mandated

## Dependencies & Crates

| Crate | Purpose | Status |
|-------|---------|--------|
| `chacha20poly1305` (0.10) | Blob encryption (XChaCha20-Poly1305) | Already in workspace |
| `sha2` | SHA-256 for blob integrity hashes | Check if already in workspace, else add |
| `image` | JPEG/PNG decode, resize, WebP encode | New dependency |
| `thumbhash` | Generate ThumbHash previews | New dependency |
| `ratatui-image` | Terminal image rendering (Kitty/Sixel/iTerm2/half-blocks, native ratatui widget) | New dependency (Phase 2) |

## Architecture Decisions

1. **Blob crypto in moat-core, I/O in moat-atproto**: Follows "all crypto in core" principle. `blob.rs` handles encryption/decryption/hashing. `client.rs` handles HTTP upload/download.

2. **PDS-only blob storage**: `com.atproto.repo.uploadBlob` (50 MB limit) is sufficient. The `ExternalBlob.uri` field uses `at://` scheme, extensible to other schemes later.

3. **Dynamic promotion threshold**: Instead of a fixed byte count, check whether the serialized payload fits the 1 KB bucket. This automatically accounts for envelope overhead and remains correct as fields are added.

4. **Always re-encode to WebP**: Normalizes format, reduces size, keeps the pipeline simple. Accept JPEG/PNG input only.

5. **Eager blob fetch**: Download immediately on decrypt rather than lazily. Simpler UX — messages appear complete. Retry with exponential backoff handles transient failures.

6. **Cache by content_hash**: Stable across re-encryptions. Avoids re-downloading the same content even if the blob is re-uploaded with a different key.
