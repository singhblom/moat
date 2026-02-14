# Off-Chain Storage Plan

## Goals
- Cap per-event bandwidth so watchers never download multi-megabyte ciphertexts just to check tags.
- Preserve DID ⇄ conversation privacy: ciphertexts should still be indistinguishable and routing happens only after MLS decryption.
- Provide an MVP path for inline thumbnails plus deferred retrieval of the heavy payload while keeping the existing MLS transcript-integrity guarantees.

## Envelope Buckets & Layout
- Introduce three ciphertext sizes: **512 B** (reactions, short text), **1 KB** (full metadata + previews), and **4 KB (control)** used rarely for protocol control events that overflow 1 KB.
- MVP policy: use these buckets with no cover traffic. This slightly leaks a coarse size bit ("short" vs "not short" vs "control"); we may add optional cover traffic later if needed.
- Every `social.moat.event` still carries MLS-encrypted JSON, but the 1 KB/4 KB buckets contain:
  - `kind`, `group_id`, `epoch`, `message_id` (required for Message/Reaction), transcript integrity fields (`prev_event_hash`, `epoch_fingerprint`, `sender_device_id`).
  - `payload`: either an inline plaintext message (if it fits) or a **preview bundle** with:
    - `preview` (algorithmic or textual preview; see Preview Policy),
    - `ciphertext_hash` (SHA-256 of stored bytes: `nonce || ciphertext`),
    - `ciphertext_size` (bytes of `nonce || ciphertext`),
    - `content_hash` (SHA-256 of plaintext bytes),
    - `uri` (repo-local address understood by clients),
    - `key` (symmetric key for AEAD decryption),
    - optional `mime`, `width`, `height`.
- MLS padding ensures each bucket reaches its fixed size regardless of actual content.

### Selection Rules (MVP)
- 512 B bucket: Emoji reaction, short text.
- 1 KB bucket: Medium text, long text (with preview + blob), image (preview + blob), video (preview + blob), and most control events (commit/welcome) when they fit.
- 4 KB control bucket: Only for control kinds (commit, welcome, checkpoint) that exceed 1 KB. Do not use 4 KB for user content — large user payloads must use previews + off‑chain `external`.
- Encoding algorithm: attempt to serialize the plaintext JSON + 4‑byte length prefix. If total ≤ 512 B, use 512 B. Else if ≤ 1 KB, use 1 KB. Else if kind ∈ {commit,welcome,checkpoint} and ≤ 4 KB, use 4 KB. Otherwise, fail send (checkpoint) or fall back to preview+external (messages).

## Attachment Hosting & Availability
- MVP requirement: the blob lives on the same PDS as the event so reliability matches the current in-band model; we simply avoid downloading every blob unless the MLS envelope says it belongs to our conversations.
- Later, the URI can point to another PDS or storage tier for intentional obfuscation; the format already supports that without leaking information pre-decryption.
- If a blob is moved or deleted, the sender issues a follow-up MLS event referencing the original `message_id` with new `uri` and `ciphertext_hash` values. The `content_hash` remains stable across re-encryptions so receivers can verify continuity. The thumbnail ensures receivers always see that content once existed.

### URI Semantics (MVP)
- Allowed only as **repo-local addresses** resolvable via standard ATProto repo auth. Examples:
  - `at://did:plc:.../app.bsky.blob/...` style identifiers, or
  - XRPC parameters for `com.atproto.repo.getBlob` (DID + CID).
- Clients MUST use the sender’s PDS and their existing session/token to fetch; HTTPS capability/bearer URLs are out of scope for MVP and may be added later as a new subtype.

## Integrity & Transcript Binding
- `ciphertext_hash`, `ciphertext_size`, `content_hash`, and `key` sit inside the MLS payload so they are protected by MLS authentication, hash chains, and epoch fingerprints. Any mismatch triggers the existing transcript-integrity warnings.
- Verify-before-decrypt: hash the downloaded bytes (including the 24-byte nonce prefix) and compare to `ciphertext_hash`. Then decrypt with `key` and the prefixed nonce, and verify `content_hash` on the plaintext.
- Clients cache blobs keyed by `content_hash` (stable across re-encryption) and may also cache the mapping `ciphertext_hash → content_hash` to avoid reprocessing.

### Message Identifiers
- `message_id` is a 16‑byte random identifier assigned by Moat for `message` and `reaction` events (already implemented in moat-core). It anchors reactions and any later pointer updates (e.g., move/retarget). Non‑user events (`commit`, `welcome`, `checkpoint`) do not carry `message_id`.

## Client Responsibilities
1. Attempt to decrypt every 1 KB envelope as today; if it resolves to our conversation and contains a preview bundle, show the preview immediately.
2. Fetch the blob lazily (on demand or via background prefetch) using the `uri`. Verify `ciphertext_hash` before decrypt; after decrypt, verify `content_hash`.
3. Persist blobs locally (cache key: `content_hash`) to avoid re-fetching history; GC policies can follow later.
4. CLI and Flutter share blob handling through a core Rust helper that validates hashes, decrypts, and exposes a unified error surface.

## Error Taxonomy & Behavior (MVP)
- Fetch errors (repo-local URI): `Timeout/Network`, `Unauthorized/Forbidden`, `NotFound`, `RateLimited`. Use exponential backoff with jitter; keep previews visible and allow manual retry.
- Integrity errors: `CiphertextHashMismatch` (pre-decrypt), `DecryptionFailed` (AEAD tag), `ContentHashMismatch` (post-decrypt). Surface as transcript warnings; do not auto-hide the envelope.
- Pointer retargets: maintain per-`message_id` active pointer and mark older pointers as `StaleURI` internally. Auto-switch to the newest pointer, cancel in-flight stale fetches, and suppress user-visible errors for stale fetches (still logged for debugging).

## Preview Policy (MVP)
- Use algorithmic previews to fit reliably within the 1 KB envelope while giving immediate UI feedback:
  - Images/video posters: ThumbHash preferred (preliminary); store as bytes and base64-encode in JSON. Cap raw size ≤ 64 B (≈ 88 characters base64). Include optional `width/height` and `mime`.
  - Long text: `preview_text` capped to fit remaining JSON budget (≈ 240–440 ASCII chars depending on other fields).
  - Audio: `waveform` downsampled to 64–128 8‑bit samples (≤ 160 B raw, ≈ 216 characters base64).
- Notes: these caps are preliminary and may be iterated after empirical testing. Full-resolution media always streams via `uri` after decrypt.

## Message Types & Schemas (Union)
Model each user-visible message explicitly to keep validation clear and evolution tractable. The `event.kind == "message"` payload discriminates among these:

- `reaction` (always 512 B)
  - Fields: `emoji: string`, `target_message_id: bytes[16]`
  - No preview, no external blob.

- `short_text` (512 B)
  - Fields: `text: string`
  - Fits entirely inline; no external blob.

- `medium_text` (1 KB)
  - Fields: `text: string`
  - Inline, larger than short_text; no external blob.

- `long_text` (1 KB)
  - Fields: `preview_text: string`, `external` (see below), optional `mime` (`text/plain`, `text/markdown`)
  - External carries the full content.

- `image` (1 KB)
  - Fields: `preview_thumbhash: bytes` (≤ 64 B raw), `width`, `height`, `mime` (e.g., `image/jpeg`), `external`.

- `video` (1 KB)
  - Fields: `preview_thumbhash: bytes` (poster), `width`, `height`, `mime` (e.g., `video/mp4`), optional `duration_ms`, `external`.

External blob sub-structure (`external`):
- `ciphertext_hash`, `ciphertext_size`, `content_hash`, `uri` (repo address), `key` (symmetric key for AEAD). Cipher/nonce details will be specified separately.

Bucket mapping is normative for MVP; future releases may adjust thresholds based on telemetry and UX.

## Structured Payload Lexicon
Adopt the base + per-kind schema approach, aligned with explicit message union types.

- Extend `social.moat.internal.eventPayloads` with per-kind message definitions:
  - `messageShortText`, `messageMediumText`, `messageLongText`, `messageImage`, `messageVideo`, and `reaction`.
- Define `social.moat.internal.externalPayloadBase` with shared fields `{ciphertext_hash, ciphertext_size, content_hash, uri, key}`; derive specialized types:
  - `externalText`, `externalImage`, `externalVideo` to carry preview-specific metadata.

The `uri` field is intentionally generic: MVP uses repo-local addresses resolved via standard ATProto auth; future capability URLs can be introduced via a new subtype without breaking existing clients.

## Implementation Notes
- Update `social.moat.event` lexicon and `PROTOCOL.md` to reflect the new payload schema, bucket sizes, and re-fetch flow.
- Extend `moat-core` serialization + tests to cover pointer events, dual-hash binding, and 512 B vs 1 KB vs 4 KB padding.
- Add attachment downloaders to CLI/Flutter plus unit tests for fetch failures and hash mismatches.
- Provide migration tooling for wiping the prototype repos; no backward compatibility is required at this stage.

## Protocol Update & Rollout
- After implementation and tests pass, update `PROTOCOL.md` and the internal lexicons (`lexicons/social/moat/*.json` and `lexicons/social/moat/internal/*`) to match the final on-wire shapes and bucket policy (512/1024/4096), the explicit message union, preview policy, and blob encryption/hash fields. Then wipe the two test repos to reset state.

### Welcome Size Controls (MVP defaults)
- Single‑member invites only. Omit RatchetTree in Welcome; include/verifiy a tree hash so the joiner can validate the tree they fetch post‑join. Keep invite commits minimal (no batching/inlined proposals).
- Most welcomes should fit 1 KB; the 4 KB control bucket is a rare safety valve for unusually large control artifacts.

## Blob Encryption (MVP)
- AEAD: XChaCha20‑Poly1305.
- Nonce: 24‑byte random per blob, prefixed to the ciphertext in storage (`blob = nonce || ciphertext`).
- Hash target: `ciphertext_hash = SHA‑256(blob)`, `content_hash = SHA‑256(plaintext bytes)`.
- Size: `ciphertext_size = len(blob)`; `content_size` optional (for UX/progress) and may be added later.
