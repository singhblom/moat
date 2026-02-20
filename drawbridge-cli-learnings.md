# Drawbridge CLI Integration: Learnings

Summary of problems encountered integrating Drawbridge into moat-core and moat-cli (commits `07d6b72`–`9f8a9d2`, Feb 18–20 2026).

## Bug 1: Ed25519 Signing Key Extraction from MLS KeyBundle

**Problem:** The initial integration placed challenge-signing logic in moat-cli, where it parsed the raw TLS-serialized `SignatureKeyPair` from OpenMLS to extract the Ed25519 private key. This involved fragile byte-offset parsing of a 2-byte length prefix plus private key bytes, with special-case handling for 32-byte vs 64-byte representations. It broke the architecture principle that all crypto belongs in moat-core and depended on OpenMLS internal serialization details.

**Fix:** Moved Ed25519 signing into moat-core as `MoatSession::sign_drawbridge_challenge()`. Generated Ed25519 keys directly via `ed25519_dalek` instead of relying on `SignatureKeyPair::new()`, then fed the raw bytes to OpenMLS via `SignatureKeyPair::from_raw()`. This let moat-core store the raw 32-byte Ed25519 seed in a new `signature_private_key` field on `KeyBundle`, completely eliminating the TLS parsing hack.

## Bug 2: URL Path Mismatch in Challenge Signing

**Problem:** The client signed the full WebSocket connection URL including path (e.g. `wss://moat-drawbridge.fly.dev/ws`), but the server constructed its relay URL as scheme+host only (`wss://moat-drawbridge.fly.dev`). Every signature verification failed because the signed message didn't match what the server expected.

**Fix:** Added `strip_url_path()` in the client to strip the path component before signing, so both sides sign the same `scheme://host` string.

## Bug 3: Server Using localhost URL Behind TLS Proxy

**Problem:** When deployed behind a TLS-terminating proxy (Fly.io), the Go drawbridge server computed its relay URL from its local listener address, producing `ws://localhost:8080` instead of the public `wss://moat-drawbridge.fly.dev`. The server used this localhost URL in challenge construction, so verification failed against the client's public URL.

**Fix:** Three-tier relay URL resolution on the server side:
1. `RELAY_PUBLIC_URL` env var — explicit override for deployed environments
2. `X-Forwarded-Proto` + `Host` headers — auto-detected from reverse proxy
3. TLS-based fallback — for local dev

Each `Client` now stores its own `relayURL` derived per-connection at WebSocket upgrade time, rather than sharing a single global relay URL.

## Bug 4: PDS Event Ordering / rkey Sorting

**Problem:** The PDS did not return events in chronological order. Events came back in descending rkey order (newest first), which meant a `DrawbridgeHint` event could be processed before the `Welcome` event it depended on. Since the hint uses a tag derived from the MLS group — which is only established after processing the Welcome — the hint would fail to match any known conversation and get silently dropped.

**Fix:** Added an explicit `sort_by` on rkey (ascending) before processing watched events. ATProto rkeys are TIDs (timestamp-based identifiers) that sort chronologically by string comparison, so sorting ascending ensures Welcomes are processed before any derived events like hints or messages in the same batch.

## Bug 5: Reconnect Logic and Self-Decryption Errors

**Problem:** Multiple issues surfaced during real two-device testing:
- Partner Drawbridge reconnection was called inside `connect_own()`, coupling it to the own-relay connection lifecycle. If own-relay connection failed or retried, partner connections were re-attempted prematurely or not at all.
- The app tried to decrypt messages it had published itself during polling, causing spurious errors every poll cycle (MLS does not support self-decryption).
- Conversations loaded from disk showed raw DIDs instead of human-readable handles.

**Fix:**
- Decoupled partner reconnection into a separate `DrawbridgeReconnectPartners` event triggered after login.
- Added `own_published_tags: HashSet<[u8; 16]>` to track tags of self-published messages and skip them during polling.
- Added async handle resolution (`HandleResolved` event) on login for all persisted conversations.

## Key Takeaway

The core pattern was a **signing URL mismatch across three layers**: the Rust client, the TLS proxy, and the Go server each had their own idea of what the relay URL was, and they all needed to agree on the exact string being signed. This was compounded by a **layering violation** (crypto logic in moat-cli instead of moat-core) and **implicit ordering assumptions** about PDS event delivery that turned out to be wrong.
