# Postern PDS — Specification & Status

## Overview

Postern is a minimal ATProto PDS implementation for local end-to-end testing of Moat. It runs
as a real HTTP server on localhost, persists state on-disk, and satisfies both the
`MoatAtprotoClient` API and Drawbridge's `PDSVerifier`.

## Problem Statement

End-to-end integration tests for Moat (client ↔ PDS ↔ Drawbridge relay) are currently
impossible without a live Bluesky PDS. Postern provides a local, controllable, debuggable PDS
so that:

- Tests run in CI with no external network dependencies
- State is deterministic and isolated per test run
- Failures can be diagnosed via on-disk state and structured logs

## Workspace Structure

| Crate | Purpose | Status |
|---|---|---|
| `crates/moat-postern` | PDS server library | ✅ Done |
| `moat-integration-tests` | End-to-end tests using `MoatAtprotoClient` + Postern + Drawbridge | ⬜ Not started |

## Architecture

- **HTTP server** using `axum` on localhost; port is random (OS-assigned) or caller-specified.
- **In-memory store** backed by a `BTreeMap` (records) and flat files (blobs) written to a
  timestamped directory under `/tmp/postern/`.
- **Test fixture** `spawn_postern(config)` starts the server and returns a `PosternHandle`.
  The server shuts down gracefully when the handle is dropped.
- **No auth** — all write endpoints are open. Any caller may write to any DID's repo.

## Accounts

Accounts are pre-configured at spawn time via `PosternConfig`. There is no
`com.atproto.server.createAccount`; no sign-up flow is needed.

Each account has:
- A `did` (e.g. `"did:test:alice"` for unit tests, `"did:web:…"` for Drawbridge integration)
- A `handle` (e.g. `"alice.postern.test"`)

## DID Method: `did:web`

Postern serves `GET /.well-known/did.json` with a DID document whose `#atproto_pds`
service endpoint points to the server URL. For a server on port 54321:

- DID: `did:web:127.0.0.1%3A54321`
- DID document at: `http://127.0.0.1:54321/.well-known/did.json`

This allows Drawbridge's `PDSVerifier` to resolve any `did:web` DID back to Postern without a
separate PLC directory. Unit-test accounts can use any DID string (e.g. `did:test:alice`).

## API Surface

### Repository Endpoints — ✅ Implemented

| XRPC Lexicon | HTTP | Notes |
|---|---|---|
| `com.atproto.repo.createRecord` | POST | Returns `uri`, `cid`, `validationStatus`; auto-generates rkey if omitted |
| `com.atproto.repo.getRecord` | GET | 404 with `{"error":"RecordNotFound"}` if missing |
| `com.atproto.repo.listRecords` | GET | Supports `limit`, `cursor` (exclusive), `rkeyStart` (inclusive, camelCase alias) |
| `com.atproto.repo.deleteRecord` | POST | Idempotent; 200 even if record did not exist |

### Blob Endpoints — ✅ Implemented

| XRPC Lexicon | HTTP | Notes |
|---|---|---|
| `com.atproto.repo.uploadBlob` | POST | Content-addressed by SHA-256; stores globally (no per-DID namespace) |
| `com.atproto.sync.getBlob` | GET | `?did=…&cid=…`; `did` accepted but not used for lookup |

### Identity & DID Endpoints — ✅ Implemented

| Path | HTTP | Notes |
|---|---|---|
| `/xrpc/com.atproto.identity.resolveHandle` | GET | Returns `{"did":"…"}` or 400 for unknown handle |
| `/.well-known/did.json` | GET | Returns W3C DID document for `did:web` resolution |

### Out of Scope (v1)

- `com.atproto.server.createSession` / `refreshSession` — no auth
- `com.atproto.server.createAccount` — pre-configured accounts only
- Lexicon schema validation — records are stored as opaque JSON values
- CAR / MST Merkle trees — flat key-value storage
- Firehose / event subscriptions
- Rate limiting / abuse protection

## Storage Layout

State written to `/tmp/postern/<YYYY-MM-DDTHH-MM-SS.mmm>/`:

```
/tmp/postern/2024-06-01T12-00-00.000/
├── records/
│   └── <did>/
│       └── <collection>/
│           └── <rkey>.json
└── blobs/
    └── sha256:<hex>
```

> **Note:** `config.json` and `postern.log` (request/response trace) are not yet written.
> The store is currently in-memory only; on-disk files are created at spawn time to reserve the
> directory, but records and blobs are not flushed to disk between requests. This is sufficient
> for post-failure inspection of the directory path; full persistence is a future improvement.

## Test Fixture API — ✅ Implemented

```rust
pub struct PosternConfig {
    pub accounts: Vec<AccountConfig>,
    pub port: Option<u16>,      // None → OS picks a free port
    pub data_dir: Option<PathBuf>, // None → /tmp/postern/<timestamp>
}

pub struct AccountConfig {
    pub did: String,
    pub handle: String,
}

pub async fn spawn_postern(config: PosternConfig) -> PosternHandle;

pub struct PosternHandle {
    pub fn url(&self) -> &str;       // "http://127.0.0.1:PORT"
    pub fn data_dir(&self) -> &Path;
    // impl Drop → graceful shutdown
}
```

## Unit Tests — ✅ Done (23 tests, all passing)

`cargo test -p moat-postern` — 23 tests, 0 failures.

Located in `crates/moat-postern/tests/endpoints.rs`:

| # | Test | Covers |
|---|---|---|
| 1 | `did_document_returns_valid_doc` | `/.well-known/did.json` shape |
| 2 | `did_document_id_is_did_web` | DID format |
| 3 | `resolve_handle_returns_did` | `resolveHandle` happy path |
| 4 | `resolve_unknown_handle_returns_400` | `resolveHandle` error |
| 5 | `get_unknown_record_returns_404` | `getRecord` 404 |
| 6 | `create_then_get_record` | `createRecord` + `getRecord` round-trip |
| 7 | `create_record_with_explicit_rkey` | Caller-supplied rkey |
| 8 | `create_record_overwrites_same_rkey` | Last-write-wins |
| 9 | `list_records_returns_created_records` | `listRecords` basic |
| 10 | `list_records_empty_for_unknown_collection` | Empty result |
| 11 | `list_records_paginates_with_cursor` | 3-page cursor walk |
| 12 | `list_records_scoped_to_did` | DID isolation |
| 13 | `list_records_rkey_start_filters_results` | `rkeyStart` lower bound |
| 14 | `list_records_items_have_uri_and_value` | Response shape |
| 15 | `delete_record_removes_it` | `deleteRecord` + `getRecord` 404 |
| 16 | `delete_record_removes_from_list` | `deleteRecord` + `listRecords` |
| 17 | `delete_nonexistent_record_is_ok` | Idempotent delete |
| 18 | `upload_then_get_blob` | `uploadBlob` + `getBlob` round-trip |
| 19 | `upload_same_bytes_returns_same_cid` | Content-addressing |
| 20 | `upload_blob_response_includes_size` | Response shape |
| 21 | `get_unknown_blob_returns_404` | `getBlob` 404 |
| 22 | `blob_accessible_from_any_did` | Global blob store |
| 23 | `two_instances_are_isolated` | Per-spawn isolation |

## Drawbridge Compatibility

Drawbridge's `PDSVerifier` (`moat-drawbridge/verify.go`) makes two calls:

**Event verification:**
```
GET /xrpc/com.atproto.repo.getRecord?repo=<did>&collection=social.moat.event&rkey=<rkey>
```
Expects `{ "value": { "tag": { "$bytes": "<base64>" } } }`

**Key package verification:**
```
GET /xrpc/com.atproto.repo.listRecords?repo=<did>&collection=social.moat.keyPackage&limit=50
```
Expects `{ "records": [{ "value": { "keyPackage": { "$bytes": "<base64>" } } }] }`

> ⚠️ **Known gap:** `moat-atproto` serialises byte fields as plain base64 strings
> (`"tag": "AAAA…"`), while Drawbridge expects ATProto IPLD bytes format
> (`"tag": {"$bytes": "AAAA…"}`). This mismatch needs to be resolved when writing the
> `moat-integration-tests` Drawbridge compatibility test (item 10 below).

## What Remains

### `moat-integration-tests` crate (not started)

A new top-level crate that exercises the full Moat stack. Suggested test order:

| # | Test | Status |
|---|---|---|
| 8 | `MoatAtprotoClient` publishes a key package → Bob fetches it via `listRecords` | ⬜ |
| 9 | Alice and Bob exchange Welcome + Message events end-to-end via Postern | ⬜ |
| 10 | Drawbridge `PDSVerifier` resolves a `did:web` DID and verifies a published event | ⬜ |

### Logging (deferred)

Request/response trace logging to `<data_dir>/postern.log` is not yet implemented.
The `tracing` and `tracing-subscriber` dependencies are already in `Cargo.toml`.

## Dependencies

| Crate | Purpose | Added |
|---|---|---|
| `axum 0.8` | HTTP server | ✅ |
| `tokio` | Async runtime | workspace |
| `serde` / `serde_json` | JSON | workspace |
| `sha2` | CID computation (SHA-256) | workspace |
| `chrono` | Timestamped data dirs | workspace |
| `tracing` / `tracing-subscriber` | Logging (stub only) | ✅ |
| `reqwest` (dev) | Test HTTP client | ✅ |
