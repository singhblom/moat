# moat-postern

A minimal ATProto PDS for local end-to-end testing of Moat.

**Postern** (n.) — a small private gate in a castle wall, used for testing
without going through the main entrance.

## What it is

Postern is a real HTTP server that speaks the ATProto XRPC protocol. It
implements just the endpoints that Moat's clients and the Drawbridge relay
need, no more. All state is held in memory and mirrored to a timestamped
directory under `/tmp/postern/` so you can inspect it after a test failure.

It is designed to be used with a `spawn_postern()` fixture that boots a fresh
server on a random port and shuts it down automatically when the test ends.

## Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/did.json` | GET | `did:web` DID document — lets Drawbridge resolve the PDS URL |
| `/xrpc/com.atproto.identity.resolveHandle` | GET | Handle → DID |
| `/xrpc/com.atproto.repo.createRecord` | POST | Write a record |
| `/xrpc/com.atproto.repo.getRecord` | GET | Read one record |
| `/xrpc/com.atproto.repo.listRecords` | GET | List records (cursor pagination, `rkeyStart`) |
| `/xrpc/com.atproto.repo.deleteRecord` | POST | Delete a record |
| `/xrpc/com.atproto.repo.uploadBlob` | POST | Store a blob (content-addressed by SHA-256) |
| `/xrpc/com.atproto.sync.getBlob` | GET | Retrieve a blob by CID |

Auth is intentionally skipped — all endpoints are open. This is a test tool.

## Usage

```rust
use moat_postern::{spawn_postern, AccountConfig, PosternConfig};

#[tokio::test]
async fn alice_publishes_key_package() {
    let postern = spawn_postern(PosternConfig {
        accounts: vec![
            AccountConfig {
                did: "did:test:alice".to_string(),
                handle: "alice.postern.test".to_string(),
            },
        ],
        port: None,     // OS picks a free port
        data_dir: None, // /tmp/postern/<timestamp>/
    })
    .await;

    // postern.url() → "http://127.0.0.1:XXXXX"
    // postern.data_dir() → PathBuf to the on-disk state
    // server shuts down when `postern` is dropped
}
```

## On-disk layout

Every call to `spawn_postern` creates a fresh directory:

```
/tmp/postern/2024-06-01T12-00-00.000/
├── records/
│   └── did:test:alice/
│       └── social.moat.keyPackage/
│           └── 00000000000000000001.json
└── blobs/
    └── sha256:deadbeef…
```

Records are plain JSON files; blobs are raw bytes. Both survive test crashes
and can be inspected with any editor or `jq`.

## DIDs

Postern uses `did:web` so Drawbridge's `PDSVerifier` can resolve accounts
back to the server without a separate PLC directory:

- Server URL: `http://127.0.0.1:54321`
- DID: `did:web:127.0.0.1%3A54321`
- DID document: `http://127.0.0.1:54321/.well-known/did.json`

Test accounts can use any DID string (e.g. `did:test:alice`). The `did:web`
DID identifies the *server itself* and is what Drawbridge uses to find the
PDS endpoint.

## Running the tests

```bash
cargo test -p moat-postern
```

Tests run in parallel — each gets its own server on a distinct random port.
