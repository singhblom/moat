//! TDD endpoint tests for Postern.
//!
//! Each test follows the red/green pattern:
//!   1. Spin up a fresh Postern instance via `spawn_postern`.
//!   2. Issue raw HTTP requests with `reqwest`.
//!   3. Assert the exact response status code and body shape.
//!
//! Tests are isolated — each gets its own server on a random port and its own
//! timestamped data directory under `/tmp/postern/`.

use moat_postern::{spawn_postern, AccountConfig, PosternConfig};
use reqwest::StatusCode;
use serde_json::{json, Value};

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn alice() -> AccountConfig {
    AccountConfig {
        did: "did:test:alice".to_string(),
        handle: "alice.postern.test".to_string(),
    }
}

fn bob() -> AccountConfig {
    AccountConfig {
        did: "did:test:bob".to_string(),
        handle: "bob.postern.test".to_string(),
    }
}

async fn postern_one_account() -> moat_postern::PosternHandle {
    spawn_postern(PosternConfig {
        accounts: vec![alice()],
        port: None,
        data_dir: None,
    })
    .await
}

// ── 1. DID document ───────────────────────────────────────────────────────────

/// `/.well-known/did.json` returns a valid DID document with an
/// `AtprotoPersonalDataServer` service pointing to the server URL.
#[tokio::test]
async fn did_document_returns_valid_doc() {
    let postern = postern_one_account().await;

    let resp = reqwest::get(format!("{}/.well-known/did.json", postern.url()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();

    assert!(body["id"].is_string(), "DID document must have an id field");

    let services = body["service"].as_array().expect("service must be an array");
    let pds = services
        .iter()
        .find(|s| s["type"] == "AtprotoPersonalDataServer")
        .expect("must have an AtprotoPersonalDataServer service");

    assert_eq!(
        pds["serviceEndpoint"].as_str().unwrap(),
        postern.url(),
        "serviceEndpoint must equal the server URL"
    );
}

/// The DID document id is a `did:web:` DID containing the server host.
#[tokio::test]
async fn did_document_id_is_did_web() {
    let postern = postern_one_account().await;
    let resp = reqwest::get(format!("{}/.well-known/did.json", postern.url()))
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();
    assert!(id.starts_with("did:web:"), "id must be a did:web DID, got: {id}");
}

// ── 2. resolveHandle ─────────────────────────────────────────────────────────

/// A configured handle resolves to its DID.
#[tokio::test]
async fn resolve_handle_returns_did() {
    let postern = postern_one_account().await;

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.identity.resolveHandle?handle=alice.postern.test",
        postern.url()
    ))
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["did"].as_str().unwrap(), "did:test:alice");
}

/// An unknown handle returns 400.
#[tokio::test]
async fn resolve_unknown_handle_returns_400() {
    let postern = postern_one_account().await;

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.identity.resolveHandle?handle=nobody.postern.test",
        postern.url()
    ))
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].is_string());
}

// ── 3. getRecord – 404 for unknown ───────────────────────────────────────────

/// `getRecord` returns 404 when the record does not exist.
#[tokio::test]
async fn get_unknown_record_returns_404() {
    let postern = postern_one_account().await;

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.getRecord\
         ?repo=did:test:alice&collection=social.moat.event&rkey=nonexistent",
        postern.url()
    ))
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "RecordNotFound");
}

// ── 4. createRecord + getRecord round-trip ────────────────────────────────────

/// Creating a record and then fetching it returns the same value.
#[tokio::test]
async fn create_then_get_record() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    let resp = http
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "record": {
                "v": 1,
                "tag": "AAAAAAAAAAAAAAAAAAAAAA==",
                "ciphertext": "aGVsbG8=",
                "createdAt": "2024-01-01T00:00:00Z"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let created: Value = resp.json().await.unwrap();
    let uri = created["uri"].as_str().unwrap();
    assert!(
        uri.starts_with("at://did:test:alice/social.moat.event/"),
        "unexpected URI: {uri}"
    );

    let rkey = uri.split('/').last().unwrap();

    let resp = http
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord\
             ?repo=did:test:alice&collection=social.moat.event&rkey={rkey}",
            postern.url()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["value"]["v"], 1);
    assert_eq!(body["value"]["tag"].as_str().unwrap(), "AAAAAAAAAAAAAAAAAAAAAA==");
    assert_eq!(body["uri"].as_str().unwrap(), uri);
}

/// When an explicit rkey is supplied, the record is stored under that rkey.
#[tokio::test]
async fn create_record_with_explicit_rkey() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    let resp = http
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.keyPackage",
            "rkey": "my-explicit-rkey",
            "record": { "v": 1, "keyPackage": "dGVzdA==" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["uri"].as_str().unwrap().ends_with("/my-explicit-rkey"),
        "URI should end with the supplied rkey"
    );
}

/// Overwriting an existing rkey replaces the record value.
#[tokio::test]
async fn create_record_overwrites_same_rkey() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    for v in [1u64, 2] {
        http.post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "rkey": "fixed-key",
            "record": { "v": v }
        }))
        .send()
        .await
        .unwrap();
    }

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.getRecord\
         ?repo=did:test:alice&collection=social.moat.event&rkey=fixed-key",
        postern.url()
    ))
    .await
    .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["value"]["v"], 2, "second write should win");
}

// ── 5. listRecords ────────────────────────────────────────────────────────────

/// `listRecords` returns all records in a collection.
#[tokio::test]
async fn list_records_returns_created_records() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    for i in 0..3u32 {
        http.post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "record": { "v": i }
        }))
        .send()
        .await
        .unwrap();
    }

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.listRecords\
         ?repo=did:test:alice&collection=social.moat.event",
        postern.url()
    ))
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["records"].as_array().unwrap().len(), 3);
}

/// `listRecords` returns an empty array for a collection with no records.
#[tokio::test]
async fn list_records_empty_for_unknown_collection() {
    let postern = postern_one_account().await;

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.listRecords\
         ?repo=did:test:alice&collection=social.moat.event",
        postern.url()
    ))
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["records"].as_array().unwrap().len(), 0);
    assert!(
        body.get("cursor").is_none() || body["cursor"].is_null(),
        "no cursor on empty result"
    );
}

/// `listRecords` paginates with `limit` and `cursor`.
#[tokio::test]
async fn list_records_paginates_with_cursor() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    // Create 5 records with deterministic rkeys so ordering is predictable.
    for i in 0..5u32 {
        http.post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "rkey": format!("rkey-{i:03}"),
            "record": { "v": i }
        }))
        .send()
        .await
        .unwrap();
    }

    // Page 1: limit=2 → records 0,1 and a cursor.
    let resp = http
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords\
             ?repo=did:test:alice&collection=social.moat.event&limit=2",
            postern.url()
        ))
        .send()
        .await
        .unwrap();
    let p1: Value = resp.json().await.unwrap();
    assert_eq!(p1["records"].as_array().unwrap().len(), 2);
    let cursor1 = p1["cursor"].as_str().expect("page 1 must have a cursor");

    // Page 2: limit=2 with cursor → records 2,3 and a cursor.
    let resp = http
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords\
             ?repo=did:test:alice&collection=social.moat.event&limit=2&cursor={cursor1}",
            postern.url()
        ))
        .send()
        .await
        .unwrap();
    let p2: Value = resp.json().await.unwrap();
    assert_eq!(p2["records"].as_array().unwrap().len(), 2);
    let cursor2 = p2["cursor"].as_str().expect("page 2 must have a cursor");

    // Page 3: limit=2 with cursor → only record 4, no cursor.
    let resp = http
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords\
             ?repo=did:test:alice&collection=social.moat.event&limit=2&cursor={cursor2}",
            postern.url()
        ))
        .send()
        .await
        .unwrap();
    let p3: Value = resp.json().await.unwrap();
    assert_eq!(p3["records"].as_array().unwrap().len(), 1);
    assert!(
        p3.get("cursor").is_none() || p3["cursor"].is_null(),
        "no cursor on final page"
    );
}

/// Records from different DIDs are not visible in each other's listing.
#[tokio::test]
async fn list_records_scoped_to_did() {
    let postern = spawn_postern(PosternConfig {
        accounts: vec![alice(), bob()],
        port: None,
        data_dir: None,
    })
    .await;
    let http = reqwest::Client::new();

    // Alice writes a record.
    http.post(format!(
        "{}/xrpc/com.atproto.repo.createRecord",
        postern.url()
    ))
    .json(&json!({
        "repo": "did:test:alice",
        "collection": "social.moat.event",
        "record": { "v": 1 }
    }))
    .send()
    .await
    .unwrap();

    // Bob's list is empty.
    let resp = http
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords\
             ?repo=did:test:bob&collection=social.moat.event",
            postern.url()
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["records"].as_array().unwrap().len(), 0);
}

/// `rkeyStart` filters to records at or after that rkey.
#[tokio::test]
async fn list_records_rkey_start_filters_results() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    for i in 0..5u32 {
        http.post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "rkey": format!("rkey-{i:03}"),
            "record": { "v": i }
        }))
        .send()
        .await
        .unwrap();
    }

    // rkeyStart=rkey-002 should return records 2,3,4 (inclusive).
    let resp = http
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords\
             ?repo=did:test:alice&collection=social.moat.event&rkeyStart=rkey-002",
            postern.url()
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 3, "expected records 2,3,4");
    // Verify the first record is the one at rkey-002.
    let first_uri = records[0]["uri"].as_str().unwrap();
    assert!(first_uri.ends_with("/rkey-002"), "first record should be rkey-002, got {first_uri}");
}

/// Each record in the list response carries a `uri` and a `value`.
#[tokio::test]
async fn list_records_items_have_uri_and_value() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    http.post(format!(
        "{}/xrpc/com.atproto.repo.createRecord",
        postern.url()
    ))
    .json(&json!({
        "repo": "did:test:alice",
        "collection": "social.moat.keyPackage",
        "rkey": "kp-001",
        "record": { "v": 1, "keyPackage": "dGVzdA==" }
    }))
    .send()
    .await
    .unwrap();

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.listRecords\
         ?repo=did:test:alice&collection=social.moat.keyPackage",
        postern.url()
    ))
    .await
    .unwrap();
    let body: Value = resp.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["uri"].as_str().unwrap(),
        "at://did:test:alice/social.moat.keyPackage/kp-001"
    );
    assert_eq!(records[0]["value"]["keyPackage"].as_str().unwrap(), "dGVzdA==");
}

// ── 6. deleteRecord ───────────────────────────────────────────────────────────

/// Deleting a record makes it unreachable via `getRecord`.
#[tokio::test]
async fn delete_record_removes_it() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    http.post(format!(
        "{}/xrpc/com.atproto.repo.createRecord",
        postern.url()
    ))
    .json(&json!({
        "repo": "did:test:alice",
        "collection": "social.moat.event",
        "rkey": "to-delete",
        "record": { "v": 1 }
    }))
    .send()
    .await
    .unwrap();

    let del = http
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "rkey": "to-delete"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::OK);

    let get = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.getRecord\
         ?repo=did:test:alice&collection=social.moat.event&rkey=to-delete",
        postern.url()
    ))
    .await
    .unwrap();
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

/// Deleting a record removes it from `listRecords`.
#[tokio::test]
async fn delete_record_removes_from_list() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    for i in 0..3u32 {
        http.post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "rkey": format!("evt-{i:03}"),
            "record": { "v": i }
        }))
        .send()
        .await
        .unwrap();
    }

    http.post(format!(
        "{}/xrpc/com.atproto.repo.deleteRecord",
        postern.url()
    ))
    .json(&json!({
        "repo": "did:test:alice",
        "collection": "social.moat.event",
        "rkey": "evt-001"
    }))
    .send()
    .await
    .unwrap();

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.listRecords\
         ?repo=did:test:alice&collection=social.moat.event",
        postern.url()
    ))
    .await
    .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["records"].as_array().unwrap().len(), 2);
}

/// Deleting a non-existent record returns 200 (idempotent).
#[tokio::test]
async fn delete_nonexistent_record_is_ok() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    let resp = http
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            postern.url()
        ))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "rkey": "never-existed"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ── 7. uploadBlob + getBlob ───────────────────────────────────────────────────

/// Uploading a blob and then downloading it returns the original bytes.
#[tokio::test]
async fn upload_then_get_blob() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    let blob_data: &[u8] = b"hello encrypted blob";

    let up = http
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            postern.url()
        ))
        .header("Content-Type", "application/octet-stream")
        .body(blob_data.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(up.status(), StatusCode::OK);
    let body: Value = up.json().await.unwrap();
    let cid = body["blob"]["ref"]["$link"]
        .as_str()
        .expect("blob.ref.$link must be present");
    assert!(!cid.is_empty());

    let down = http
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob?did=did:test:alice&cid={cid}",
            postern.url()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(down.status(), StatusCode::OK);
    assert_eq!(down.bytes().await.unwrap().as_ref(), blob_data);
}

/// Uploading the same bytes twice returns the same CID (content-addressed).
#[tokio::test]
async fn upload_same_bytes_returns_same_cid() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    let data = b"deterministic content";
    let upload = || {
        http.post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            postern.url()
        ))
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec())
        .send()
    };

    let r1: Value = upload().await.unwrap().json().await.unwrap();
    let r2: Value = upload().await.unwrap().json().await.unwrap();

    assert_eq!(
        r1["blob"]["ref"]["$link"].as_str().unwrap(),
        r2["blob"]["ref"]["$link"].as_str().unwrap(),
        "same content must produce the same CID"
    );
}

/// The `uploadBlob` response includes the blob size in bytes.
#[tokio::test]
async fn upload_blob_response_includes_size() {
    let postern = postern_one_account().await;
    let http = reqwest::Client::new();

    let data = b"twelve bytes";
    let resp: Value = http
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            postern.url()
        ))
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["blob"]["size"].as_u64().unwrap(), data.len() as u64);
}

/// `getBlob` returns 404 for an unknown CID.
#[tokio::test]
async fn get_unknown_blob_returns_404() {
    let postern = postern_one_account().await;

    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.sync.getBlob?did=did:test:alice&cid=sha256:deadbeef",
        postern.url()
    ))
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "BlobNotFound");
}

/// Blobs are globally content-addressed: uploading from one DID makes the
/// blob downloadable with any DID (Postern stores blobs by CID only).
#[tokio::test]
async fn blob_accessible_from_any_did() {
    let postern = spawn_postern(PosternConfig {
        accounts: vec![alice(), bob()],
        port: None,
        data_dir: None,
    })
    .await;
    let http = reqwest::Client::new();

    let up: Value = http
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            postern.url()
        ))
        .header("Content-Type", "application/octet-stream")
        .body(b"shared data".to_vec())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let cid = up["blob"]["ref"]["$link"].as_str().unwrap();

    // Fetch with Bob's DID — should still work.
    let down = http
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob?did=did:test:bob&cid={cid}",
            postern.url()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(down.status(), StatusCode::OK);
    assert_eq!(down.bytes().await.unwrap().as_ref(), b"shared data");
}

// ── 8. State isolation between instances ─────────────────────────────────────

/// Two Postern instances are fully isolated: records written to one are not
/// visible in the other.
#[tokio::test]
async fn two_instances_are_isolated() {
    let p1 = postern_one_account().await;
    let p2 = postern_one_account().await;
    let http = reqwest::Client::new();

    http.post(format!("{}/xrpc/com.atproto.repo.createRecord", p1.url()))
        .json(&json!({
            "repo": "did:test:alice",
            "collection": "social.moat.event",
            "rkey": "shared-rkey",
            "record": { "v": 1 }
        }))
        .send()
        .await
        .unwrap();

    // Same rkey on the second instance must return 404.
    let resp = reqwest::get(format!(
        "{}/xrpc/com.atproto.repo.getRecord\
         ?repo=did:test:alice&collection=social.moat.event&rkey=shared-rkey",
        p2.url()
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
