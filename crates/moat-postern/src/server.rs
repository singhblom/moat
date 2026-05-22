//! axum HTTP server and all XRPC handlers.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::config::{PosternConfig, PosternHandle};
use crate::store::{SharedStore, Store};

// ── CIDv1 helper ─────────────────────────────────────────────────────────────

/// Compute a valid CIDv1 (raw codec, SHA-256 multihash) for the given bytes.
///
/// Returns a multibase base32-lowercase string (prefix `b`), e.g.
/// `bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku`.
///
/// This is the format expected by the atrium library when it parses CID fields
/// in ATProto XRPC responses.
fn compute_cid(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(data);

    // CIDv1: [version=1][codec=raw(0x55)][sha2-256(0x12)][digest_len=32(0x20)][digest]
    let mut cid_bytes = vec![0x01u8, 0x55, 0x12, 0x20];
    cid_bytes.extend_from_slice(&digest);

    // Multibase base32 lowercase (no padding), prefix 'b'.
    let b32 = base32_lower_nopad(&cid_bytes);
    format!("b{b32}")
}

/// Base32 lowercase (RFC 4648 alphabet `a–z`, `2–7`) without padding.
fn base32_lower_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

// ── DAG-JSON normalisation ────────────────────────────────────────────────────

/// Strip base64 padding (`=`) from every `{"$bytes":"…"}` field in a JSON
/// value, mirroring what the real Bluesky PDS does when it round-trips records
/// through DAG-CBOR.  ATProto's DAG-JSON spec mandates unpadded base64 for
/// byte fields, but Dart's `base64Encode` produces padded strings.  Without
/// this normalisation Postern would accept padded input and echo it back
/// verbatim, masking the bug that surfaces against the production PDS.
fn strip_bytes_padding(val: &mut Value) {
    match val {
        Value::Object(map) => {
            if map.len() == 1 {
                if let Some(Value::String(b64)) = map.get_mut("$bytes") {
                    b64.retain(|c| c != '=');
                    return;
                }
            }
            for v in map.values_mut() {
                strip_bytes_padding(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_bytes_padding(v);
            }
        }
        _ => {}
    }
}

// ── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    store: SharedStore,
    server_url: String,
    /// Shared override for the `serviceEndpoint` in DID documents.
    /// Set via `PosternHandle::set_pds_endpoint_override` at runtime.
    pds_endpoint_override: Arc<Mutex<Option<String>>>,
    /// Drawbridge URL advertised in `describeServer`.
    /// Set via `PosternHandle::set_drawbridge_url` at runtime.
    drawbridge_url: Arc<Mutex<Option<String>>>,
}

// ── Error helper ─────────────────────────────────────────────────────────────

fn atproto_error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"error": code, "message": message}))).into_response()
}

// ── GET /.well-known/did.json ─────────────────────────────────────────────────

async fn did_document(State(state): State<AppState>) -> Json<Value> {
    let host = state
        .server_url
        .strip_prefix("http://")
        .unwrap_or(&state.server_url);
    let did = format!("did:web:{}", host.replace(':', "%3A"));
    let pds_url = state
        .pds_endpoint_override
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| state.server_url.clone());

    Json(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_url,
        }]
    }))
}

// ── GET /:did — per-user DID document (PLC directory compatible) ──────────────
//
// Drawbridge's PLCResolver resolves `did:plc:*` DIDs by hitting
// `{PLC_BASE_URL}/{did}`.  When `PLC_BASE_URL` is set to Postern's address
// (via `proxy-db-verify`), this handler returns the DID document for any
// pre-configured account DID.

async fn did_document_for_user(
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> Response {
    let store = match state.store.read() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    let exists = store.handles_contain_did(&did);
    drop(store);

    if !exists {
        return atproto_error(StatusCode::NOT_FOUND, "NotFound", "DID not found");
    }

    let pds_url = state
        .pds_endpoint_override
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| state.server_url.clone());

    Json(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_url,
        }]
    }))
    .into_response()
}

// ── GET /xrpc/com.atproto.identity.resolveHandle ─────────────────────────────

#[derive(Deserialize)]
struct ResolveHandleParams {
    handle: String,
}

async fn resolve_handle(
    State(state): State<AppState>,
    Query(p): Query<ResolveHandleParams>,
) -> Response {
    let store = match state.store.read() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    match store.resolve_handle(&p.handle) {
        Some(did) => Json(json!({ "did": did })).into_response(),
        None => atproto_error(StatusCode::BAD_REQUEST, "InvalidHandle", "Handle not found"),
    }
}

// ── POST /xrpc/com.atproto.repo.createRecord ─────────────────────────────────

#[derive(Deserialize)]
struct CreateRecordInput {
    repo: String,
    collection: String,
    rkey: Option<String>,
    record: Value,
}

async fn create_record(
    State(state): State<AppState>,
    Json(input): Json<CreateRecordInput>,
) -> Response {
    let mut store = match state.store.write() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    let rkey = input.rkey.unwrap_or_else(|| store.next_rkey());
    let record_json = serde_json::to_vec(&input.record).unwrap_or_default();
    let cid = compute_cid(&record_json);
    store.put_record(&input.repo, &input.collection, &rkey, input.record);
    let uri = format!("at://{}/{}/{}", input.repo, input.collection, rkey);
    Json(json!({
        "uri": uri,
        "cid": cid,
        "validationStatus": "unknown",
    }))
    .into_response()
}

// ── POST /xrpc/com.atproto.repo.putRecord ─────────────────────────────────────

#[derive(Deserialize)]
struct PutRecordInput {
    repo: String,
    collection: String,
    rkey: String,
    record: Value,
}

async fn put_record(
    State(state): State<AppState>,
    Json(input): Json<PutRecordInput>,
) -> Response {
    let mut store = match state.store.write() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    let record_json = serde_json::to_vec(&input.record).unwrap_or_default();
    let cid = compute_cid(&record_json);
    store.put_record(&input.repo, &input.collection, &input.rkey, input.record);
    let uri = format!("at://{}/{}/{}", input.repo, input.collection, input.rkey);
    Json(json!({
        "uri": uri,
        "cid": cid,
        "validationStatus": "unknown",
    }))
    .into_response()
}

// ── GET /xrpc/com.atproto.repo.getRecord ─────────────────────────────────────

#[derive(Deserialize)]
struct GetRecordParams {
    repo: String,
    collection: String,
    rkey: String,
}

async fn get_record(
    State(state): State<AppState>,
    Query(p): Query<GetRecordParams>,
) -> Response {
    let store = match state.store.read() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    match store.get_record(&p.repo, &p.collection, &p.rkey) {
        Some(v) => {
            let mut value = v.clone();
            strip_bytes_padding(&mut value);
            let uri = format!("at://{}/{}/{}", p.repo, p.collection, p.rkey);
            let cid = compute_cid(&serde_json::to_vec(&value).unwrap_or_default());
            Json(json!({ "uri": uri, "cid": cid, "value": value })).into_response()
        }
        None => atproto_error(StatusCode::NOT_FOUND, "RecordNotFound", "Record not found"),
    }
}

// ── GET /xrpc/com.atproto.repo.listRecords ───────────────────────────────────

#[derive(Deserialize)]
struct ListRecordsParams {
    repo: String,
    collection: String,
    limit: Option<usize>,
    cursor: Option<String>,
    /// Inclusive lower bound on rkey (ATProto: `rkeyStart`).
    #[serde(alias = "rkeyStart")]
    rkey_start: Option<String>,
    /// Inclusive upper bound on rkey (ATProto: `rkeyEnd`). Accepted but not yet applied.
    #[serde(alias = "rkeyEnd")]
    rkey_end: Option<String>,
    reverse: Option<bool>,
}

async fn list_records(
    State(state): State<AppState>,
    Query(p): Query<ListRecordsParams>,
) -> Response {
    let _ = (p.rkey_end, p.reverse); // accepted, not yet implemented
    let store = match state.store.read() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    let limit = p.limit.unwrap_or(50).min(100);
    let (records, next_cursor) = store.list_records(
        &p.repo,
        &p.collection,
        limit,
        p.cursor.as_deref(),
        p.rkey_start.as_deref(),
    );

    let items: Vec<Value> = records
        .into_iter()
        .map(|(rkey, mut val)| {
            strip_bytes_padding(&mut val);
            let uri = format!("at://{}/{}/{}", p.repo, p.collection, rkey);
            let cid = compute_cid(&serde_json::to_vec(&val).unwrap_or_default());
            json!({ "uri": uri, "cid": cid, "value": val })
        })
        .collect();

    let mut body = json!({ "records": items });
    if let Some(cursor) = next_cursor {
        body["cursor"] = json!(cursor);
    }
    Json(body).into_response()
}

// ── POST /xrpc/com.atproto.repo.deleteRecord ─────────────────────────────────

#[derive(Deserialize)]
struct DeleteRecordInput {
    repo: String,
    collection: String,
    rkey: String,
}

async fn delete_record(
    State(state): State<AppState>,
    Json(input): Json<DeleteRecordInput>,
) -> Response {
    let mut store = match state.store.write() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    store.delete_record(&input.repo, &input.collection, &input.rkey);
    Json(json!({})).into_response()
}

// ── POST /xrpc/com.atproto.repo.uploadBlob ───────────────────────────────────
//
// Auth is skipped — any caller may upload.  Blobs are stored globally by CID
// (content-addressed), so the `did` is not needed at upload time.

async fn upload_blob(State(state): State<AppState>, body: Bytes) -> Response {
    let size = body.len();
    let data = body.to_vec();

    let mut store = match state.store.write() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    let cid = store.put_blob(data);

    Json(json!({
        "blob": {
            "$type": "blob",
            "ref": { "$link": cid },
            "mimeType": "application/octet-stream",
            "size": size,
        }
    }))
    .into_response()
}

// ── GET /xrpc/com.atproto.sync.getBlob ───────────────────────────────────────

#[derive(Deserialize)]
struct GetBlobParams {
    /// Accepted for ATProto compatibility; not used for lookup.
    did: Option<String>,
    cid: String,
}

async fn get_blob(
    State(state): State<AppState>,
    Query(p): Query<GetBlobParams>,
) -> Response {
    let _ = p.did;
    let store = match state.store.read() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };
    match store.get_blob(&p.cid).cloned() {
        Some(data) => {
            drop(store);
            ([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response()
        }
        None => atproto_error(StatusCode::NOT_FOUND, "BlobNotFound", "Blob not found"),
    }
}

// ── POST /xrpc/com.atproto.server.createSession ──────────────────────────────

#[derive(Deserialize)]
struct CreateSessionInput {
    identifier: String,
    password: Option<String>,
}

async fn create_session(
    State(state): State<AppState>,
    Json(input): Json<CreateSessionInput>,
) -> Response {
    let store = match state.store.read() {
        Ok(s) => s,
        Err(_) => {
            return atproto_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store lock poisoned",
            )
        }
    };

    // Accept either handle or DID in `identifier`.
    let (did, handle) = if input.identifier.starts_with("did:") {
        // Reverse-lookup handle for the given DID
        let handle = store
            .resolve_did(&input.identifier)
            .unwrap_or_else(|| input.identifier.clone());
        (input.identifier.clone(), handle)
    } else {
        match store.resolve_handle(&input.identifier) {
            Some(did) => (did.clone(), input.identifier.clone()),
            None => {
                return atproto_error(
                    StatusCode::UNAUTHORIZED,
                    "AuthenticationRequired",
                    "Handle not found",
                )
            }
        }
    };

    // No password validation — this is a test PDS.
    let _ = input.password;

    // Note: `didDoc` is intentionally omitted — atrium parses it via an
    // IPLD-aware decoder that rejects non-CID strings, which would cause
    // a multihash parse error for test DIDs like `did:test:alice`.
    Json(serde_json::json!({
        "did": did,
        "handle": handle,
        "accessJwt": "postern-access-jwt",
        "refreshJwt": "postern-refresh-jwt",
    }))
    .into_response()
}

// ── POST /xrpc/com.atproto.server.refreshSession ─────────────────────────────

async fn refresh_session() -> Response {
    // Postern sessions never expire; just return a fresh token pair.
    Json(serde_json::json!({
        "accessJwt": "postern-access-jwt",
        "refreshJwt": "postern-refresh-jwt",
    }))
    .into_response()
}

// ── GET /xrpc/com.atproto.server.describeServer ───────────────────────────────

async fn describe_server(State(state): State<AppState>) -> Json<Value> {
    let drawbridge_url = state.drawbridge_url.lock().unwrap().clone();
    let services = match drawbridge_url {
        Some(url) => json!({
            "social.moat.drawbridge": {
                "type": "DrawbridgeService",
                "endpoint": url,
            }
        }),
        None => json!({}),
    };
    Json(json!({
        "availableUserDomains": [],
        "services": services,
    }))
}

// ── Router ────────────────────────────────────────────────────────────────────

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/did.json", get(did_document))
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle),
        )
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(create_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route(
            "/xrpc/com.atproto.repo.createRecord",
            post(create_record),
        )
        .route(
            "/xrpc/com.atproto.repo.putRecord",
            post(put_record),
        )
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route(
            "/xrpc/com.atproto.repo.deleteRecord",
            post(delete_record),
        )
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(upload_blob),
        )
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        // PLC-directory-compatible per-user DID document lookup.
        // Drawbridge hits `{PLC_BASE_URL}/{did}` to resolve test DIDs.
        .route("/{did}", get(did_document_for_user))
        .with_state(state)
}

// ── spawn_postern ─────────────────────────────────────────────────────────────

/// Spawn a Postern PDS instance and return a handle to it.
///
/// The server is ready to accept connections when this function returns.
/// It shuts down gracefully when the returned [`PosternHandle`] is dropped.
pub async fn spawn_postern(config: PosternConfig) -> PosternHandle {
    // Resolve the data directory.
    let data_dir = config.data_dir.unwrap_or_else(|| {
        let ts = Utc::now().format("%Y-%m-%dT%H-%M-%S%.3f").to_string();
        PathBuf::from(format!("/tmp/postern/{}", ts))
    });
    std::fs::create_dir_all(&data_dir).expect("failed to create postern data dir");

    // Build the in-memory store.
    let store = Arc::new(RwLock::new(Store::new(&config.accounts)));

    // Bind the TCP listener.
    let addr = format!("127.0.0.1:{}", config.port.unwrap_or(0));
    let listener = TcpListener::bind(&addr)
        .await
        .expect("failed to bind postern listener");
    let local_addr = listener.local_addr().expect("no local address");
    let server_url = format!("http://127.0.0.1:{}", local_addr.port());

    let pds_endpoint_override: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let drawbridge_url: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let state = AppState {
        store,
        server_url: server_url.clone(),
        pds_endpoint_override: pds_endpoint_override.clone(),
        drawbridge_url: drawbridge_url.clone(),
    };
    let app = build_router(state);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("postern server error");
    });

    PosternHandle {
        url: server_url,
        data_dir,
        shutdown: Some(shutdown_tx),
        pds_endpoint_override,
        drawbridge_url,
    }
}
