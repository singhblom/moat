//! axum HTTP server and all XRPC handlers.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

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

// ── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    store: SharedStore,
    server_url: String,
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

    Json(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": state.server_url,
        }]
    }))
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
    store.put_record(&input.repo, &input.collection, &rkey, input.record);
    let uri = format!("at://{}/{}/{}", input.repo, input.collection, rkey);
    Json(json!({
        "uri": uri,
        "cid": "bafyplaceholder",
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
        Some(value) => {
            let uri = format!("at://{}/{}/{}", p.repo, p.collection, p.rkey);
            Json(json!({ "uri": uri, "cid": "bafyplaceholder", "value": value }))
                .into_response()
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
        .map(|(rkey, val)| {
            let uri = format!("at://{}/{}/{}", p.repo, p.collection, rkey);
            json!({ "uri": uri, "cid": "bafyplaceholder", "value": val })
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

// ── Router ────────────────────────────────────────────────────────────────────

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/did.json", get(did_document))
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle),
        )
        .route(
            "/xrpc/com.atproto.repo.createRecord",
            post(create_record),
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

    let state = AppState {
        store,
        server_url: server_url.clone(),
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
    }
}
