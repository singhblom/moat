//! HTTP API server for headless / integration-test mode.
//!
//! Launched via `--http <addr>` instead of the TUI. Exposes the same `App`
//! state machine (MLS crypto, ATProto polling, Drawbridge) as REST endpoints.

use crate::app::{App, AppError, PollStats};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive},
        IntoResponse, Sse,
    },
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

// ── Shared state ──────────────────────────────────────────────────────────────

struct ServerState {
    app: Arc<tokio::sync::Mutex<App>>,
    event_broadcast: tokio::sync::broadcast::Sender<String>,
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginRequest {
    handle: String,
    password: String,
}

#[derive(Deserialize)]
struct CreateConversationRequest {
    recipient_handle: String,
}

#[derive(Deserialize)]
struct SetConversationRequest {
    group_id: Option<String>,
}

#[derive(Deserialize)]
struct SendMessageRequest {
    text: String,
}

#[derive(Deserialize)]
struct SendReactionRequest {
    emoji: String,
}

#[derive(Deserialize)]
struct WatchRequest {
    handle: String,
}

#[derive(Serialize)]
struct StatusResponse {
    logged_in: bool,
    handle: Option<String>,
    did: Option<String>,
}

#[derive(Serialize)]
struct ConversationDto {
    id: String,
    name: String,
    participant_did: String,
    epoch: u64,
    unread: usize,
}

#[derive(Serialize)]
struct MessageDto {
    from: String,
    content: String,
    timestamp: String,
    is_own: bool,
    sender_did: Option<String>,
    message_id: Option<String>,
}

// ── Error helper ─────────────────────────────────────────────────────────────

fn app_err(e: AppError) -> (StatusCode, Json<Value>) {
    let status = match &e {
        AppError::NotLoggedIn => StatusCode::UNAUTHORIZED,
        AppError::NoConversation => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": e.to_string() })))
}

type HandlerResult<T> = Result<T, (StatusCode, Json<Value>)>;

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn post_login(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<LoginRequest>,
) -> HandlerResult<Json<Value>> {
    let mut app = state.app.lock().await;
    app.api_login(&body.handle, &body.password)
        .await
        .map_err(app_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn post_logout(State(state): State<Arc<ServerState>>) -> Json<Value> {
    let mut app = state.app.lock().await;
    app.client = None;
    app.logged_in_handle = None;
    Json(json!({ "ok": true }))
}

async fn get_status(State(state): State<Arc<ServerState>>) -> Json<StatusResponse> {
    let app = state.app.lock().await;
    let did = app.client.as_ref().map(|c| c.did().to_string());
    Json(StatusResponse {
        logged_in: app.client.is_some(),
        handle: app.logged_in_handle.clone(),
        did,
    })
}

async fn get_conversations(State(state): State<Arc<ServerState>>) -> Json<Vec<ConversationDto>> {
    let app = state.app.lock().await;
    let dtos = app
        .conversations
        .iter()
        .map(|c| ConversationDto {
            id: c.id.clone(),
            name: c.name.clone(),
            participant_did: c.participant_did.clone(),
            epoch: c.current_epoch,
            unread: c.unread,
        })
        .collect();
    Json(dtos)
}

async fn post_conversations(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<CreateConversationRequest>,
) -> HandlerResult<Json<Value>> {
    let mut app = state.app.lock().await;
    let group_id = app
        .api_start_conversation(&body.recipient_handle)
        .await
        .map_err(app_err)?;
    Ok(Json(json!({ "group_id": group_id })))
}

async fn delete_conversation(
    State(state): State<Arc<ServerState>>,
    Path(group_id): Path<String>,
) -> HandlerResult<Json<Value>> {
    let mut app = state.app.lock().await;
    app.api_delete_conversation(&group_id).map_err(app_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn put_conversation(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<SetConversationRequest>,
) -> HandlerResult<Json<Value>> {
    let mut app = state.app.lock().await;
    app.api_set_active_conversation(body.group_id.as_deref())
        .map_err(app_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_messages(
    State(state): State<Arc<ServerState>>,
    Path(group_id): Path<String>,
) -> Json<Vec<MessageDto>> {
    let app = state.app.lock().await;
    let msgs = app.api_get_messages(&group_id);
    let dtos = msgs
        .into_iter()
        .map(|m| MessageDto {
            from: if m.is_own {
                "You".to_string()
            } else {
                m.sender_did.clone().unwrap_or_else(|| "Unknown".to_string())
            },
            content: m.content,
            timestamp: m.timestamp.to_rfc3339(),
            is_own: m.is_own,
            sender_did: m.sender_did,
            message_id: m.message_id.map(|id| hex::encode(&id)),
        })
        .collect();
    Json(dtos)
}

async fn post_message(
    State(state): State<Arc<ServerState>>,
    Path(group_id): Path<String>,
    Json(body): Json<SendMessageRequest>,
) -> HandlerResult<Json<Value>> {
    let mut app = state.app.lock().await;
    // Ensure the right conversation is active
    app.api_set_active_conversation(Some(&group_id))
        .map_err(app_err)?;
    app.api_send_message(body.text).map_err(app_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn post_reaction(
    State(state): State<Arc<ServerState>>,
    Path((group_id, message_id)): Path<(String, String)>,
    Json(body): Json<SendReactionRequest>,
) -> HandlerResult<Json<Value>> {
    let mut app = state.app.lock().await;
    app.api_set_active_conversation(Some(&group_id))
        .map_err(app_err)?;
    app.api_send_reaction(&message_id, &body.emoji)
        .await
        .map_err(app_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_watch(State(state): State<Arc<ServerState>>) -> Json<Vec<String>> {
    let app = state.app.lock().await;
    Json(app.api_watched_dids())
}

async fn post_watch(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<WatchRequest>,
) -> HandlerResult<Json<Value>> {
    let mut app = state.app.lock().await;
    app.api_watch_handle(&body.handle).await.map_err(app_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn delete_watch(
    State(state): State<Arc<ServerState>>,
    Path(did): Path<String>,
) -> Json<Value> {
    let mut app = state.app.lock().await;
    app.api_unwatch_did(&did);
    Json(json!({ "ok": true }))
}

async fn post_poll_interval(
    State(state): State<Arc<ServerState>>,
    Path(seconds): Path<u64>,
) -> Json<Value> {
    let mut app = state.app.lock().await;
    app.api_set_poll_interval(seconds);
    Json(json!({ "ok": true, "poll_interval_seconds": seconds }))
}

async fn post_poll(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let rx = {
        let mut app = state.app.lock().await;
        let (tx, rx) = tokio::sync::oneshot::channel::<PollStats>();
        app.pending_poll_result = Some(tx);
        if !app.poll_in_flight {
            app.spawn_poll_messages();
        }
        rx
    }; // lock released — event loop can now process PollFetched

    match tokio::time::timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(stats)) => Json(json!({
            "new_messages": stats.new_messages,
            "new_conversations": stats.new_conversations,
        }))
        .into_response(),
        _ => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({ "error": "poll timed out" })),
        )
            .into_response(),
    }
}

async fn get_events(
    State(state): State<Arc<ServerState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, std::convert::Infallible>>> {
    let rx = state.event_broadcast.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|r| {
        r.ok().map(|data| Ok(SseEvent::default().data(data)))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ── Headless event loop ───────────────────────────────────────────────────────

fn is_async_bg_event(ev: &crate::app::BgEvent) -> bool {
    matches!(
        ev,
        crate::app::BgEvent::DrawbridgeConnectOwn { .. }
            | crate::app::BgEvent::DrawbridgeHandleHint { .. }
            | crate::app::BgEvent::DrawbridgeUpdateTags { .. }
            | crate::app::BgEvent::DrawbridgeNotifyEventPosted { .. }
            | crate::app::BgEvent::DrawbridgeRetryDisconnected
    )
}

fn spawn_headless_loop(app: Arc<tokio::sync::Mutex<App>>) {
    tokio::spawn(async move {
        loop {
            let mut async_evs = Vec::new();
            {
                let mut app = app.lock().await;
                while let Ok(ev) = app.bg_rx.try_recv() {
                    if is_async_bg_event(&ev) {
                        async_evs.push(ev);
                    } else {
                        app.handle_bg_event(ev);
                    }
                }
                app.tick();
            }
            for ev in async_evs {
                let mut app = app.lock().await;
                app.handle_bg_event_async(ev).await;
            }
            {
                let mut app = app.lock().await;
                if app.should_poll_devices() {
                    app.do_device_poll().await;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run_http(
    storage_dir: Option<PathBuf>,
    pds_url: Option<String>,
    drawbridge_url: Option<String>,
    addr: &str,
) -> anyhow::Result<()> {
    // halfblocks picker doesn't query the terminal, safe for headless use
    let picker = ratatui_image::picker::Picker::halfblocks();
    let mut app = App::new(storage_dir, pds_url, drawbridge_url, picker)?;

    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    app.event_broadcast = Some(broadcast_tx.clone());

    let app = Arc::new(tokio::sync::Mutex::new(app));

    spawn_headless_loop(app.clone());

    let state = Arc::new(ServerState {
        app,
        event_broadcast: broadcast_tx,
    });

    let router = Router::new()
        .route("/login", post(post_login))
        .route("/logout", post(post_logout))
        .route("/status", get(get_status))
        .route("/conversations", get(get_conversations))
        .route("/conversations", post(post_conversations))
        .route("/conversations/:group_id", delete(delete_conversation))
        .route("/conversation", put(put_conversation))
        .route("/conversations/:group_id/messages", get(get_messages))
        .route("/conversations/:group_id/messages", post(post_message))
        .route(
            "/conversations/:group_id/messages/:message_id/reactions",
            post(post_reaction),
        )
        .route("/watch", get(get_watch))
        .route("/watch", post(post_watch))
        .route("/watch/:did", delete(delete_watch))
        .route("/poll", post(post_poll))
        .route("/poll/:seconds", post(post_poll_interval))
        .route("/events", get(get_events))
        .with_state(state);

    println!("Moat HTTP API listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
