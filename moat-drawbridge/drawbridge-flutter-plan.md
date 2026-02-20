# Drawbridge Flutter Integration Plan

Informed by CLI integration learnings (see `drawbridge-cli-learnings.md`).

---

## Phase 0: Server-Side Fix (moat-drawbridge)

### 0.1 Include Request Path in Relay URL

The CLI had to add a `strip_url_path()` workaround because the server constructs its relay URL as `scheme://host` while clients connect to `scheme://host/ws`. Rather than requiring every client to strip the path, fix the server to include `req.URL.Path` in the relay URL used for challenge verification.

**Changes:**
- `relay.go`: `clientRelayURL()` appends `req.URL.Path` to the constructed URL
- `auth_test.go` / `relay_test.go`: update test URLs to include `/ws`
- `drawbridge_prop_test.go`: update property tests

**Coordinated client changes (simultaneous release):**
- `moat-cli`: remove `strip_url_path()` from `drawbridge.rs`, sign the full connection URL as-is
- No transition period needed — there are no deployed users yet

### 0.2 Verify Server CORS for Future Web Support

No CORS changes needed now (WebSocket upgrade bypasses CORS on native platforms). Web platform support is deferred to Phase 6.

---

## Phase 1: FFI Bindings (moat-flutter/rust)

### 1.1 Add Signing FFI

Add `sign_drawbridge_challenge` to `moat-flutter/rust/src/api/simple.rs`. This wraps `MoatSession::sign_drawbridge_challenge()` which is already in moat-core. The function takes the full `key_bundle` bytes (not just the signature key — this was a CLI lesson; the raw Ed25519 seed lives in the `signature_private_key` field of `KeyBundle`).

```rust
/// Sign a Drawbridge challenge. Returns (signature_bytes, public_key_bytes).
pub fn sign_drawbridge_challenge(
    key_bundle: Vec<u8>,
    message: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    MoatSession::sign_drawbridge_challenge(&key_bundle, &message)
        .map_err(|e| e.to_string())
}
```

### 1.2 Existing FFI Functions

Already implemented in `simple.rs`:
- `generate_drawbridge_ticket() -> Vec<u8>` — 32-byte random ticket
- `create_drawbridge_hint(handle, group_id, url, ticket) -> Result<EventDto, String>` — creates a DrawbridgeHint event
- `EventDto.drawbridge_hint_payload()` — extracts `DrawbridgeHintPayloadDto` with `(url, device_id, ticket)`

No additional FFI functions needed beyond 1.1.

---

## Phase 2: Dart Service

### 2.1 DrawbridgeService (Standalone Singleton)

Create `lib/services/drawbridge_service.dart` as a standalone singleton, consistent with the `ConversationManager` pattern. Initialized from `AuthGate` after login, not owned by `AuthProvider`.

```dart
class DrawbridgeService {
  static final DrawbridgeService instance = DrawbridgeService._();
  DrawbridgeService._();

  // --- Own Drawbridge (sender mode, DID challenge-response auth) ---
  WebSocketChannel? _ownConnection;
  StreamSubscription? _ownSubscription;

  // --- Partner Drawbridges (recipient mode, ticket auth) ---
  // Key: (url, ticketHex)
  final Map<(String, String), WebSocketChannel> _partnerConnections = {};
  final Map<(String, String), StreamSubscription> _partnerSubscriptions = {};

  /// Connect to own Drawbridge relay.
  /// [keyBundle] is the full key bundle bytes (not just signature key).
  Future<void> connectOwn(String url, String did, Uint8List keyBundle) async { ... }

  /// Connect to a partner's Drawbridge relay using a ticket.
  Future<void> connectPartner(String url, Uint8List ticket, List<Uint8List> tags) async { ... }

  /// Handle an incoming DrawbridgeHint (from PDS polling).
  Future<void> handleHint(DrawbridgeHintPayloadDto hint, String partnerDid, String groupIdHex) async { ... }

  /// Notify own relay that we posted an event (so partner gets new_event).
  Future<void> notifyEventPosted(Uint8List tag, String rkey) async { ... }

  /// Disconnect all connections (call on app background / logout).
  void disconnectAll() { ... }

  /// Reconnect all partner connections from persisted hints (call on app resume / login).
  Future<void> reconnectAll(Uint8List keyBundle) async { ... }
}
```

### 2.2 Challenge-Response Auth Flow (Own Relay)

When connecting to own relay:
1. Open WebSocket to the full URL (e.g. `wss://moat-drawbridge.fly.dev/ws`)
2. Send `{"type": "request_challenge", "did": "did:plc:..."}`
3. Receive `{"type": "challenge", "nonce": "..."}`
4. Construct message: `"{nonce}\n{url}\n{timestamp}\n"` — use the **full connection URL** (server fix in Phase 0 means no path stripping needed)
5. Call Rust FFI `sign_drawbridge_challenge(keyBundle, messageBytes)` → `(sigBytes, pubBytes)`
6. Base64-encode sig and pub, send `{"type": "challenge_response", ...}`
7. Receive `{"type": "authenticated"}`

### 2.3 Default Relay URL

Ship with a hardcoded default: `wss://moat-drawbridge.fly.dev/ws`. Allow override in a future settings screen for self-hosters. Store the configured URL in `SecureStorageService`.

### 2.4 Hint Storage (Conversation Metadata)

Store Drawbridge hints as part of each conversation's existing metadata rather than a separate file. A Drawbridge ticket is bound to a specific conversation partner in a specific conversation, so the lifecycle is naturally coupled.

Add to the conversation metadata (already stored per-group by `KeyStore`/`ConversationStorage`):
- `drawbridgeUrl: String?`
- `drawbridgeTicketHex: String?`
- `drawbridgeDeviceIdHex: String?`
- `ownTicketHex: String?` (the ticket we registered for this conversation on our own relay)

### 2.5 Automatic Ticket Registration

After creating a conversation (Welcome sent):
1. `generate_drawbridge_ticket()` via FFI
2. Register ticket on own Drawbridge via `register_ticket` message
3. Create DrawbridgeHint event via FFI
4. Publish hint to PDS via `AtprotoClient.publishEvent()`

This happens automatically with no user interaction.

### 2.6 Event Notification Flow

When a `new_event` notification arrives from a partner's Drawbridge:
- Signal `PollingService` to poll immediately (bump the timer)
- Do **not** fetch the specific event directly — reuse existing polling logic to avoid duplicating fetch/decrypt code
- `PollingService` handles dedup via rkey pagination

### 2.7 App Lifecycle

- **On login:** Initialize `DrawbridgeService`, connect to own relay, reconnect all partner relays from persisted hints
- **On app background:** `disconnectAll()` — tear down all WebSocket connections. Saves battery, avoids stale connections on mobile
- **On app resume:** `reconnectAll()` — re-establish connections. Brief latency spike is acceptable
- **On logout:** `disconnectAll()` and clear state

Use `WidgetsBindingObserver.didChangeAppLifecycleState` to detect background/resume.

---

## Phase 3: Integration with Existing Services

### 3.1 PollingService Integration

`PollingService` needs a `pollNow()` method (or equivalent) that `DrawbridgeService` can call when a `new_event` notification arrives. This skips the 5-second timer wait.

### 3.2 SendService Integration

After `SendService` publishes an event, call `DrawbridgeService.notifyEventPosted(tag, rkey)` to notify the own relay so the partner's Drawbridge gets a `new_event` push.

### 3.3 Conversation Creation Integration

After a Welcome is sent and the conversation is created, automatically run the ticket registration + hint publishing flow (Phase 2.5).

### 3.4 Event Processing — Hint Handling

When `PollingService` decrypts a `DrawbridgeHint` event from a partner:
1. Extract hint payload via `EventDto.drawbridge_hint_payload()`
2. Store in conversation metadata
3. Call `DrawbridgeService.handleHint()` to connect to the partner's relay

---

## Phase 4: Testing

### 4.1 Unit Tests (Dart)

- `DrawbridgeService` state management (hint storage, connection tracking)
- Challenge message construction (format matches `"{nonce}\n{url}\n{timestamp}\n"`)
- Hint parsing from `DrawbridgeHintPayloadDto`
- Conversation metadata roundtrip with drawbridge fields
- Reconnect logic (persisted hints → partner connections)

### 4.2 Rust FFI Tests

- `sign_drawbridge_challenge` end-to-end (sign + verify with `ed25519_dalek`)
- Signature over wrong message fails verification
- Invalid/old key bundle gives clear error

### 4.3 Property-Based Tests (Rust)

- For any random seed + message, `sign_drawbridge_challenge` produces a valid 64-byte signature that verifies against the returned 32-byte public key
- Different seeds produce different public keys
- Signature does not verify against wrong message

### 4.4 Integration Tests (Real Go Server)

Use a test script (`scripts/test-drawbridge-integration.sh`) that:
1. Starts the Go drawbridge server locally (`go run .` in `moat-drawbridge/`)
2. Runs Flutter integration tests that perform real WebSocket connect + challenge-response auth + ticket registration + event notification cycle
3. Tears down the server

### 4.5 Widget Tests

- Verify conversation creation triggers automatic Drawbridge ticket registration
- Verify incoming hint triggers partner connection
- Verify app lifecycle (background → disconnect, resume → reconnect)

---

## Phase 5: End-to-End Verification

Manual two-device test:
1. Alice creates conversation with Bob
2. Verify Alice's DrawbridgeHint is published to PDS
3. Bob processes Welcome + Hint, connects to Alice's relay
4. Alice sends message → Bob receives `new_event` notification → poll triggers → message appears
5. Kill and restart Bob's app → verify reconnection from persisted hints
6. Background Bob's app → verify WebSocket disconnect → foreground → verify reconnect

---

## Phase 6: Web Platform Support (Deferred)

Web support has additional complications beyond CORS:

### Known Issues

1. **CORS/COEP interaction** — The Flutter web app runs with `Cross-Origin-Embedder-Policy: require-corp` for SharedArrayBuffer (needed by WASM threading). WebSocket upgrade requests are not subject to CORS, but if the drawbridge server ever serves non-WebSocket HTTP responses (e.g. health checks from the same origin), COEP could block them.

2. **`web_socket_channel` on web** — Uses the browser's native WebSocket API, which works but has different error semantics than native. Connection failures surface as `CloseEvent` rather than OS-level socket errors, making reconnect detection different.

3. **Background tab throttling** — Browsers throttle timers and network activity in background tabs. WebSocket connections may be silently dropped after extended background periods, and reconnect timers may fire much less frequently than the configured interval.

4. **SharedArrayBuffer requirement** — The WASM Rust bridge requires SharedArrayBuffer (hence the COEP headers). If the drawbridge server is on a different origin, the browser may block the WebSocket if COEP is misconfigured. Need to verify that WebSocket connections to cross-origin servers work under `require-corp` COEP.

### Required Server Changes

- Verify WebSocket upgrade works with Flutter web's COEP headers
- Add `Access-Control-Allow-Origin` headers if needed for any preflight requests
- Test with `./scripts/run-web.sh` which sets the correct COEP/COOP headers

---

## Other Work (Out of Scope but Noted)

### Self-Published Tag Tracking

The CLI needed `own_published_tags: HashSet<[u8; 16]>` to skip self-decryption during polling (MLS cannot decrypt messages encrypted by the same device). The Flutter `PollingService` likely needs the same mechanism. Should be implemented but is not Drawbridge-specific.

### Event Ordering Verification

The CLI discovered that the PDS returns events in descending rkey order, requiring an ascending sort before processing so Welcomes are handled before DrawbridgeHints. The Flutter `AtprotoClient.fetchEvents()` already sorts by rkey ascending — verify this is correct and add a test if missing.

---

## Platform Support Summary

| Platform | WebSocket | Status |
|----------|-----------|--------|
| Android  | `web_socket_channel` | Supported (Phase 2–5) |
| iOS      | `web_socket_channel` | Supported (Phase 2–5) |
| Web      | `web_socket_channel` (browser native) | Deferred (Phase 6) |
