# Plan: Headless Dart HTTP Server for moat-beacon Integration Testing

## Context

moat-beacon drives moat-cli processes via HTTP using `MoatCliClient`. We want to test the Dart app's business logic the same way — by creating a headless Dart binary that exposes an identical HTTP API and is driven by the same `MoatCliClient`. The key constraint: the headless binary must exercise **the same code files** as moat-flutter, not a reimplementation.

A pure Dart package can't depend on a Flutter package (the Dart SDK won't resolve Flutter SDK dependencies). So we must extract the pure-Dart business logic into a shared package that both moat-flutter and the headless binary depend on.

Key enabler: `flutter_rust_bridge` 2.11.1 has **no Flutter SDK dependency** — its pubspec only lists pure Dart deps (args, async, meta, path, web). The FRB-generated FFI bindings can live in a pure Dart package.

## Target Architecture

A **Dart workspace** at `moat-dart/`, symmetric with the Rust `crates/` layout. Three member packages share a single `pubspec.lock` and unified dependency resolution.

```
moat-dart/                          # Dart workspace root
├── pubspec.yaml                    # workspace: [common, app, server]
├── common/                         # pure Dart package — shared business logic
│   ├── pubspec.yaml                # resolution: workspace; NO flutter SDK
│   └── lib/
│       ├── models/                 # MOVED from moat-flutter
│       ├── services/               # EXTRACTED from providers + MOVED services
│       ├── utils/                  # MOVED from moat-flutter
│       └── rust/                   # MOVED FRB-generated bindings
├── app/                            # Flutter app (was moat-flutter/)
│   ├── pubspec.yaml                # resolution: workspace; depends on common
│   └── lib/
│       ├── providers/              # ChangeNotifier wrappers around common services
│       ├── screens/                # Unchanged
│       ├── widgets/                # Unchanged
│       └── services/
│           └── flutter_storage_backend.dart  # FlutterSecureStorage impl
└── server/                         # Headless HTTP server binary
    ├── pubspec.yaml                # resolution: workspace; depends on common
    └── bin/
        └── moat_dart_server.dart   # CLI: --http, --storage-dir, --pds-url
```

All three packages exercise the **same service classes** in `common/`. The only differences are the storage backend (FlutterSecureStorage vs file-based) and the presentation layer (Flutter UI vs HTTP).

## Phase 1: Create workspace skeleton

**`moat-dart/pubspec.yaml`** (workspace root — no dependencies, just declares members):
```yaml
name: moat_dart_workspace
publish_to: none
environment:
  sdk: ">=3.5.0 <4.0.0"
workspace:
  - common
  - app
  - server
```

**`moat-dart/common/pubspec.yaml`**:
```yaml
name: moat_dart_common
publish_to: none
environment:
  sdk: ">=3.5.0 <4.0.0"
resolution: workspace
dependencies:
  flutter_rust_bridge: 2.11.1
  http: ^1.2.2
  web_socket_channel: ^3.0.3
  web: ^1.1.0
```

**`moat-dart/server/pubspec.yaml`**:
```yaml
name: moat_dart_server
publish_to: none
environment:
  sdk: ">=3.5.0 <4.0.0"
resolution: workspace
dependencies:
  moat_dart_common:
    path: ../common
  shelf: ^1.4.2
  shelf_router: ^1.1.4
  args: ^2.4.2
```

**`moat-dart/app/pubspec.yaml`** (was `moat-flutter/pubspec.yaml`): add `resolution: workspace` and
`moat_dart_common: path: ../common`. Remove `flutter_rust_bridge` (now in common). Keep all Flutter-specific deps.

**Migration**: `git mv moat-flutter moat-dart/app` — preserves full git history.

## Phase 2: Abstract storage and move pure-Dart code

### 2a. StorageBackend interface
**New file: `moat-dart/common/lib/services/storage_backend.dart`**
```dart
abstract class StorageBackend {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
  Future<void> deleteAll();
}
```

### 2b. FileStorageBackend
**New file: `moat-dart/common/lib/services/file_storage_backend.dart`**

Each key → file `<dir>/secure/<sanitized-key>.txt`. Plain text value.

### 2c. Adapt SecureStorageService
Takes `StorageBackend` instead of `FlutterSecureStorage`:
```dart
class SecureStorageService {
  final StorageBackend _storage;
  SecureStorageService({required StorageBackend storage}) : _storage = storage;
}
```

### 2d–2g. Adapt ConversationStorage, MessageStorage, move models and utils
- `ConversationStorage`: constructor-injected `Directory` (no path_provider)
- `MessageStorage`: already supports injected `Directory`, move as-is
- Models: pure Dart, move unchanged (`Conversation`, `Message`, `BlueskyProfile`)
- Utils: `message_payload.dart` pure Dart, move unchanged

### 2h. Move FRB bindings
Move `moat-flutter/lib/src/rust/` → `moat-dart/common/lib/rust/`. No changes needed (FRB is pure Dart).

### 2i. DebugLog
Simple implementation writing to stderr + optional file. No Flutter dependency.

## Phase 3: Extract business logic from providers

### 3a. AuthService
Extract from `auth_provider.dart` — same logic, no `ChangeNotifier`, no `notifyListeners()`.
Constructor takes `AtprotoClient` + `SecureStorageService`.
`CreateConversationResult` class moves here.

### 3b. ConversationsService
Extract from `conversations_provider.dart` — no `ChangeNotifier`, no `notifyListeners()`.
Constructor takes `ConversationStorage`.

### 3c. WatchListService
Extract from `watch_list_provider.dart` — no `ChangeNotifier`.
`WatchListEntry` class moves here. Constructor takes `SecureStorageService` + `AtprotoClient`.

## Phase 4: Adapt remaining services

### 4a. PollingService
- Replace `AuthProvider` → `AuthService`, providers → services
- Remove `flutter/foundation.dart` (VoidCallback → `void Function()`)
- Add `Future<PollStats> pollOnce()` returning `PollStats(newMessages, newConversations)`

### 4b–4c. SendService, SendQueue
- `SendService`: replace `AuthProvider` → `AuthService`
- `SendQueue`: add `sendDirect(text)` → `Future<Message>` (bypasses queue, for server use)

### 4d. ConversationRepository
Remove `extends ChangeNotifier` and all `notifyListeners()` calls. Add `sendMessageSync(text)` → `Future<Message>`.

### 4e. ConversationManager
Replace `AuthProvider` → `AuthService` in `init()`. Singleton pattern stays.

### 4f. AtprotoClient
Replace `debugPrint` with `moatLog()`. Add `pdsOverride` field: when set, `resolvePdsEndpoint()` returns it for all DIDs (needed for test environment).

### 4g. DrawbridgeService
Replace `dart:ui show VoidCallback` with `typedef VoidCallback = void Function();`.

### 4h. ProfileCacheService
Replace `path_provider` with constructor-injected `Directory`. Replace `debugPrint` with `moatLog()`.

## Phase 5: Build the headless HTTP server

**`moat-dart/server/bin/moat_dart_server.dart`**

CLI args:
- `--http <addr>` (required) — listen address
- `--storage-dir <path>` (required) — state directory
- `--pds-url <url>` — PDS endpoint override
- `--drawbridge-url <url>` — Drawbridge WebSocket URL
- `--lib-path <path>` — path to `librust_lib_moat_flutter.dylib`

Startup: parse args → `RustLib.init(externalLibrary: ExternalLibrary.open(libPath))` → create services → build shelf router → listen.

**`moat-dart/server/lib/http/server.dart`** — Shelf router:

| Method | Path | What it does |
|--------|------|--------------|
| POST | /login | `authService.login()`, init conversations + watch list |
| GET | /status | Return `{logged_in, handle, did}` |
| GET | /conversations | List from `convsService.conversations` |
| POST | /conversations | Resolve recipient → fetch keys → `authService.createConversation()` → publish welcome → save → return `{group_id}` |
| GET | /conversations/:id/messages | `loadMessages()` then return `.messages` |
| POST | /conversations/:id/messages | `repo.sendMessageSync(text)` — awaited |
| POST | /conversations/:id/messages/:mid/reactions | Send reaction |
| POST | /watch | `watchListService.addHandle(handle)` |
| POST | /poll | `pollingService.pollOnce()` → return `{new_messages, new_conversations}` |
| POST | /poll/:seconds | Set auto-poll interval (0 = disable) |

Background polling loop: `Timer.periodic` at configured interval.

## Phase 6: Update moat-dart/app/ to depend on common

After `git mv moat-flutter moat-dart/app`:
- Add `resolution: workspace` and `moat_dart_common` dep to `app/pubspec.yaml`
- Remove `flutter_rust_bridge` from app (now in common)
- New `app/lib/services/flutter_storage_backend.dart`: wraps `FlutterSecureStorage` as `StorageBackend`
- Providers become thin `ChangeNotifier` wrappers around common services
- Update import paths from relative to `package:moat_dart_common/...`

**Can be deferred if tests pass first.**

## Phase 7: moat-beacon integration

### 7a. Binary resolution in world.rs
`dart_server_binary() -> Result<PathBuf>`:
- Auto-builds Rust FFI lib: `cargo build -p rust_lib_moat_flutter`
- Auto-compiles Dart binary: `dart compile exe moat-dart/server/bin/moat_dart_server.dart -o target/moat-dart-server/moat_dart_server`

### 7b. TestWorld extension
Add `ParticipantKind { RustCli, DartServer }`. `spawn_participant` gains `kind` parameter.
When `DartServer`: uses dart binary path, adds `--lib-path`, same health check via `GET /status`.

### 7c. Test scenarios
- `dart_two_party_chat` — both participants are Dart
- `mixed_two_party_chat` — Alice=Rust, Bob=Dart
- Test files: `proptest_dart_two_party.rs`, `proptest_mixed.rs`

## Implementation Order

1. Update plan file ✓
2. `git mv moat-flutter moat-dart/app`
3. Phase 1 — workspace pubspec files
4. Phase 2a–2c — StorageBackend + FileStorageBackend + SecureStorageService
5. Phase 2d–2i — models, utils, FRB bindings, ConversationStorage, MessageStorage, DebugLog
6. Phase 3a — AuthService (largest extraction)
7. Phase 3b–3c — ConversationsService, WatchListService
8. Phase 4a — PollingService + pollOnce()
9. Phase 4b–4h — SendService, SendQueue, ConversationRepository, ConversationManager, DrawbridgeService, ProfileCacheService, AtprotoClient
10. `cd moat-dart && dart pub get` — verify common compiles
11. Phase 5 — HTTP server binary
12. `dart compile exe moat-dart/server/bin/moat_dart_server.dart` — verify
13. Phase 7a–7c — moat-beacon integration
14. Phase 6 — update app/ (deferred)

## Verification

1. `dart --version` → ≥ 3.5.0 ✓ (3.11.0)
2. `cd moat-dart && dart pub get` → resolves without Flutter SDK errors
3. `dart analyze moat-dart/common` → no errors
4. `dart analyze moat-dart/server` → no errors
5. `dart compile exe moat-dart/server/bin/moat_dart_server.dart -o /tmp/moat_dart_server` → success
6. Start server: `/tmp/moat_dart_server --http 127.0.0.1:9090 --storage-dir /tmp/moat-test --lib-path target/debug/librust_lib_moat_flutter.dylib`
7. `curl -s http://127.0.0.1:9090/status` → `{"logged_in":false}`
8. `cargo test -p moat-beacon --test smoke_dart` → green
9. `cargo test -p moat-beacon --test proptest_dart_two_party` → green
10. `cd moat-dart/app && flutter test` → existing tests still pass
