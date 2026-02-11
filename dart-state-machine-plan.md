# Dart Message State Machine Refactor

## Problem

The current Flutter message handling has two independent writers to storage (PollingService and MessagesProvider), two sources of truth (disk and in-memory list), and no coordination between them. This causes:

1. **Storage write races** — `addMessages` fires `_storage.appendMessages()` without awaiting, while `sendReaction` fires `_storage.saveMessages()` without awaiting. Concurrent writes do load-modify-save independently; the second overwrites the first.
2. **Dual-write divergence** — PollingService writes to storage then notifies the provider, and the provider also writes to storage. Every polled message gets written twice.
3. **Fragile own-message dedup** — Matches on `content == message.content && m.isOwn`, so sending identical text twice causes the second polling echo to be incorrectly deduplicated.
4. **No single owner** — The provider treats `_messages` as the UI source of truth, storage is the persistence source of truth, and they can silently diverge.

## Solution: ConversationRepository + ConversationManager

### Architecture overview

Three new classes replace the current `MessagesProvider` + `MessageNotifier` duo:

- **`ConversationRepository`** — Single owner of all message state for one conversation. Replaces `MessagesProvider` entirely (collapsed into one class). Extends `ChangeNotifier` so the UI can listen directly.
- **`ConversationManager`** — Global singleton that manages `ConversationRepository` lifecycle. Replaces `MessageNotifier`. Holds a `Map<String, ConversationRepository>` and lazily creates repos on first access.
- **`SendQueue`** — Separate non-notifier class that handles send orchestration (queuing, sequential processing, retry). Owns a `SendService` reference. Each `ConversationRepository` has one.

### Key design decisions

1. **Single class for UI** — `MessagesProvider` is eliminated. `ConversationRepository` is the only `ChangeNotifier` the UI listens to. No two-level notification chain.
2. **Global, lazily-created repositories** — `ConversationManager` creates repositories on first access (from either polling or screen navigation). Repos persist across screen navigation.
3. **Lazy load/unload of persisted messages** — Background repos are lightweight. The full `_persisted` list is only loaded from disk when the screen opens. For background polling, `mergeFromPolling()` appends directly to storage (serialized) without loading the full message list. This keeps inactive repos near-zero memory cost. (Future: pagination for large conversations with media.)
4. **All event types through the same path** — Messages, reactions, and future event types (images, videos, voice messages, stickers) all follow the same code path through the repository. The architecture makes no distinction between event types in the send/receive/persist flow. This ensures bugs are fixed once for all event types.
5. **Reactions embedded on messages for display** — At the protocol level, reactions are events on the conversation chain. For display, they are coupled to their target messages (merged onto the `Message` model's `reactions` field). The repository handles this merging internally.
6. **MLS events stay in PollingService** — Commits, epoch updates, and tag derivation are MLS protocol concerns. They stay in `PollingService`. `ConversationRepository` only handles user-visible events (messages, reactions, future media).

### New file: `lib/services/conversation_repository.dart`

```dart
/// Single owner of message state for a conversation.
/// All mutations go through this class; storage writes are serialized.
/// Replaces MessagesProvider — the UI listens to this directly.
class ConversationRepository extends ChangeNotifier {
  final String groupIdHex;
  final MessageStorage _storage;
  final SendQueue _sendQueue;

  List<Message> _persisted = [];        // Source of truth (matches disk)
  List<Message> _optimistic = [];       // Local-only, not yet confirmed
  bool _loaded = false;                 // Whether _persisted is loaded from disk
  bool _isLoading = false;
  String? _error;

  // Write serialization
  Future<void>? _pendingWrite;

  /// The merged view for the UI: persisted + optimistic, sorted.
  /// Only available when loaded. Returns empty list if not loaded.
  List<Message> get messages {
    if (!_loaded) return List.unmodifiable(_optimistic);
    final merged = <Message>[];
    merged.addAll(_persisted);
    for (final opt in _optimistic) {
      if (!_persisted.any((p) => p.messageId == opt.messageId && opt.messageId != null)) {
        merged.add(opt);
      }
    }
    merged.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return List.unmodifiable(merged);
  }

  bool get isLoading => _isLoading;
  String? get error => _error;

  /// Load persisted messages from disk. Called when screen opens.
  /// Drops any messages with status sending or failed (stale from previous session).
  Future<void> loadMessages() async { ... }

  /// Unload persisted messages from memory. Called when screen closes.
  /// Repo stays alive in ConversationManager but releases memory.
  void unloadMessages() { ... }
}
```

### Core principles

1. **Serialized writes** — All disk writes go through `_enqueueWrite()` which chains futures so only one write runs at a time:

```dart
Future<void> _enqueueWrite(Future<void> Function() op) {
  final prev = _pendingWrite ?? Future.value();
  _pendingWrite = prev.then((_) => op());
  return _pendingWrite!;
}
```

2. **Optimistic messages are separate** — They live in `_optimistic` and are merged into the `messages` getter for display. They never touch disk. When the real message arrives (matched by MLS `messageId`), the optimistic entry is removed and the persisted entry takes over.

3. **Two-step own-message dedup via MLS messageId** —
   - User sends → optimistic message created (no `messageId` yet), shown in UI immediately
   - `SendService` returns → optimistic message updated with `messageId` from MLS encryption
   - Polling delivers our echo → `mergeFromPolling` matches on `messageId`, removes optimistic entry, adds persisted entry

4. **Single write path** — Both polling and send flow through the same repository methods:

```dart
/// Called by polling when new/updated messages arrive.
/// If loaded: merges into persisted list and saves to disk.
/// If not loaded: appends directly to storage (serialized).
Future<void> mergeFromPolling(List<Message> incoming) async { ... }

/// Called when user sends a message. Adds to optimistic list immediately.
void addOptimistic(Message message) { ... }

/// Called when send succeeds. Updates optimistic message with messageId.
void confirmSent(String localId, Message confirmed) { ... }

/// Called when send fails. Updates optimistic message status.
void markFailed(String localId) { ... }

/// Called when a reaction event is received (from polling or own send).
/// Toggles reaction on the target message and persists.
Future<void> applyReaction(String targetMessageId, String emoji, String senderDid) async { ... }
```

5. **Error surfacing** — If a disk write fails, the repository sets `_error` and calls `notifyListeners()`. The UI can display the error (e.g., "Unable to save messages"). Messages remain in memory even if persistence fails.

6. **Stale message cleanup on load** — When `loadMessages()` reads from disk, any messages with `status: sending` or `status: failed` are dropped. These are stale optimistic messages from a previous app session that were never meant to be persisted (but may have leaked through a bug). The user re-types if needed.

### New file: `lib/services/send_queue.dart`

```dart
/// Handles send orchestration: queuing, sequential processing, retry.
/// Owns a SendService reference. Not a ChangeNotifier — communicates
/// back to ConversationRepository via callbacks.
class SendQueue {
  final SendService _sendService;
  final List<PendingMessage> _queue = [];
  bool _isProcessing = false;

  /// Enqueue a message for sending. Returns immediately.
  void enqueue(PendingMessage pending) { ... }

  /// Retry a failed message by localId.
  void retry(String localId) { ... }

  /// Process queue sequentially. On success, calls onSent callback.
  /// On failure, calls onFailed callback and stops processing.
  Future<void> _processQueue() async { ... }

  // Callbacks set by ConversationRepository
  void Function(String localId, Message confirmed)? onSent;
  void Function(String localId)? onFailed;
}
```

### New file: `lib/services/conversation_manager.dart`

```dart
/// Global singleton managing ConversationRepository lifecycle.
/// Replaces MessageNotifier.
class ConversationManager {
  static final ConversationManager instance = ConversationManager._();

  final Map<String, ConversationRepository> _repos = {};
  final MessageStorage _storage;

  /// Get or lazily create a repository for a conversation.
  ConversationRepository getRepository(String groupIdHex) {
    return _repos.putIfAbsent(groupIdHex, () =>
      ConversationRepository(
        groupIdHex: groupIdHex,
        storage: _storage,
        sendQueue: SendQueue(sendService),
      ));
  }

  /// Called by PollingService when new messages arrive.
  /// Routes to the appropriate repository (creating it if needed).
  void notify(String groupIdHex, List<Message> messages) {
    getRepository(groupIdHex).mergeFromPolling(messages);
  }

  /// Called by PollingService when a reaction event arrives.
  void notifyReaction(String groupIdHex, String targetMessageId, String emoji, String senderDid) {
    getRepository(groupIdHex).applyReaction(targetMessageId, emoji, senderDid);
  }

  /// Dispose a repository (e.g., when conversation is deleted).
  void remove(String groupIdHex) {
    _repos.remove(groupIdHex)?.dispose();
  }
}
```

### Changes to existing files

#### `MessagesProvider` — DELETED

`ConversationRepository` replaces it entirely. All references in `ConversationScreen` and elsewhere change from `MessagesProvider` to `ConversationRepository`.

#### `MessageNotifier` — DELETED

`ConversationManager` replaces it entirely. `PollingService` routes through `ConversationManager.notify()` instead of `MessageNotifier.notify()`.

#### `PollingService` — simplified

Stops writing to `MessageStorage` directly. All message and reaction events route through `ConversationManager`:

```dart
// Before (two writers):
await _messageStorage.appendMessage(groupIdHex, message);
onNewMessages?.call(groupIdHex, [message]);

// After (single writer via ConversationManager):
ConversationManager.instance.notify(groupIdHex, [message]);

// Before (reaction):
await _messageStorage.toggleReaction(groupIdHex, targetMessageId, emoji, senderDid);
onNewMessages?.call(groupIdHex, [updatedMessage]);

// After:
ConversationManager.instance.notifyReaction(groupIdHex, targetMessageId, emoji, senderDid);
```

MLS-level events (commits, epoch updates, tag derivation) stay in `PollingService` unchanged.

#### `ConversationScreen` — minor changes

Switches from `context.watch<MessagesProvider>()` to `context.watch<ConversationRepository>()`. Calls `repo.loadMessages()` on open and `repo.unloadMessages()` on dispose.

### Migration plan (incremental commits)

1. **Create `ConversationRepository`** — New file with serialized writes, optimistic/persisted separation, lazy load/unload. Unit tests for core operations (merge, optimistic, confirm, fail, reaction).
2. **Create `SendQueue`** — New file with sequential processing, retry logic, callbacks. Unit tests.
3. **Create `ConversationManager`** — New file replacing `MessageNotifier`. Lazy repo creation, routing methods. Unit tests.
4. **Wire `ConversationScreen` to `ConversationRepository`** — Replace `MessagesProvider` usage in UI. Load/unload lifecycle.
5. **Wire `PollingService` to `ConversationManager`** — Remove direct `MessageStorage` usage from PollingService for messages and reactions. Integration tests for the full send/receive/persist flow.
6. **Delete `MessagesProvider` and `MessageNotifier`** — Remove dead code. Final cleanup.

Each step produces a working app and is a separately testable commit.

### What stays the same

- `MessageStorage` (native/web) — unchanged, still the disk persistence layer
- `SendService` — unchanged, still handles crypto + publish
- `Message` model — unchanged (reactions remain embedded for display)
- `PollingService` — simplified (no longer writes to storage directly) but still owns MLS event handling

### Invariants this design enforces

- **Single writer**: Only `ConversationRepository` calls `MessageStorage` methods
- **Serialized writes**: `_enqueueWrite` prevents concurrent load-modify-save
- **Optimistic/persisted separation**: Optimistic messages never leak to disk
- **MLS messageId matching**: No content-based dedup; own messages matched by MLS messageId after encryption
- **UI always sees merged view**: `messages` getter combines both lists, always sorted
- **Event-type agnostic**: Messages, reactions, and future event types all follow the same code path
- **Stale cleanup**: Messages with sending/failed status are dropped on load from disk
- **Error visibility**: Disk write failures surface to the UI via `_error` + `notifyListeners()`
- **Lazy memory**: Persisted messages only loaded when screen is active; background repos are near-zero cost

### Testing plan

**Unit tests:**
- `ConversationRepository` — merge from polling (dedup, sort), optimistic add/confirm/fail, reaction apply, serialized writes (concurrent merges don't race), lazy load/unload, stale message cleanup on load, error surfacing on write failure
- `SendQueue` — sequential processing, retry, callback invocation, queue ordering
- `ConversationManager` — lazy repo creation, routing, disposal

**Integration tests:**
- Full send flow: user sends → optimistic in UI → SendService encrypts → confirmSent with messageId → polling echo arrives → optimistic replaced by persisted
- Full receive flow: polling delivers message → ConversationManager routes → repo merges → UI updates
- Reaction roundtrip: user sends reaction → optimistic toggle → polling echo → dedup (no double-toggle)
- Background receive: message arrives while screen is closed → repo appends to storage without loading full list → screen opens → loadMessages shows the message
- App restart: messages with sending/failed status are dropped on load
