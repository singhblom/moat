# Moat Dart App Plan

A neat and simple messenger app built on top of the Moat APIs.

## Overview

- **Platform**: Flutter, Android first (API 29+ / Android 10+)
- **Project location**: `moat-flutter/` at repo root
- **UI style**: Minimal Material 3, clean and functional
- **CI**: Manual builds for now, CI comes later

## Architecture

### FFI Layer (moat-core)
- Use **flutter_rust_bridge (FRB) v2** to generate Dart bindings from moat-core's public API
- FRB reads Rust source directly — no annotations needed on moat-core types
- A thin `rust/src/api.rs` wrapper in the Flutter project re-exports moat-core's API for FRB codegen
- Compile Rust to Android native libraries (`.so`) via Cargokit (bundled with FRB)
- **UniFFI deferred**: Add UniFFI proc macro annotations later when Swift/Kotlin native targets are needed; FRB and UniFFI are non-conflicting

### State Ownership
- **Dart owns bytes**: Dart reads/writes persistent storage, passes byte buffers across FFI for crypto operations
- Rust moat-core stays stateless from the FFI perspective (takes bytes in, returns bytes out)

### Storage
- Use **flutter_secure_storage** (or equivalent) for sensitive data (keys, credentials)
- Standard app storage for non-sensitive data (conversation metadata, message history)

### Networking
- **Dart-native HTTP** for all ATProto calls (login, fetch/publish events, key packages, stealth addresses)
- Evaluate existing Dart ATProto packages on pub.dev before writing from scratch; fall back to minimal custom HTTP client if nothing fits

## Implementation Steps

Each step produces a working, testable app.

### Step 0: Foundation ✅ COMPLETE
- Install FRB codegen: `cargo install flutter_rust_bridge_codegen`
- Scaffold Flutter project: `flutter_rust_bridge_codegen create moat_flutter --template plugin`, then move to `moat-flutter/` at repo root
- Replace generated `rust/` crate with a dependency on `moat-core` (path = `../crates/moat-core`)
- Create thin `rust/src/api.rs` re-exporting moat-core's public API (MoatSession methods, free functions, types)
- Run FRB codegen: `flutter_rust_bridge_codegen generate` to produce Dart bindings in `lib/src/rust/`
- Write minimal Dart test calling `MoatSession.new()` and printing device ID
- Verify on Android emulator: `flutter run`
- Optionally add `moat-flutter/rust` to workspace `Cargo.toml` members

### Step 1: Login + Conversations List ✅ COMPLETE
- Implement ATProto login (handle + app password) in Dart HTTP ✅
- **Device name setup**: Prompt for device name on first launch (or auto-generate from device model) ✅
- Generate identity key and stealth key via FFI to moat-core ✅
- **Embed device name in key package**: Use `MoatCredential` with DID + device name when generating key package ✅
- Publish key package and stealth address to PDS ✅
- Display list of conversations from local storage (initially empty for new devices) ✅
- Secure storage for credentials, keys, and device name ✅
- **Note**: New devices start with no conversation history — they'll be added to groups by existing devices

### Step 2: Create & Join Conversations (Invites + Watch List) ✅ COMPLETE

This step must come before messaging because you need a conversation to test with. The invite system involves:

1. **Watch list** - Track DIDs you're expecting invites from ✅
2. **Stealth decryption** - Invites are encrypted with your stealth address (not MLS), so only you can decrypt ✅
3. **Random tags** - Invites use random tags (not group-derived), requiring special handling ✅

**Creating a conversation (as initiator):**
- New conversation flow: enter recipient handle ✅
- Resolve handle to DID, fetch stealth address + key package from PDS ✅
- Create MLS group via FFI, add recipient (generates Welcome message) ✅
- Encrypt Welcome with recipient's stealth address (`encrypt_for_stealth`) ✅
- Publish to PDS with **random 16-byte tag** (recipient doesn't know group yet) ✅
- Store conversation metadata, register epoch 1 tag for future messages ✅

**Receiving an invite (as recipient):**
- **Watch list UI**: Add DIDs to watch for incoming invites (resolve handle → DID) ✅
- Poll events from watched DIDs (separate from conversation participant polling) ✅
- For each event: attempt stealth decryption with local stealth key ✅
- On success: process MLS Welcome via FFI, join group ✅
- Add new conversation to list, register epoch 1 tag ✅
- **Remove DID from watch list** after successful join ✅

**Testing flow:**
1. Device A creates conversation with Device B
2. Device B adds Device A's handle to watch list
3. Device B polls → receives and decrypts invite → joins conversation
4. Both devices now share a conversation for testing Steps 3-4

### Step 3: Read Messages ✅ COMPLETE

**Implemented**: Fetch, decrypt, and display messages from existing conversations.

**Files created**:
- [message.dart](moat-flutter/lib/models/message.dart) - Message data model
- [message_storage.dart](moat-flutter/lib/services/message_storage.dart) - JSON file-based message persistence
- [message_service.dart](moat-flutter/lib/services/message_service.dart) - Decryption and message processing
- [messages_provider.dart](moat-flutter/lib/providers/messages_provider.dart) - State management for messages
- [conversation_screen.dart](moat-flutter/lib/screens/conversation_screen.dart) - Conversation detail UI with message list
- [message_bubble.dart](moat-flutter/lib/widgets/message_bubble.dart) - Message display widget (aligned left/right for sender)

**Key features**:
- Tag-based routing: Events matched to conversations via tag map lookup
- Per-DID rkey tracking for pagination across all conversation participants
- Commit handling: Epoch updates trigger new tag registration
- Duplicate detection via message ID (groupIdHex + rkey)
- Messages sorted by timestamp, displayed in chat-style UI

### Step 4: Send Messages ✅ COMPLETE

**Implemented**: Users can compose and send encrypted messages from the Flutter app.

#### 4.1 Message Model Updates

Update `lib/models/message.dart` to add status tracking:

```dart
enum MessageStatus {
  sending,  // In flight to PDS
  sent,     // Confirmed published
  failed,   // PDS publish failed
}

class Message {
  // ... existing fields ...
  final MessageStatus status;  // New field
  final String? localId;       // Temporary ID for pending messages (before rkey assigned)
}
```

#### 4.2 Send Service

Create `lib/services/send_service.dart`:

**Core responsibilities**:
1. Encrypt message via FFI (`encryptEvent`)
2. Pad plaintext to bucket size (`padToBucket`)
3. Publish to PDS (`publishEvent`)
4. Persist sent message locally (MLS can't decrypt own ciphertexts)
5. Update MLS group state after encryption

**Key flow**:
```dart
Future<Message> sendMessage(Conversation conv, String text) async {
  // 1. Auto-refresh epoch if needed (poll for commits, process them)
  await _ensureEpochCurrent(conv);

  // 2. Load keyBundle from secure storage (per-send, not cached)
  final keyBundle = await _secureStorage.loadKeyBundle();

  // 3. Pad plaintext to bucket
  final plaintext = utf8.encode(text);
  final padded = padToBucket(plaintext: plaintext);

  // 4. Create event DTO
  final event = EventDto(
    kind: EventKindDto.message,
    groupId: conv.groupId,
    epoch: BigInt.from(conv.epoch),
    senderDeviceId: '$myDid/$deviceName',
    payload: padded,
  );

  // 5. Encrypt via FFI - returns (newGroupState, tag, ciphertext)
  final result = await session.encryptEvent(
    groupId: conv.groupId,
    keyBundle: keyBundle,
    event: event,
  );

  // 6. Persist updated MLS state
  await _secureStorage.saveMlsState(result.newGroupState);

  // 7. Publish to PDS with returned tag
  final uri = await _atproto.publishEvent(result.tag, result.ciphertext);

  // 8. Create and store message locally
  final message = Message(
    id: '${conv.groupIdHex}_${extractRkey(uri)}',
    localId: null,
    groupId: conv.groupId,
    senderDid: myDid,
    senderDeviceId: '$myDid/$deviceName',
    content: text,
    timestamp: DateTime.now(),
    isOwn: true,
    epoch: conv.epoch,
    status: MessageStatus.sent,
  );

  return message;
}
```

**Epoch refresh logic** (`_ensureEpochCurrent`):
- Poll for new events from conversation participants
- Process any commits to update local epoch
- If refresh fails (network error), block send with error message

#### 4.3 Send Queue

Implement ordered message queue in `MessagesProvider` or separate `SendQueue`:

- User can type and tap send multiple times rapidly
- Messages queue and send in order
- If message N fails, messages N+1, N+2 etc wait until N succeeds or user cancels
- Failed messages show inline retry button
- Each message tracks its own `MessageStatus`

**Queue state**:
```dart
class SendQueue {
  final List<PendingMessage> _queue = [];
  bool _isProcessing = false;

  void enqueue(PendingMessage msg);
  Future<void> _processNext();
  void retry(String localId);
  void cancel(String localId);
}
```

#### 4.4 UI Changes

**Text input** (`conversation_screen.dart`):
- Replace placeholder with real `TextField`
- Expanding multi-line: grows as user types, up to ~4 lines, then scrolls
- Enter key sends message, Shift+Enter adds newline
- 200-300ms debounce on send button to prevent double-taps
- Send button enabled/disabled based on text content (not empty)

**Message bubble updates** (`message_bubble.dart`):
- Add status indicator for own messages:
  - `sending`: Single gray checkmark
  - `sent`: Double gray checkmarks
  - `failed`: Red error icon, tap to retry
- Checkmark style like WhatsApp

**Live updates**:
- When conversation screen is open and new messages arrive via polling
- If user is scrolled to bottom: auto-scroll to show new messages
- If user has scrolled up: show "New messages" indicator at bottom

**Files created/modified**:
- [send_service.dart](moat-flutter/lib/services/send_service.dart) - Encryption and publishing logic
- [message.dart](moat-flutter/lib/models/message.dart) - Added `MessageStatus` enum, `status` and `localId` fields, `copyWith` method
- [conversation_screen.dart](moat-flutter/lib/screens/conversation_screen.dart) - Real TextField input with send button
- [message_bubble.dart](moat-flutter/lib/widgets/message_bubble.dart) - Status indicators (clock, checkmarks, error) and retry on tap
- [messages_provider.dart](moat-flutter/lib/providers/messages_provider.dart) - Send queue, optimistic UI, retry/cancel

**Key features**:
- Optimistic UI: Message appears immediately with "sending" status
- Send queue: Messages sent in order, queue blocks on failure
- Status indicators: Clock (sending), double checkmarks (sent), error icon (failed)
- Retry mechanism: Tap failed message to retry, or cancel via provider
- Auto-scroll: Automatically scroll to bottom when new messages arrive (if already at bottom)
- Multiline input: TextField expands up to ~4 lines, then scrolls internally
- MLS state persistence: Updated after each encryption operation

### Step 5: Multi-Device Support ✅ COMPLETE
- **Auto-add own devices**: Poll for own new key packages and add them to groups you create ✅
- **New device alerts**: Show notification when a new device joins a conversation ✅
- **Auto-add new devices for existing members**: When polling, detect new key packages for group members and add them (with stealth-encrypted welcome, random delay to reduce race conditions) ✅
- **Poll own DID for welcomes**: Flutter polls its own DID for stealth-encrypted welcomes from CLI/other devices ✅
- **Ensure keys on PDS**: On startup, verify stealth address and key package are published (re-publish if missing) ✅
- **File-based debug logging**: DebugLog service for troubleshooting multi-device sync ✅
