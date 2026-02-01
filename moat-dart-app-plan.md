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

**Goal**: Fetch, decrypt, and display messages from existing conversations.

#### 3.1 Message Model

Create `lib/models/message.dart`:
```dart
class Message {
  final String id;              // Unique ID (groupIdHex + rkey)
  final Uint8List groupId;      // Which conversation
  final String senderDid;       // DID of sender (for display grouping)
  final String? senderDeviceId; // Device that sent (for message info)
  final String content;         // Decrypted text
  final DateTime timestamp;     // From EventRecord.createdAt
  final bool isOwn;             // Sent by us (for styling)
  final int epoch;              // MLS epoch when sent
}
```

#### 3.2 Message Storage

Add to `SecureStorageService` (`lib/services/secure_storage.dart`):
- `saveMessages(String groupIdHex, List<Message>)` - Persist message list per conversation
- `loadMessages(String groupIdHex) -> List<Message>` - Load messages for a conversation
- `appendMessage(String groupIdHex, Message)` - Add single message efficiently

Use standard file storage (not secure storage) for message content since it's just decrypted text. Keep keys only in secure storage.

Consider: SQLite via `sqflite` package for efficient querying and large message histories. Start with JSON file for simplicity, migrate later if needed.

#### 3.3 Message Polling Infrastructure

**Extend `PollingService`** with new method `_pollConversationMessages()`:

1. **Get all participant DIDs**: For each conversation, collect all participant DIDs
2. **Per-DID polling**: Fetch events from each DID using existing `fetchEvents()` with rkey pagination
3. **Tag-based routing**: For each event:
   - Convert tag to hex: `tagHex = event.tag.map(...).join()`
   - Look up in tag map: `groupIdHex = await _secureStorage.lookupByTag(tagHex)`
   - If found → route to that conversation for decryption
   - If not found → skip (could be stealth invite, old epoch, or not for us)

**Per-conversation last rkey tracking**: Store `Map<groupIdHex, Map<did, lastRkey>>` to track pagination per participant per conversation. Add to `SecureStorageService`:
- `saveConversationLastRkeys(String groupIdHex, Map<String, String> didToRkey)`
- `loadConversationLastRkeys(String groupIdHex) -> Map<String, String>`

#### 3.4 Message Decryption Pipeline

Create `lib/services/message_service.dart`:

```dart
class MessageService {
  Future<Message?> decryptEvent(EventRecord record, Conversation conversation) async {
    // 1. Get current MLS state
    final mlsState = await _secureStorage.loadMlsState();
    final session = await MoatSessionHandle.fromState(mlsState);

    // 2. Decrypt
    final result = await session.decryptEvent(
      groupId: conversation.groupId,
      ciphertext: record.ciphertext,
    );

    // 3. Persist updated MLS state (CRITICAL - must happen after each decrypt)
    await _secureStorage.saveMlsState(result.newGroupState);

    // 4. Handle by event kind
    switch (result.event.kind) {
      case EventKindDto.message:
        // Unpad and decode text
        final padded = result.event.payload;
        final plaintext = unpad(padded: padded);
        final text = utf8.decode(plaintext);

        return Message(
          id: '${conversation.groupIdHex}_${record.rkey}',
          groupId: conversation.groupId,
          senderDid: _extractDidFromDeviceId(result.event.senderDeviceId),
          senderDeviceId: result.event.senderDeviceId,
          content: text,
          timestamp: record.createdAt,
          isOwn: _isSenderMe(result.event.senderDeviceId),
          epoch: result.event.epoch,
        );

      case EventKindDto.commit:
        // Epoch advanced - update conversation and tag map
        await _handleCommit(conversation, result.event);
        return null; // No message to display

      case EventKindDto.welcome:
      case EventKindDto.checkpoint:
        return null; // Not displayable messages
    }
  }

  Future<void> _handleCommit(Conversation conv, EventDto event) async {
    // Update conversation epoch
    conv.epoch = event.epoch;
    await _conversationsProvider.updateConversation(conv);

    // Derive and register new tag for this epoch
    final newTag = deriveTag(groupId: conv.groupId, epoch: BigInt.from(event.epoch));
    final tagHex = newTag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    await _secureStorage.registerTag(tagHex, conv.groupIdHex);
  }
}
```

**Error handling considerations**:
- Decryption can fail if: wrong group, already processed, epoch mismatch
- On failure: log error, skip event, continue with next
- Track failed rkeys to avoid re-processing in future polls

#### 3.5 Messages Provider

Create `lib/providers/messages_provider.dart`:

```dart
class MessagesProvider extends ChangeNotifier {
  final String groupIdHex;
  List<Message> _messages = [];
  bool _isLoading = false;

  List<Message> get messages => _messages;
  bool get isLoading => _isLoading;

  Future<void> loadMessages() async {
    _isLoading = true;
    notifyListeners();

    _messages = await _storage.loadMessages(groupIdHex);

    _isLoading = false;
    notifyListeners();
  }

  void addMessage(Message message) {
    _messages.add(message);
    _messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    notifyListeners();
  }

  void markAsRead() {
    // Update conversation unread count
  }
}
```

#### 3.6 Conversation Detail Screen

Create `lib/screens/conversation_screen.dart`:

**Layout**:
- AppBar: Conversation display name, menu with info option
- Body: `ListView.builder` with messages, reversed for chat UI
- Bottom: Placeholder text "Sending messages coming in Step 4"

**Message bubble widget**:
```dart
class MessageBubble extends StatelessWidget {
  final Message message;

  // Align right for own messages, left for others
  // Show sender name for first message in a group from same DID
  // Long-press shows message info (device ID, timestamp, epoch)
}
```

**Collapsed identity display**:
- Group consecutive messages from same DID
- Show sender handle/name only on first message of group
- Don't show individual device names unless user taps for info

**History boundary**:
- When at top of list, show: "Messages before [date] are on your other devices"
- This acknowledges new devices don't get history

#### 3.7 Navigation Wiring

Update `ConversationsScreen._ConversationTile.onTap`:
```dart
onTap: () {
  Navigator.of(context).push(
    MaterialPageRoute(
      builder: (context) => ChangeNotifierProvider(
        create: (_) => MessagesProvider(conversation.groupIdHex)..loadMessages(),
        child: ConversationScreen(conversation: conversation),
      ),
    ),
  );
  // Mark as read when opening
  conversationsProvider.markAsRead(conversation);
}
```

#### 3.8 Background Polling Integration

Modify `PollingService`:

1. Add `_pollConversationMessages()` to `poll()` method
2. Call after welcome polling completes
3. Use `ConversationsProvider` to get list of conversations to poll
4. For each new message decrypted:
   - Add to appropriate `MessagesProvider` (if screen is open)
   - Update conversation's `lastMessagePreview` and `lastMessageAt`
   - Increment `unreadCount` if conversation screen not open

**Callback pattern**:
```dart
/// Callback when new messages arrive
void Function(String groupIdHex, List<Message> messages)? onNewMessages;
```

#### 3.9 Testing Flow

1. **Setup**: Device A and Device B both have a shared conversation (from Step 2)
2. **Send from CLI**: Use `cargo run -p moat-cli -- send-test --tag <tag> --message "Hello"`
3. **Poll on Flutter**: App polls, decrypts message, displays in conversation view
4. **Verify epoch tracking**: Send multiple messages, confirm tag updates work
5. **Cross-device**: Open conversation on both Flutter devices, verify both receive messages

#### 3.10 Files to Create/Modify

**New files**:
- `lib/models/message.dart` - Message data model
- `lib/services/message_service.dart` - Decryption and message processing
- `lib/providers/messages_provider.dart` - State management for messages
- `lib/screens/conversation_screen.dart` - Conversation detail UI
- `lib/widgets/message_bubble.dart` - Message display widget

**Modified files**:
- `lib/services/secure_storage.dart` - Add message persistence methods
- `lib/services/polling_service.dart` - Add message polling logic
- `lib/screens/conversations_screen.dart` - Wire up navigation
- `lib/providers/conversations_provider.dart` - Add `markAsRead()`, `updateConversation()`
- `lib/models/conversation.dart` - Add `lastSyncedRkeys` field (optional)

#### 3.11 Implementation Order

1. **Message model** - Define the data structure
2. **Secure storage extensions** - Persistence layer
3. **Message service** - Core decryption logic
4. **Messages provider** - State management
5. **Conversation screen + message bubble** - UI
6. **Navigation wiring** - Connect screens
7. **Polling integration** - Background updates
8. **Testing** - End-to-end verification

#### 3.12 Edge Cases

- **Epoch mismatch**: If we miss a commit, decryption fails. Log and skip; user may need to re-sync.
- **Duplicate processing**: Use message ID (groupId + rkey) to deduplicate.
- **Out-of-order messages**: Sort by timestamp after loading.
- **Large histories**: Implement pagination/virtualization if needed (defer to later).
- **Network failures**: Retry with exponential backoff; show error toast if persistent.

### Step 4: Send Messages
- Text input and message composition
- Encrypt via FFI (MLS encrypt), pad to buckets
- Derive conversation tag from group_id + epoch
- Publish to PDS with derived tag
- Store sent messages locally (MLS can't decrypt own ciphertexts)
- Update tag_map if epoch advances
- **Multi-device sync**: Your other devices receive your sent messages as normal group messages

### Step 5: Multi-Device Support ✅ COMPLETE
- **Auto-add own devices**: Poll for own new key packages and add them to groups you create ✅
- **New device alerts**: Show notification when a new device joins a conversation ✅
- **Auto-add new devices for existing members**: When polling, detect new key packages for group members and add them (with stealth-encrypted welcome, random delay to reduce race conditions) ✅
- **Poll own DID for welcomes**: Flutter polls its own DID for stealth-encrypted welcomes from CLI/other devices ✅
- **Ensure keys on PDS**: On startup, verify stealth address and key package are published (re-publish if missing) ✅
- **File-based debug logging**: DebugLog service for troubleshooting multi-device sync ✅
