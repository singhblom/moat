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

### Step 2: Create & Join Conversations (Invites + Watch List)

This step must come before messaging because you need a conversation to test with. The invite system involves:

1. **Watch list** - Track DIDs you're expecting invites from
2. **Stealth decryption** - Invites are encrypted with your stealth address (not MLS), so only you can decrypt
3. **Random tags** - Invites use random tags (not group-derived), requiring special handling

**Creating a conversation (as initiator):**
- New conversation flow: enter recipient handle
- Resolve handle to DID, fetch stealth address + key package from PDS
- Create MLS group via FFI, add recipient (generates Welcome message)
- Encrypt Welcome with recipient's stealth address (`encrypt_for_stealth`)
- Publish to PDS with **random 16-byte tag** (recipient doesn't know group yet)
- Store conversation metadata, register epoch 1 tag for future messages

**Receiving an invite (as recipient):**
- **Watch list UI**: Add DIDs to watch for incoming invites (resolve handle → DID)
- Poll events from watched DIDs (separate from conversation participant polling)
- For each event: attempt stealth decryption with local stealth key
- On success: process MLS Welcome via FFI, join group
- Add new conversation to list, register epoch 1 tag
- **Remove DID from watch list** after successful join

**Testing flow:**
1. Device A creates conversation with Device B
2. Device B adds Device A's handle to watch list
3. Device B polls → receives and decrypts invite → joins conversation
4. Both devices now share a conversation for testing Steps 3-4

### Step 3: Read Messages
- Poll events from all conversation participant DIDs
- **Tag-based routing**: Match event tags to known tags in tag_map → find conversation
- For unknown tags from watched DIDs: try as welcome (handled in Step 2)
- Decrypt messages via FFI (MLS decrypt)
- Display messages in a conversation view
- **Collapsed identity display**: Group messages by DID, not by device (show "Alice" not "Alice-phone")
- **Message Info**: Track sender device per message, viewable via long-press or info button
- Background polling (every few seconds)
- **History boundary**: Show indicator when scrolling to top: "Messages before [date] are on your other devices"

### Step 4: Send Messages
- Text input and message composition
- Encrypt via FFI (MLS encrypt), pad to buckets
- Derive conversation tag from group_id + epoch
- Publish to PDS with derived tag
- Store sent messages locally (MLS can't decrypt own ciphertexts)
- Update tag_map if epoch advances
- **Multi-device sync**: Your other devices receive your sent messages as normal group messages

### Step 5: Multi-Device Support
- **Auto-add own devices**: Poll for own new key packages and add them to groups you create
- **New device alerts**: Show notification when a new device joins a conversation
- **Auto-add new devices for existing members**: When polling, detect new key packages for group members and add them (with stealth-encrypted welcome, random delay to reduce race conditions)
