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

### Step 2: Read Messages
- Fetch events from PDS for conversation participants
- Tag-based routing to match events to conversations
- Decrypt messages via FFI (MLS decrypt)
- Display messages in a conversation view
- **Collapsed identity display**: Group messages by DID, not by device (show "Alice" not "Alice-phone")
- **Message Info**: Track sender device per message, viewable via long-press or info button
- Background polling for new messages
- **History boundary**: Show indicator when scrolling to top: "Messages before [date] are on your other devices"

### Step 3: Send Messages
- Text input and message composition
- Encrypt via FFI (MLS encrypt), pad to buckets
- Derive conversation tag, publish to PDS
- Store sent messages locally (MLS can't decrypt own ciphertexts)
- **Multi-device sync**: Your other devices receive your sent messages as normal group messages

### Step 4: Create Conversations
- New conversation flow: enter recipient handle
- Resolve handle to DID, fetch stealth address + key package
- Create MLS group via FFI (pass DID + device name), add recipient
- Encrypt Welcome with stealth address, publish to PDS
- **Auto-add own devices**: Poll for own new key packages and add them to groups you create

### Step 5: Handle Invites
- Watch for incoming invites (stealth-encrypted Welcomes)
- Try decryption with local stealth key
- Process MLS Welcome, join group
- Add new conversation to list
- **New device alerts**: Show notification when a new device joins a conversation
- **Auto-add new devices for existing members**: When polling, detect new key packages for group members and add them (with random delay to reduce race conditions)
