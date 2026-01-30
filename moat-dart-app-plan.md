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

### Step 0: Foundation
- Install FRB codegen: `cargo install flutter_rust_bridge_codegen`
- Scaffold Flutter project: `flutter_rust_bridge_codegen create moat_flutter --template plugin`, then move to `moat-flutter/` at repo root
- Replace generated `rust/` crate with a dependency on `moat-core` (path = `../crates/moat-core`)
- Create thin `rust/src/api.rs` re-exporting moat-core's public API (MoatSession methods, free functions, types)
- Run FRB codegen: `flutter_rust_bridge_codegen generate` to produce Dart bindings in `lib/src/rust/`
- Write minimal Dart test calling `MoatSession.new()` and printing device ID
- Verify on Android emulator: `flutter run`
- Optionally add `moat-flutter/rust` to workspace `Cargo.toml` members

### Step 1: Login + Conversations List
- Implement ATProto login (handle + app password) in Dart HTTP
- Generate identity key and stealth key via FFI to moat-core
- Publish key package and stealth address to PDS
- Display list of conversations from local storage
- Secure storage for credentials and keys

### Step 2: Read Messages
- Fetch events from PDS for conversation participants
- Tag-based routing to match events to conversations
- Decrypt messages via FFI (MLS decrypt)
- Display messages in a conversation view
- Background polling for new messages

### Step 3: Send Messages
- Text input and message composition
- Encrypt via FFI (MLS encrypt), pad to buckets
- Derive conversation tag, publish to PDS
- Store sent messages locally (MLS can't decrypt own ciphertexts)

### Step 4: Create Conversations
- New conversation flow: enter recipient handle
- Resolve handle to DID, fetch stealth address + key package
- Create MLS group via FFI, add recipient
- Encrypt Welcome with stealth address, publish to PDS

### Step 5: Handle Invites
- Watch for incoming invites (stealth-encrypted Welcomes)
- Try decryption with local stealth key
- Process MLS Welcome, join group
- Add new conversation to list
