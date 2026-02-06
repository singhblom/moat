# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Moat is an encrypted messaging application built on ATProto (Bluesky's protocol) using MLS (Messaging Layer Security) for end-to-end encryption. The MVP is a Ratatui-based terminal UI. Privacy features include stealth addresses and metadata obfuscation through rotating tags and message padding.

## Build & Test Commands

```bash
cargo build                  # Build all crates
cargo test                   # Run all tests
cargo test -p moat-core      # Run core crypto tests only (73 tests)
cargo test -p moat-atproto   # Run ATProto tests only (3 tests)
cargo run -p moat-cli        # Run the TUI (default, no subcommand)

# Testing multiple accounts locally
cargo run -p moat-cli -- -s /tmp/moat-alice
cargo run -p moat-cli -- -s /tmp/moat-bob

# CLI subcommands (run-once, no TUI)
cargo run -p moat-cli -- fetch --repository handle.bsky.social   # Fetch & decrypt new events (read-only)
cargo run -p moat-cli -- status                                  # Show account info, conversation count, storage
cargo run -p moat-cli -- send-test --tag <32-hex> --message "…"  # Publish test message to a conversation
cargo run -p moat-cli -- export --log /tmp/debug.log             # Export debug log
cargo run -p moat-cli -- export --events /tmp/e.json --repository handle.bsky.social  # Export events as JSON
```

## Workspace Structure

Three-crate Rust workspace + Flutter app:

- **moat-core** - Pure MLS cryptography, no network/IO. Provides `MoatSession` API for all crypto operations.
- **moat-atproto** - Async ATProto client for PDS interactions (key packages, events, stealth addresses).
- **moat-cli** - Ratatui terminal UI that orchestrates core + atproto.
- **moat-flutter/** - Flutter app (Android + Web). Contains its own Rust crate at `moat-flutter/rust/` that wraps moat-core via flutter_rust_bridge.

## Architecture Principles

1. **All crypto in moat-core** - CLI should only call `MoatSession` methods, never touch OpenMLS directly.
2. **Clean API boundaries** - Core MLS logic is stateless (takes serialized state + private key bundle, returns new state).
3. **Private keys stay local** - Never stored on PDS, kept in `~/.moat/keys/`.
4. **Storage is automatic** - `FileStorage` persists MLS state to `~/.moat/mls.bin` on every operation.
5. **Network calls are async** - Uses Tokio; be aware of sync/async boundaries.

## Key Types

**moat-core:**
- `MoatSession` - Main API for MLS operations with file-backed persistence
- `Event` / `EventKind` - Unified event type (Message, Commit, Welcome, Checkpoint)
- `KeyBundle` - Serialized key package with private keys

**moat-atproto:**
- `MoatAtprotoClient` - Async client for PDS operations (login, publish/fetch events, key packages, stealth addresses)

**moat-cli:**
- `App` - Application state combining MLS session, ATProto client, and UI state
- `KeyStore` - Local storage for credentials, identity key, and stealth key

## Lexicons

Located in `lexicons/social/moat/`:
- `event.json` - Unified encrypted payload with 16-byte rotating tag
- `keyPackage.json` - MLS key package distribution
- `stealthAddress.json` - X25519 public key for privacy-preserving invites

## Privacy Features

- **Stealth addresses** - ECDH-based invite encryption makes invites unlinkable
- **Rotating tags** - 16-byte conversation tags change with MLS epochs
- **Padding** - Messages padded to 256B/1KB/4KB buckets
- **Unified records** - All events use same schema, hiding message type

## Local Storage Layout

```
~/.moat/
├── mls.bin           # MoatSession's FileStorage (MLS state)
├── debug.log
└── keys/
    ├── credentials.json
    ├── identity.key
    ├── stealth.key
    └── conversations/
```

## MLS Ciphersuite

`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

## Flutter App (moat-flutter)

### Build & Run

```bash
cd moat-flutter
flutter run                  # Run on connected device (Android/iOS)
flutter run -d chrome \      # Run in Chrome with required CORS headers
  --web-header=Cross-Origin-Opener-Policy=same-origin \
  --web-header=Cross-Origin-Embedder-Policy=credentialless

flutter_rust_bridge_codegen build-web  # Rebuild WASM after Rust changes
flutter build web            # Production web build
flutter build apk            # Android APK
```

### Web Platform Architecture

- **Conditional imports** — Services that need platform-specific I/O use Dart conditional imports (`*_native.dart` / `*_web.dart`), selected via `dart.library.js_interop`. Files using this pattern: `debug_log`, `conversation_storage`, `message_storage`, `profile_cache_service`.
- **Native** uses `dart:io` + `path_provider` for file-based storage.
- **Web** uses `package:web` (`window.localStorage`) for persistence.
- **WASM** — The Rust FFI library is compiled to WASM via `flutter_rust_bridge_codegen build-web`. Output goes to `moat-flutter/web/pkg/`. Requires nightly Rust + `wasm-pack`.
- **Cross-origin headers** are required for `SharedArrayBuffer` (WASM threading). Flutter 3.17+ supports `--web-header` flags.
- **`flutter_secure_storage`** works on web out of the box (uses localStorage internally).

### WASM Build Prerequisites

```bash
rustup toolchain install nightly
rustup +nightly component add rust-src
rustup +nightly target add wasm32-unknown-unknown
cargo install wasm-pack
```

### Key Constraints for WASM Compatibility

- **No `dart:io`** on web — any file I/O must be behind conditional imports.
- **`path_provider`** has no web implementation for `getApplicationDocumentsDirectory`.
- **OpenMLS** requires the `js` feature for WASM (`openmls/js`). This is enabled via moat-core's `js` feature, which the flutter rust crate activates for wasm targets.
- **`getrandom`** requires the `js` feature for WASM.
- **Avoid `parking_lot`** in moat-core — it has WASM compatibility issues. Use `std::sync::RwLock` / `std::sync::Mutex` instead.

## FFI / Flutter Bridge

- moat-core operations are synchronous — the flutter bridge wraps `MoatSession` in a `std::sync::Mutex` via `MoatSessionHandle`.
- flutter_rust_bridge v2.11.1 generates platform-conditional code in `lib/src/rust/frb_generated.dart`.
- Binary data crosses the FFI boundary as `Vec<u8>` (Rust) / `Uint8List` (Dart).
- Error types use `Result<T, String>` for FFI-friendliness.
