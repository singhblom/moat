# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Moat is an encrypted messaging application built on ATProto (Bluesky's protocol) using MLS (Messaging Layer Security) for end-to-end encryption. The MVP is a Ratatui-based terminal UI. Privacy features include stealth addresses and metadata obfuscation through rotating tags and message padding.

## Build & Test Commands

```bash
cargo build                  # Build all crates
cargo test                   # Run all tests (49 total)
cargo test -p moat-core      # Run core crypto tests only (46 tests)
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

Three-crate Rust workspace:

- **moat-core** - Pure MLS cryptography, no network/IO. Provides `MoatSession` API for all crypto operations.
- **moat-atproto** - Async ATProto client for PDS interactions (key packages, events, stealth addresses).
- **moat-cli** - Ratatui terminal UI that orchestrates core + atproto.

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

## FFI Considerations (Future)

When adding FFI/mobile support:
- Keep operations synchronous in moat-core
- Prefer fixed-size arrays over Vec
- Make storage controllable by native side (explicit save())
- Error types should be FFI-friendly
