# Moat

Encrypted messaging on ATProto using MLS (Messaging Layer Security).

## Architecture

```
moat/
├── crates/
│   ├── moat-core/      # Pure MLS logic, no IO
│   ├── moat-atproto/   # PDS interaction, ATProto client
│   └── moat-cli/       # Ratatui terminal UI
└── lexicons/           # ATProto lexicon definitions
```

### moat-core

Pure Rust MLS operations using OpenMLS. Handles:
- Key package generation with persistence
- Group creation, loading, and member management
- Welcome/commit message processing
- Event encryption/decryption with automatic padding
- Tag derivation (rotating 16-byte tags per epoch)
- Message padding (256B / 1KB / 4KB buckets)
- File-backed storage provider for MLS state persistence

### moat-atproto

ATProto client for interacting with a PDS (Personal Data Server). Handles:
- Authentication (login with handle + app password)
- Publishing and fetching key packages (`social.moat.keyPackage`)
- Publishing and fetching encrypted events (`social.moat.event`)
- Handle-to-DID resolution

### moat-cli

Terminal UI built with Ratatui. Features:
- Login screen with credential storage
- Conversation list
- Message display
- Local key storage in `~/.moat/keys/`

## Lexicons

**`social.moat.keyPackage`** - MLS key packages for establishing encrypted conversations
- `v`: Schema version (1)
- `ciphersuite`: MLS ciphersuite identifier
- `keyPackage`: TLS-serialized MLS KeyPackage
- `expiresAt`: Expiration timestamp
- `createdAt`: Creation timestamp

**`social.moat.event`** - Unified encrypted event record (messages, commits, invites)
- `v`: Schema version (1)
- `tag`: 16-byte rotating tag for conversation clustering
- `ciphertext`: Padded encrypted payload
- `createdAt`: Creation timestamp

## Privacy Features

- **Rotating tags**: Conversation tags rotate with MLS epochs to prevent correlation
- **Size bucketing**: Messages are padded to fixed sizes (256B, 1KB, 4KB) to hide length
- **Unified records**: All event types use the same record schema to hide message type

## Building

```bash
cargo build
```

## Testing

Run all tests:

```bash
cargo test
```

Run tests for a specific crate:

```bash
cargo test -p moat-core
cargo test -p moat-atproto
cargo test -p moat-cli
```

### Test Coverage

- **moat-core** (38 tests):
  - Key package generation and persistence
  - Group creation, loading, and persistence across restarts
  - Member addition with welcome/commit
  - Two-party encrypted messaging (Alice ↔ Bob)
  - Event encryption/decryption with padding
  - Rotating tag derivation
  - Padding bucket selection and round-trip
- **moat-atproto**: Record serialization (integration tests require a live PDS)
- **moat-cli**: Keystore operations

## Running the CLI

```bash
cargo run -p moat-cli
```

On first run, you'll be prompted to log in with your Bluesky handle and an app password.

## Current Status

This is an MVP implementation.

### Working ✓

**moat-core (complete)**
- MLS key package generation with persistence
- Group creation with file-backed storage
- Member addition with welcome/commit generation
- Welcome processing to join groups
- Event encryption/decryption with padding
- Rotating conversation tags via HKDF-SHA256
- Full MLS state persistence across restarts
- 38 passing tests including two-party messaging

**moat-atproto**
- ATProto authentication (handle + app password)
- Key package publishing/fetching (`social.moat.keyPackage`)
- Basic record operations

**moat-cli**
- Login screen with credential storage
- Basic terminal UI with Ratatui
- Local keystore at `~/.moat/keys/`
- MoatSession integration with persistent MLS state at `~/.moat/mls.bin`
- Key generation via MoatSession (persisted to storage)
- New conversation flow (press 'n', enter handle, creates MLS group + publishes welcome)

### Not Yet Implemented

- Wire `send_message()` to use MLS encryption
- Message polling/decryption
- Multi-device support

## License

MIT
