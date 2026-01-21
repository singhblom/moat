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
- Key package generation
- Group creation
- Tag derivation (rotating 16-byte tags for conversation privacy)
- Message padding (256B / 1KB / 4KB buckets to hide message length)

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

- **moat-core**: Key generation, group creation, padding, tag derivation
- **moat-atproto**: Record serialization (integration tests require a live PDS)
- **moat-cli**: Keystore operations

## Running the CLI

```bash
cargo run -p moat-cli
```

On first run, you'll be prompted to log in with your Bluesky handle and an app password.

## Current Status

This is an MVP implementation. Working:
- MLS key package generation
- ATProto record publishing/fetching
- Local key storage
- Basic terminal UI

Not yet implemented:
- Full MLS group state persistence
- Welcome/commit processing
- Real-time message polling
- Multi-device support

## License

MIT
