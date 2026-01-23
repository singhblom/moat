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
- Conversation list with unread counts
- Message display with MLS decryption
- New conversation flow (resolve handle → create MLS group → publish welcome)
- Watch for invites from new contacts
- Background polling for incoming messages
- Local key storage in `~/.moat/keys/`
- MLS state persistence in `~/.moat/mls.bin`

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

## Usage

```bash
cargo run -p moat-cli
```

On first run, you'll be prompted to log in with your Bluesky handle and an app password.

### Command Line Options

| Option | Description |
|--------|-------------|
| `-s`, `--storage-dir <PATH>` | Custom storage directory (default: `~/.moat`) |

Example with custom storage directory (useful for testing with multiple identities):

```bash
cargo run -p moat-cli -- -s /tmp/moat-alice
cargo run -p moat-cli -- --storage-dir /tmp/moat-bob
```

### Key Bindings

| Key | Action |
|-----|--------|
| `n` | Start new conversation (enter recipient handle) |
| `w` | Watch for invites from a handle |
| `↑`/`↓` or `j`/`k` | Navigate conversation list |
| `Enter` | Select conversation / Send message |
| `Tab` | Switch between panes |
| `Esc` | Cancel / Go back |
| `q` | Quit |

### Test Flow (Two Users)

1. **User A** runs moat, logs in
2. **User B** runs moat, logs in, presses `w`, enters User A's handle (now watching for invites)
3. **User A** presses `n`, enters User B's handle (creates conversation, sends welcome)
4. **User B**'s next poll discovers the welcome, conversation appears
5. Both users can now exchange encrypted messages

## Current Status

This is an MVP implementation. End-to-end encrypted messaging works but needs real-world testing.

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

**moat-atproto (complete)**
- ATProto authentication (handle + app password)
- Key package publishing/fetching (`social.moat.keyPackage`)
- Event publishing/fetching (`social.moat.event`)
- Handle-to-DID resolution

**moat-cli (MVP complete)**
- Login screen with credential storage
- Ratatui terminal UI with conversation list and message panes
- MoatSession integration with persistent MLS state
- New conversation flow: resolve handle → fetch key package → create group → publish welcome
- Send messages with MLS encryption
- Poll and decrypt incoming messages
- Watch handle feature for receiving invites from new contacts
- Unread message counts

### Not Yet Implemented

- Cursor-based pagination (currently uses URI deduplication)
- Multi-device support
- Stealth addresses for invites
- Handle resolution for incoming invites (currently shows DID)

## License

MIT
