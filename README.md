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
- Stealth address cryptography (ECDH + HKDF + XChaCha20-Poly1305) for private invitations

### moat-atproto

ATProto client for interacting with a PDS (Personal Data Server). Handles:
- Authentication (login with handle + app password)
- Publishing and fetching key packages (`social.moat.keyPackage`)
- Publishing and fetching encrypted events (`social.moat.event`)
- Publishing and fetching stealth addresses (`social.moat.stealthAddress`)
- Handle-to-DID resolution

### moat-cli

Terminal UI built with Ratatui. Features:
- Login screen with credential storage
- Conversation list with unread counts
- Message display with MLS decryption
- New conversation flow (resolve handle → fetch stealth address → create MLS group → publish stealth-encrypted welcome)
- Watch for invites from new contacts
- Background polling for incoming messages
- Local key storage in `~/.moat/keys/` (credentials, identity key, stealth key)
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
- `tag`: 16-byte rotating tag for conversation clustering (random for stealth invites)
- `ciphertext`: Padded encrypted payload (stealth-encrypted for invites, MLS-encrypted for messages)
- `createdAt`: Creation timestamp

**`social.moat.stealthAddress`** - Stealth meta-address for receiving private invitations
- `v`: Schema version (1)
- `scanPubkey`: X25519 public key (32 bytes) for stealth address derivation
- `createdAt`: Creation timestamp

## Privacy Features

- **Stealth addresses**: Invitations are encrypted with recipient's stealth public key using ECDH + XChaCha20-Poly1305. Observers cannot determine who an invitation is for, and multiple invites to the same person are unlinkable.
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

- **moat-core** (46 tests):
  - Key package generation and persistence
  - Group creation, loading, and persistence across restarts
  - Member addition with welcome/commit
  - Two-party encrypted messaging (Alice ↔ Bob)
  - Event encryption/decryption with padding
  - Rotating tag derivation
  - Padding bucket selection and round-trip
  - Stealth address keypair generation
  - Stealth encryption/decryption round-trip
  - Wrong-key and corrupted-payload rejection
- **moat-atproto** (3 tests): Record serialization (integration tests require a live PDS)
- **moat-cli** (6 tests): Keystore operations including stealth key storage

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

1. **User A** runs moat, logs in (generates MLS key package + stealth address on first login)
2. **User B** runs moat, logs in (generates MLS key package + stealth address on first login)
3. **User B** presses `w`, enters User A's handle (now watching for invites from A)
4. **User A** presses `n`, enters User B's handle (fetches B's stealth address + key package, creates group, sends stealth-encrypted welcome)
5. **User B**'s next poll discovers the stealth-encrypted welcome, decrypts it, joins the group
6. Both users can now exchange MLS-encrypted messages

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
- Stealth address cryptography (keypair generation, encryption, decryption)
- 46 passing tests including two-party messaging and stealth encryption

**moat-atproto (complete)**
- ATProto authentication (handle + app password)
- Key package publishing/fetching (`social.moat.keyPackage`)
- Event publishing/fetching (`social.moat.event`)
- Stealth address publishing/fetching (`social.moat.stealthAddress`)
- Handle-to-DID resolution

**moat-cli (MVP complete)**
- Login screen with credential storage
- Ratatui terminal UI with conversation list and message panes
- MoatSession integration with persistent MLS state
- Stealth address generation on first login
- New conversation flow: resolve handle → fetch stealth address → fetch key package → create group → publish stealth-encrypted welcome
- Incoming invite detection via stealth decryption
- Send messages with MLS encryption
- Poll and decrypt incoming messages
- Watch handle feature for receiving invites from new contacts
- Unread message counts

### Not Yet Implemented

- Cursor-based pagination (currently uses URI deduplication)
- Multi-device support
- Handle resolution for incoming invites (currently shows DID)
- Cover traffic (dummy events to obscure activity patterns)

## License

MIT
