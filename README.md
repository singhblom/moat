# Moat

Encrypted messaging on ATProto using MLS (Messaging Layer Security). Messages are end-to-end encrypted and stored on users' existing Personal Data Servers — no separate messaging server.

See [PROTOCOL.md](PROTOCOL.md) for the full protocol specification (crypto, record schemas, privacy mechanisms, stealth invite flow).

## Architecture

```
moat/
├── crates/
│   ├── moat-core/      # Pure MLS logic, no IO
│   ├── moat-atproto/   # PDS interaction, ATProto client
│   └── moat-cli/       # Ratatui terminal UI
├── moat-flutter/       # Flutter app (Android + Web)
├── moat-drawbridge/    # Notification relay (Go) [WIP]
└── lexicons/           # ATProto lexicon definitions
```

- **moat-core** — Pure Rust MLS operations using OpenMLS. Key packages, group management, event encryption/decryption, tag derivation, padding, stealth address crypto.
- **moat-atproto** — Async ATProto client. Authentication, publishing/fetching records (`social.moat.keyPackage`, `social.moat.event`, `social.moat.stealthAddress`), handle-to-DID resolution.
- **moat-cli** — Ratatui terminal UI. Login, conversation list, message display, new conversation flow, background polling.
- **moat-flutter** — Flutter app (Android + Web) with Rust FFI via flutter_rust_bridge. See [moat-flutter/README.md](moat-flutter/README.md) for build and usage instructions.
- **moat-drawbridge** — (WIP) Notification relay service in Go. A lightweight WebSocket broker that tells clients *when* to poll, without storing or decrypting messages. Clients authenticate via DID-signed challenge. Supports FCM/APNs push for backgrounded mobile apps. See [notifications-plan.md](notifications-plan.md) for the full design.

## Building & Testing

```bash
cargo build              # Build all crates
cargo test               # Run all tests
cargo run -p moat-cli    # Run the TUI
```

Run tests for a specific crate:

```bash
cargo test -p moat-core
cargo test -p moat-atproto
cargo test -p moat-cli
```

## Usage

```bash
cargo run -p moat-cli
```

On first run, you'll be prompted to log in with your Bluesky handle and an app password.

### Command Line Options

| Option | Description |
|--------|-------------|
| `-s`, `--storage-dir <PATH>` | Custom storage directory (default: `~/.moat`) |

Test with multiple identities:

```bash
cargo run -p moat-cli -- -s /tmp/moat-alice
cargo run -p moat-cli -- -s /tmp/moat-bob
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

MVP implementation. End-to-end encrypted messaging works but needs real-world testing.

### Not Yet Implemented

- Cover traffic (dummy events to obscure activity patterns)

## License

MIT
