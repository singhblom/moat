# moat-cli

Terminal UI and command-line tools for Moat encrypted messaging over ATProto.

## Usage

Running without a subcommand launches the interactive TUI:

```bash
cargo run -p moat-cli
```

### Global Flags

- `-s, --storage-dir <PATH>` — Custom storage directory (default: `~/.moat`). Applies to all subcommands.

```bash
# Run two accounts locally for testing
cargo run -p moat-cli -- -s /tmp/moat-alice
cargo run -p moat-cli -- -s /tmp/moat-bob
```

### TUI Keybindings

| Key | Context | Action |
|---|---|---|
| `n` | Conversations | Start new conversation |
| `w` | Conversations | Watch a handle for incoming invites |
| `j/k` or arrows | Conversations / Messages | Navigate |
| `Enter` | Conversations | Open conversation |
| `Tab` | Any | Switch focus |
| `Esc` | Any | Go back |
| `q` | Conversations / Messages | Quit |
| `Ctrl+C` | Any | Quit |

## Subcommands

### `fetch`

Fetch events from a repository for debugging. Reads the last-known rkey from local state and only fetches newer events. Does not update local state. Attempts to decrypt events using local MLS state (read-only).

```bash
cargo run -p moat-cli -- fetch --repository alice.bsky.social
```

### `status`

Print account info, conversation count, last sync rkey, and storage size.

```bash
cargo run -p moat-cli -- status
```

### `send-test`

Publish an encrypted message to a conversation identified by its current tag.

```bash
cargo run -p moat-cli -- send-test --tag <32-char-hex> --message "hello world"
```

The tag is the hex-encoded 16-byte conversation tag for the current epoch. You can find it in the debug log.

### `export`

Export debug logs or event data. At least one of `--log` or `--events` is required.

```bash
# Export debug log
cargo run -p moat-cli -- export --log /tmp/moat-debug.log

# Export events as JSON
cargo run -p moat-cli -- export --events /tmp/events.json --repository alice.bsky.social

# Both
cargo run -p moat-cli -- export --log /tmp/debug.log --events /tmp/events.json --repository alice.bsky.social
```
