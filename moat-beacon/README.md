# moat-beacon

Integration and property-based test harness for the moat stack.

Beacon spins up real processes — [moat-postern](../crates/moat-postern) as an
in-process test PDS and one `moat-cli --http` subprocess per participant — and
drives them through scripted or randomly generated scenarios, asserting
invariants at each step.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Test process                                       │
│                                                     │
│  ┌──────────┐   HTTP    ┌────────────────────────┐  │
│  │  beacon  │ ────────► │  moat-cli --http (alice)│  │
│  │  test    │           └─────────────┬──────────┘  │
│  │          │                         │ XRPC        │
│  │          │   HTTP    ┌─────────────▼──────────┐  │
│  │          │ ────────► │  moat-cli --http (bob)  │  │
│  │          │           └─────────────┬──────────┘  │
│  │          │                         │ XRPC        │
│  │          │           ┌─────────────▼──────────┐  │
│  │          │           │  Postern (in-process)   │  │
│  └──────────┘           └────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

Each `moat-cli --http` process has an isolated temp storage directory and talks
to the shared Postern instance. Tests control participants exclusively through
the typed [`MoatCliClient`](src/client.rs) HTTP wrapper — no direct access to
MLS state or storage.

## Running the tests

```bash
# Run all beacon integration tests
cargo test -p moat-beacon

# Run a specific test file
cargo test -p moat-beacon --test smoke

# See stdout from the test processes
cargo test -p moat-beacon -- --nocapture
```

The `moat` binary (from `moat-cli`) is built automatically on the first run if
it isn't present in `target/debug/`.

## Key types

### `TestWorld` ([`src/world.rs`](src/world.rs))

The central orchestrator for a scenario:

```rust
let world = TestWorld::new(&["alice", "bob"], ".postern.test").await?;
let alice = world.client("alice");
let bob   = world.client("bob");
```

`TestWorld::new` will:
1. Create Postern accounts (`did:test:<handle>`) for each participant.
2. Start a Postern server on a free port.
3. Spawn one `moat-cli --http` subprocess per participant with `--pds-url`
   pointing at Postern.
4. Wait (up to 10 s) for each subprocess's HTTP server to become healthy.

Everything is torn down when `TestWorld` is dropped.

### `MoatCliClient` ([`src/client.rs`](src/client.rs))

Typed async wrapper for the moat-cli REST API:

| Method | HTTP call | Description |
|--------|-----------|-------------|
| `login(handle, pw)` | `POST /login` | Authenticate with Postern |
| `status()` | `GET /status` | Check login state |
| `watch_handle(handle)` | `POST /watch` | Subscribe to a peer's event feed |
| `start_conversation(handle)` | `POST /conversations` | Create a new MLS group |
| `list_conversations()` | `GET /conversations` | List joined groups |
| `send_message(group_id, text)` | `POST /conversations/:id/messages` | Encrypt and publish a message |
| `get_messages(group_id)` | `GET /conversations/:id/messages` | Read decrypted messages |
| `send_reaction(group_id, msg_id, emoji)` | `POST /conversations/:id/messages/:msg_id/reactions` | Send a reaction |
| `poll()` | `POST /poll` | Fetch new events, returns `PollStats` |

## Writing a test

```rust
use moat_beacon::world::TestWorld;

#[tokio::test]
async fn my_scenario() {
    let world = TestWorld::new(&["alice", "bob"], ".postern.test")
        .await
        .expect("world setup");

    let alice = world.client("alice");
    let bob   = world.client("bob");

    alice.login("alice.postern.test", "any-password").await.unwrap();
    bob.login("bob.postern.test", "any-password").await.unwrap();

    // Bob must watch Alice before polling so her events are included.
    bob.watch_handle("alice.postern.test").await.unwrap();

    let group_id = alice.start_conversation("bob.postern.test").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let stats = bob.poll().await.unwrap();
    assert!(stats.new_conversations > 0);

    alice.send_message(&group_id, "hello").await.unwrap();
    let stats = bob.poll().await.unwrap();
    assert!(stats.new_messages > 0);
}
```

### Important: watch before polling

`moat-cli` only polls event feeds for DIDs it already knows about — either from
existing conversation participants or from explicitly watched handles. A fresh
participant with no conversations must call `watch_handle` before their first
`poll`, otherwise the poll fetches nothing.

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | ✅ Done | Smoke test: Alice → Bob message delivery |
| 2 | Planned | Network fault injection via [Toxiproxy](https://github.com/Shopify/toxiproxy) |
| 3 | Planned | Property-based scenarios: random `Action` sequences with `proptest` |
| 4 | Planned | Drawbridge (WebSocket) integration |
| 5 | Planned | `beacon run <name>` / `beacon replay <seed>` CLI |
