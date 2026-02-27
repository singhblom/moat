# moat-beacon

Integration and property-based test harness for the moat stack.

Beacon spins up real processes — [moat-postern](../crates/moat-postern) as an
in-process test PDS and one `moat-cli --http` subprocess per participant — and
drives them through scripted or randomly generated scenarios, asserting
invariants at each step.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Test process                                                       │
│                                                                     │
│  ┌──────────┐  HTTP  ┌──────────────────┐                           │
│  │  beacon  │ ──────►│ moat-cli (alice) │──┐                        │
│  │  test /  │  HTTP  ├──────────────────┤  │   ┌────────────────┐   │
│  │  binary  │ ──────►│ moat-cli (bob)   │──┼──►│   Toxiproxy    │   │
│  └──────────┘        └──────────────────┘  │   │  proxy-pds     ├─┐ │
│                                            │   │  proxy-db-*    │ │ │
│                                            └──►│  proxy-db-verify│ │ │
│                                                └────────┬───────┘ │ │
│                                                    WS   │   XRPC  │ │
│                                              ┌──────────▼──┐  ┌───▼─┴──┐ │
│                                              │ Drawbridge  │  │Postern │ │
│                                              │  (Go proc)  │  │(in-proc)│ │
│                                              └─────────────┘  └────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

All XRPC calls from `moat-cli` to Postern pass through the `proxy-pds`
Toxiproxy proxy. In Drawbridge scenarios, WebSocket connections are routed
through per-participant `proxy-db-*` proxies. Tests can inject latency,
bandwidth limits, or connection resets via [`TestWorld::toxiproxy`](src/world.rs)
without touching any application code.

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
cargo test -p moat-beacon --test proptest_two_party    # ~20 s
cargo test -p moat-beacon --test proptest_drawbridge   # ~35 s, requires Go

# See stdout from the test processes
cargo test -p moat-beacon -- --nocapture
```

The `moat` binary (from `moat-cli`) is built automatically on the first run if
it isn't present in `target/debug/`. The Drawbridge binary is built via `go build`
on first use.

## `beacon` binary

The `beacon` binary lets you run or replay scenarios interactively, outside of
`cargo test`. Useful for debugging CI failures or exploring scenario behaviour.

```bash
# List available scenarios
cargo run -p moat-beacon -- list

# Run a named scenario once with verbose output (random action sequence)
cargo run -p moat-beacon -- run two-party-chat
cargo run -p moat-beacon -- run two-party-push

# Replay a proptest seed from a CI failure
# Seed format matches proptest regression files: "cc <64-hex>"
cargo run -p moat-beacon -- replay two-party-chat \
  "cc b66c98ff3f0c0de590ad11de287c4eefcdd098090ceb2b3546f42680b8b6ede0"
```

**Verbose output format:**
```
=== Scenario: two-party-chat ===
[setup] starting TestWorld...
[setup] login alice... done
[setup] login bob... done
[setup] bob watches alice... done
[setup] alice starts conversation... group=abc123...
[setup] bob polls to join... done (1 new conversations)

[action 1/5] SendMessage { from: Alice, text: "hi" }
[action 2/5] Poll { participant: Bob }
[action 3/5] SendMessage { from: Bob, text: "no" }
[action 4/5] React { from: Alice, msg_idx: 0, emoji: "👍" }
[action 5/5] SendMessage { from: Alice, text: "ok" }

[drain] waiting for events to propagate...
[check] delivery... ok (3 messages)
[check] consensus ordering... ok
[check] no duplicates... ok

=== PASSED ===
```

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
| `get_messages(group_id)` | `GET /conversations/:id/messages` | Read decrypted messages (sorted by timestamp) |
| `send_reaction(group_id, msg_id, emoji)` | `POST /conversations/:id/messages/:msg_id/reactions` | Send a reaction |
| `poll()` | `POST /poll` | Fetch new events, returns `PollStats` |
| `set_poll_interval(seconds)` | `POST /poll/:seconds` | Set auto-poll interval; `0` disables polling |

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
| 2 | ✅ Done | Toxiproxy integration: all connections proxied, fault injection ready |
| 3 | ✅ Done | Property-based scenarios: random `Action` sequences with `proptest` |
| 4 | ✅ Done | Drawbridge (WebSocket) integration: push delivery, `proptest_drawbridge` |
| 5 | ✅ Done | `beacon list` / `beacon run <name>` / `beacon replay <name> <seed>` CLI |
| 6 | Planned | `GoOffline` / `ComeOnline` actions: full process restart, disk-state survival |
