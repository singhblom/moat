# moat-beacon: Integration & Property Test Runner

## Overview

`moat-beacon` is the integration and property-based test runner for the moat stack. It replaces the earlier `moat-integration-tests` sketch. Instead of calling Rust libraries directly, beacon orchestrates real processes — `moat-cli --http`, Postern, Drawbridge, and Toxiproxy — and verifies invariants over randomly generated action sequences.

---

## Location & Crate Structure

```
moat-beacon/             # Top-level, alongside moat-drawbridge and moat-flutter
├── Cargo.toml           # lib + bin, workspace member
├── src/
│   ├── lib.rs           # Re-exports public types for tests
│   ├── main.rs          # Binary entry point (run, replay sub-commands)
│   ├── world.rs         # TestWorld: orchestrates all processes per scenario
│   ├── client.rs        # MoatCliClient: typed HTTP client for moat-cli --http API
│   ├── toxiproxy.rs     # ToxiproxyManager: download/cache, spawn, configure toxics
│   ├── drawbridge.rs    # DrawbridgeProcess: build via `go build`, spawn, await health
│   ├── actions.rs       # Action enum + proptest Arbitrary impl
│   └── invariants.rs    # Invariant checkers (delivery, ordering, reactions, dedup)
└── tests/
    └── scenarios/
        ├── smoke.rs               # Basic 2-party message exchange (deterministic)
        └── proptest_two_party.rs  # Property-based 2-party scenarios
```

Add `"moat-beacon"` to the workspace `members` in the root `Cargo.toml`.

---

## Binary Interface

```bash
# Run a named scenario (verbose, prints action trace and result)
cargo run -p moat-beacon -- run two-party-chat

# Replay a specific proptest seed from a CI failure
cargo run -p moat-beacon -- replay <seed-hex>

# Run all scenarios (same as cargo test but with richer output)
cargo test -p moat-beacon
```

---

## Process Architecture

Each scenario spins up a fresh, isolated set of processes. All network paths go through Toxiproxy so tests can inject faults.

```
┌─────────────────────────────────────────────────────────────┐
│                         TestWorld                           │
│                                                             │
│  ┌────────────────┐       ┌──────────────────────────────┐  │
│  │ moat-cli Alice │──┐    │         Toxiproxy            │  │
│  │ --http :A      │  │    │  :proxy-pds      → Postern   │  │
│  └────────────────┘  ├───▶│  :proxy-db-alice → Drawbridge│  │
│  ┌────────────────┐  │    │  :proxy-db-bob  → Drawbridge │  │
│  │ moat-cli Bob   │──┤    │  :proxy-db-verify→ Postern  │  │
│  │ --http :B      │  │    └──────────────────────────────┘  │
│  └────────────────┘  │            │             │           │
│                      │            ▼             ▼           │
│                       ─────▶ ┌──────────┐  ┌───────────┐  │
│                              │ Postern  │  │Drawbridge │  │
│                              │ (in-proc)│  │(Go proc)  │  │
│                              └──────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | How started | Required |
|-----------|-------------|----------|
| **Postern** | In-process via `spawn_postern()` | Always |
| **Toxiproxy** | Subprocess, auto-downloaded & cached | Always |
| **Drawbridge** | Subprocess, built via `go build` | Per-scenario |
| **moat-cli** | Subprocess per participant, `--http :PORT` | Always |

### Proxied connections (for fault injection)

| Proxy | Route | Simulates |
|-------|-------|-----------|
| `proxy-pds` | cli → Postern | Slow or unavailable PDS |
| `proxy-db-{participant}` | cli → Drawbridge WS | Push notification outages |
| `proxy-db-verify` | Drawbridge → Postern | Drawbridge failing event verification |

---

## moat-cli Changes Required

Two new flags must be added to `moat-cli`:

```
--pds-url <url>         Override PDS base URL (default: from credentials.json)
--drawbridge-url <url>  Override Drawbridge WebSocket URL (default: from stored state)
```

Each participant process also gets its own temp storage dir via the existing `--storage` flag, so state is isolated:

```
/tmp/beacon-{run-id}/
├── alice/     # Alice's --storage dir
└── bob/       # Bob's --storage dir
```

---

## Action Enum

Initial set for proptest generation:

```rust
#[derive(Debug, Clone, Arbitrary)]
enum Action {
    SendMessage {
        from: ParticipantId,
        text: String,
    },
    Poll {
        participant: ParticipantId,
    },
    React {
        from: ParticipantId,
        emoji: String,  // constrained to a small emoji set
    },
    StartConversation {
        initiator: ParticipantId,
        recipient: ParticipantId,
    },
}
```

**Deferred actions** (important but require more design):
- `GoOffline` / `ComeOnline` — needs full process restart to test disk serialization, not just WebSocket disconnect. Design separately once the scaffold is working.
- `NewUser` / `NewConversation` — enables random topology generation. Deferred until fixed topology works well.

---

## Invariants

Checked after each generated action sequence completes (all participants poll to drain pending events):

1. **Message delivery**: Every message sent is present in every online participant's message list for that conversation.
2. **Ordering**: Messages appear in send order for each participant (no reordering within a conversation).
3. **Reaction consistency**: If a reaction was sent, all participants see it attached to the correct message.
4. **No duplicates**: No participant's message list contains the same message ID more than once.

---

## Topology

Initially fixed per test scenario:
- Each scenario type defines N participants and 1 conversation.
- `proptest` randomizes only the action sequence within that topology.

Example named scenarios:
- `two-party-chat`: Alice + Bob, 1 conversation
- `three-party-chat`: Alice + Bob + Carol, 1 conversation

Future: `NewUser` and `NewConversation` actions will allow random topology.

---

## Toxiproxy Management

1. **Check** `TOXIPROXY_BIN` env var, then `PATH` for `toxiproxy-server`.
2. **If not found**: Download from [GitHub releases](https://github.com/Shopify/toxiproxy/releases) for current OS/arch.
3. **Cache** the downloaded binary to `~/.cache/moat-beacon/toxiproxy-{version}/toxiproxy-server`.
4. **Spawn** on a random free port; configure proxies via toxiproxy's HTTP management API.
5. **Kill** on `Drop` (or scenario teardown).

Toxiproxy version is pinned in the beacon crate (e.g., `const TOXIPROXY_VERSION: &str = "2.12.0";`).

---

## Drawbridge Management

1. **Build** the Go binary via `go build -o target/moat-drawbridge/drawbridge ./...` in `moat-drawbridge/`.
2. **Spawn** on a random free port; poll `GET /health` until ready (timeout: 10s).
3. **Kill** on `Drop`.

Requires Go toolchain at test time. Beacon fails with a clear error if `go` is not in PATH.

---

## Implementation Phases

### Phase 1: Scaffold + smoke test
- Create crate structure, `TestWorld`, `MoatCliClient`.
- Add `--pds-url` and `--drawbridge-url` to moat-cli.
- Write `smoke.rs`: Alice sends a message, Bob polls, Bob receives it.
- No Toxiproxy, no Drawbridge required for Phase 1.

### Phase 2: Toxiproxy integration
- Implement `ToxiproxyManager` (download/cache, spawn, proxy config API).
- Route all connections through proxies.
- Verify smoke test still passes with proxies in the path (no toxics added).

### Phase 3: proptest action sequences
- Implement `Action` enum with `proptest::Arbitrary`.
- Implement `execute_action()` against `MoatCliClient`.
- Implement invariant checkers in `invariants.rs`.
- Write `proptest_two_party.rs` — generates random 2-party action sequences, checks invariants.

### Phase 4: Drawbridge integration
- Implement `DrawbridgeProcess` (build + spawn).
- Add Drawbridge proxy to Toxiproxy setup.
- Add `--drawbridge-url` support to moat-cli.
- Extend scenarios to use Drawbridge for push delivery.

### Phase 5: Binary + replay
- Implement `beacon run <name>` and `beacon replay <seed>` commands.
- Register named scenarios in a `scenarios![]` registry macro or inventory pattern.

### Phase 6: GoOffline / ComeOnline (design separately)
- Full process restart (kill subprocess + restart with same --storage dir).
- Verify disk state survives: MLS session, conversations, drawbridge state.
- Add to Action enum once design is clear.

---

## Files To Create / Modify

| File | Change |
|------|--------|
| `Cargo.toml` (root) | Add `"moat-beacon"` to workspace members |
| `moat-beacon/Cargo.toml` | New crate: lib + bin |
| `moat-beacon/src/lib.rs` | Re-exports |
| `moat-beacon/src/main.rs` | `run` and `replay` CLI commands |
| `moat-beacon/src/world.rs` | `TestWorld` orchestrator |
| `moat-beacon/src/client.rs` | `MoatCliClient` HTTP wrapper |
| `moat-beacon/src/toxiproxy.rs` | `ToxiproxyManager` |
| `moat-beacon/src/drawbridge.rs` | `DrawbridgeProcess` |
| `moat-beacon/src/actions.rs` | `Action` enum + proptest Arbitrary |
| `moat-beacon/src/invariants.rs` | Invariant checkers |
| `moat-beacon/tests/scenarios/smoke.rs` | Phase 1 smoke test |
| `moat-beacon/tests/scenarios/proptest_two_party.rs` | Phase 3 property tests |
| `crates/moat-cli/src/main.rs` | Add `--pds-url`, `--drawbridge-url` flags |
| `crates/moat-cli/src/app.rs` | Plumb new URL overrides through App::new() |

---

## Verification

```bash
# Phase 1 smoke test (no Drawbridge, no Toxiproxy)
cargo test -p moat-beacon smoke

# All beacon tests (requires toxiproxy in PATH or auto-downloads)
cargo test -p moat-beacon

# Run a named scenario with verbose output
cargo run -p moat-beacon -- run two-party-chat

# Replay a failing proptest seed
cargo run -p moat-beacon -- replay abc123...

# Ensure nothing broken in other crates
cargo test -p moat-postern
cargo test -p moat-atproto
cargo test -p moat-core
```
