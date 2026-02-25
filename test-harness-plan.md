# moat-beacon: Integration & Property Test Runner

## Overview

`moat-beacon` is the integration and property-based test runner for the moat stack. Instead of calling Rust libraries directly, beacon orchestrates real processes — `moat-cli --http`, Postern, Drawbridge, and Toxiproxy — and verifies invariants over randomly generated action sequences.

---

## Location & Crate Structure

```
moat-beacon/             # Top-level, alongside moat-drawbridge and moat-flutter
├── Cargo.toml           # lib + bin, workspace member; proptest in [dependencies] (lib code)
├── src/
│   ├── lib.rs           # Re-exports public types for tests
│   ├── main.rs          # Binary entry point (placeholder; run/replay in Phase 5)
│   ├── world.rs         # TestWorld: orchestrates all processes per scenario
│   ├── client.rs        # MoatCliClient: typed HTTP client for moat-cli --http API
│   ├── toxiproxy.rs     # ToxiproxyManager: download/cache, spawn, configure toxics
│   ├── actions.rs       # Action enum + prop_flat_map fold strategy (✅ done)
│   └── invariants.rs    # Invariant checkers (✅ done)
└── tests/
    ├── smoke.rs                # Basic 2-party message exchange (deterministic)
    └── proptest_two_party.rs   # Property-based 2-party scenarios (✅ done)
```

---

## Binary Interface

```bash
# Run all beacon integration tests
cargo test -p moat-beacon

# Run only the smoke test
cargo test -p moat-beacon --test smoke

# Run only the proptest scenarios
cargo test -p moat-beacon --test proptest_two_party

# Run a named scenario with verbose output (Phase 5)
cargo run -p moat-beacon -- run two-party-chat

# Replay a failing proptest seed (Phase 5)
cargo run -p moat-beacon -- replay <seed-hex>
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
| **Drawbridge** | Subprocess, built via `go build` | Per-scenario (Phase 4) |
| **moat-cli** | Subprocess per participant, `--http :PORT` | Always |

### Proxied connections (for fault injection)

| Proxy | Route | Simulates |
|-------|-------|-----------|
| `proxy-pds` | cli → Postern | Slow or unavailable PDS |
| `proxy-db-{participant}` | cli → Drawbridge WS | Push notification outages |
| `proxy-db-verify` | Drawbridge → Postern | Drawbridge failing event verification |

---

## moat-cli Changes

### Completed

- `--pds-url <url>` — overrides the PDS base URL for all ATProto calls. Used by `TestWorld`
  to point each participant at Postern via the Toxiproxy `proxy-pds` proxy.
- `api_get_messages` sorts by `StoredMessage::timestamp` before returning, giving globally
  consistent message ordering across all participants (see Ordering section below).

### Pending (Phase 4)

- `--drawbridge-url <url>` — overrides the Drawbridge WebSocket URL.

---

## Action Enum

Implemented in `src/actions.rs`. Generation uses a `prop_flat_map` fold that threads a
running message count through each step, so `React` is only generated after at least one
`SendMessage`, and `message_idx` is always a valid index by construction.

```rust
pub enum Action {
    SendMessage { from: ParticipantId, text_idx: usize },  // index into TEXT_VOCAB
    Poll        { participant: ParticipantId },
    React       { from: ParticipantId, message_idx: usize, emoji_idx: usize },
}

pub const TEXT_VOCAB:  &[&str] = &["hi", "hello", "yes", "no", "ok", "bye", "?"];
pub const EMOJI_VOCAB: &[&str] = &["👍", "❤️", "😂", "🎉", "🔥"];
```

Sequence length: 1–10 actions per case, chosen by proptest.

**Deferred actions:**
- `GoOffline` / `ComeOnline` — needs full process restart to test disk serialisation.
- `NewUser` / `NewConversation` — random topology generation; deferred until fixed topology
  is well exercised.

---

## Invariants

Checked after `drain_events` (300 ms sleep + 2 polls per participant):

| Invariant | Checker | Notes |
|-----------|---------|-------|
| **Delivery** | `check_delivery` | Every confirmed message ID appears in both participants' lists |
| **Consensus ordering** | `check_consensus_ordering` | Alice and Bob see the same message sequence in the same order |
| **No duplicates** | `check_no_duplicates` | No participant has a repeated message ID |
| **Per-sender ordering** | `check_per_sender_ordering` | Weaker form: each sender's messages appear in send order in both views |

### Ordering design note

Global consensus ordering (all participants see the same total message sequence) is achievable
because:

1. ATProto rkeys are TIDs — 64-bit values with microsecond timestamps, lexicographically
   sortable.
2. In the test, all records land on the same Postern instance and actions execute sequentially,
   so publish timestamps are strictly monotonic across senders.
3. `api_get_messages` sorts `StoredMessage` by `timestamp` before returning, so both
   participants converge on the same order after drain.

`check_per_sender_ordering` is retained as a documented weaker invariant for future scenarios
involving real multi-PDS deployments with potential clock skew.

**Reaction delivery** is not yet verified: `MessageDto` does not currently expose reactions,
so `React` actions are executed but only checked for absence of errors, not for delivery.
This can be added once reactions are included in the HTTP response.

---

## Topology

Fixed per test scenario for Phases 3–5:
- Each scenario type defines N participants and 1 conversation.
- `proptest` randomises only the action sequence within that topology.

Example named scenarios:
- `two-party-chat`: Alice + Bob, 1 conversation
- `three-party-chat`: Alice + Bob + Carol, 1 conversation (future)

Future: `NewUser` and `NewConversation` actions will allow random topology.

---

## Toxiproxy Management

1. **Check** `TOXIPROXY_BIN` env var, then `PATH` for `toxiproxy-server`.
2. **If not found**: Download from [GitHub releases](https://github.com/Shopify/toxiproxy/releases) for current OS/arch.
3. **Cache** to `~/.cache/moat-beacon/toxiproxy-{version}/toxiproxy-server`.
4. **Spawn** on a random free port; configure proxies via toxiproxy's HTTP management API.
5. **Kill** on `Drop`.

Pinned version: `2.12.0` (`const TOXIPROXY_VERSION` in `src/toxiproxy.rs`).

---

## Drawbridge Management (Phase 4)

1. **Build** the Go binary via `go build -o target/moat-drawbridge/drawbridge ./...` in `moat-drawbridge/`.
2. **Spawn** on a random free port; poll `GET /health` until ready (timeout: 10 s).
3. **Kill** on `Drop`.

Requires Go toolchain at test time. Beacon fails with a clear error if `go` is not in PATH.

---

## Implementation Phases

### Phase 1: Scaffold + smoke test ✅
- `TestWorld`, `MoatCliClient`, `--pds-url` flag on moat-cli.
- `tests/smoke.rs`: Alice sends a message, Bob polls, Bob receives it.
- Postern runs in-process; no Toxiproxy yet.

### Phase 2: Toxiproxy integration ✅
- `ToxiproxyManager`: download/cache, spawn, `create_proxy`, `add_toxic`, `remove_toxic`,
  `disable_proxy`, `enable_proxy`.
- All moat-cli `--pds-url` args point at `proxy-pds`; Postern is no longer contacted directly.
- Smoke test passes unchanged through the proxy.

### Phase 3: proptest action sequences ✅
- `actions.rs`: `Action` enum, `TEXT_VOCAB`, `EMOJI_VOCAB`, `action_sequence()` strategy
  using `prop_flat_map` fold (React only generated after SendMessage; index always valid).
- `invariants.rs`: `ScenarioState`, `drain_events`, `check_delivery`,
  `check_consensus_ordering`, `check_per_sender_ordering`, `check_no_duplicates`.
- `tests/proptest_two_party.rs`: 8 cases, fixed prologue, random action sequence, drain +
  invariants. Runs in ~20 s.
- `api_get_messages` fixed to sort by timestamp, enabling global consensus ordering.

### Phase 4: Drawbridge integration
- `src/drawbridge.rs`: `DrawbridgeProcess` (build + spawn).
- Add `proxy-db-{participant}` and `proxy-db-verify` proxies to `TestWorld`.
- Add `--drawbridge-url` to moat-cli.
- Extend scenarios to use Drawbridge for push delivery.

### Phase 5: Binary + replay
- `beacon run <name>`: run a named scenario with verbose action trace output.
- `beacon replay <seed>`: replay a specific proptest seed from a CI failure.
- Named scenario registry (macro or `inventory` crate pattern).

### Phase 6: GoOffline / ComeOnline (design separately)
- Full process restart (kill subprocess + restart with same `--storage` dir).
- Verify disk state survives: MLS session, conversations, drawbridge state.
- Add to `Action` enum once design is settled.

---

## Files Created / Modified

| File | Status | Description |
|------|--------|-------------|
| `moat-beacon/Cargo.toml` | ✅ | lib + bin; `proptest` in `[dependencies]` |
| `moat-beacon/src/lib.rs` | ✅ | Module re-exports |
| `moat-beacon/src/main.rs` | ✅ | Placeholder binary |
| `moat-beacon/src/world.rs` | ✅ | `TestWorld` orchestrator |
| `moat-beacon/src/client.rs` | ✅ | `MoatCliClient` HTTP wrapper |
| `moat-beacon/src/toxiproxy.rs` | ✅ | `ToxiproxyManager` |
| `moat-beacon/src/actions.rs` | ✅ | `Action` enum + `action_sequence()` strategy |
| `moat-beacon/src/invariants.rs` | ✅ | Invariant checkers |
| `moat-beacon/tests/smoke.rs` | ✅ | Phase 1 smoke test |
| `moat-beacon/tests/proptest_two_party.rs` | ✅ | Phase 3 property tests |
| `crates/moat-cli/src/main.rs` | ✅ | `--pds-url` flag |
| `crates/moat-cli/src/app.rs` | ✅ | `api_get_messages` sorts by timestamp; `--pds-url` plumbed through |
| `moat-beacon/src/drawbridge.rs` | Phase 4 | `DrawbridgeProcess` |
| `crates/moat-cli/src/main.rs` | Phase 4 | `--drawbridge-url` flag |
