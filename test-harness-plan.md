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
│   ├── main.rs          # Binary: list / run <name> / replay <name> <seed>
│   ├── world.rs         # TestWorld: orchestrates all processes per scenario
│   ├── client.rs        # MoatCliClient: typed HTTP client for moat-cli --http API
│   ├── toxiproxy.rs     # ToxiproxyManager: download/cache, spawn, configure toxics
│   ├── actions.rs       # Action enum + prop_flat_map fold strategy
│   ├── invariants.rs    # Invariant checkers
│   ├── drawbridge.rs    # DrawbridgeProcess: build Go binary, spawn, health-check
│   └── scenarios/
│       ├── mod.rs                  # Scenario registry, shared helpers, seed utilities
│       ├── two_party_chat.rs       # Polling delivery scenario
│       ├── two_party_push.rs       # Drawbridge push delivery scenario
│       ├── two_party_restart.rs    # Polling delivery + offline/online cycles
│       └── two_party_push_restart.rs # Push delivery + offline/online cycles
└── tests/
    ├── smoke.rs                    # Basic 2-party message exchange (deterministic)
    ├── proptest_two_party.rs       # Property-based polling scenarios
    ├── proptest_drawbridge.rs      # Property-based push-delivery scenarios
    ├── proptest_restart.rs         # Property-based polling + restart scenarios
    └── proptest_push_restart.rs    # Property-based push + restart scenarios
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
cargo test -p moat-beacon --test proptest_drawbridge
cargo test -p moat-beacon --test proptest_restart
cargo test -p moat-beacon --test proptest_push_restart

# List available scenarios
cargo run -p moat-beacon -- list

# Run a named scenario once with verbose output (random actions)
cargo run -p moat-beacon -- run two-party-chat

# Replay a failing proptest seed (same seed → same pre-shrink action sequence)
# Seed format matches proptest regression files: "cc <64-hex>"
cargo run -p moat-beacon -- replay two-party-chat "cc b66c98ff3f0c0de590ad11de287c4eefcdd098090ceb2b3546f42680b8b6ede0"
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

### Completed (Phase 4)

- `--drawbridge-url <url>` — overrides the Drawbridge WebSocket URL (already
  implemented).
- `POST /poll/{seconds}` — sets the auto-poll interval; `0` disables polling.

### Completed (Phase 6)

- `spawn_poll_messages` deduplicates across `dids_with_rkeys` (conversation participants)
  and `watched` (watched_dids): any DID already covered by a conversation is excluded
  from the watched list. Prevents double-fetch and double-processing when the same peer
  appears in both sets (e.g. after a restart + re-watch).

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
    GoOffline   { participant: ParticipantId },
    ComeOnline  { participant: ParticipantId },
}

pub const TEXT_VOCAB:  &[&str] = &["hi", "hello", "yes", "no", "ok", "bye", "?"];
pub const EMOJI_VOCAB: &[&str] = &["👍", "❤️", "😂", "🎉", "🔥"];
```

Sequence length: 1–10 actions per case, chosen by proptest.

Two strategies:
- `action_sequence()` — no GoOffline/ComeOnline; used by `two-party-chat` and
  `two-party-push`.
- `action_sequence_with_offline()` — extends the fold state with a `[bool; 2]` online
  mask; offline participants may only `ComeOnline`, online participants may `GoOffline`.
  Used by `two-party-restart` and `two-party-push-restart`.

**Deferred actions:**
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

### Phase 4: Drawbridge integration ✅

Goal: verify that messages are delivered via WebSocket push *without polling*. A new
`proptest_drawbridge.rs` test runs the same two-party action sequences as Phase 3, but
with `POST /poll/0` (polling disabled) after Drawbridge connects. All delivery must come
through the push path.

#### moat-cli HTTP API change

- `POST /poll/{seconds}` — sets the auto-poll interval. `0` disables polling entirely.
  Useful for production (user-configurable interval) and for tests (disable polling to
  verify push delivery).

#### moat-drawbridge change

- Add `PLC_BASE_URL` env var (defaults to `https://plc.directory`). Forwarded to
  `PLCResolver` so the base URL is configurable for test environments.

#### moat-postern changes

- `PosternConfig` gains `pds_endpoint_override: Option<String>`. When set, all DID
  documents use this value as `serviceEndpoint` instead of Postern's own URL. TestWorld
  sets this to the `proxy-db-verify` Toxiproxy address so Drawbridge's PDS verification
  calls are routed through the proxy.
- Add `GET /{did}` route: returns a per-user DID document for any pre-configured account
  DID. Used by Drawbridge's PLCResolver to resolve test DIDs without hitting
  `plc.directory`.
- Account DIDs in TestWorld use `did:plc:` format (e.g., `did:plc:alice`,
  `did:plc:bob`) so Drawbridge's PLCResolver accepts them without modification.

#### moat-beacon additions

**`src/drawbridge.rs` — `DrawbridgeProcess`**:
1. Build the Go binary: `go build -o target/moat-drawbridge/drawbridge ./...` in
   `moat-drawbridge/`. Fail with a clear error if `go` is not in PATH. Skip rebuild if
   binary is newer than all `*.go` sources.
2. Spawn on a random free port with env vars:
   - `RELAY_TLS=false`
   - `RELAY_ADDR=:{port}`
   - `RELAY_PUBLIC_URL=ws://localhost:{port}`
   - `PLC_BASE_URL=http://{proxy-db-verify-url}` (set after Toxiproxy is up)
   - `LOG_FORMAT=text`
3. Poll `GET /health` until ready (timeout: 10 s, 250 ms interval).
4. Kill subprocess on `Drop`.

**TestWorld additions**:
- Spawn one `DrawbridgeProcess` per `TestWorld`.
- Add Toxiproxy proxies:
  - `proxy-db-alice` → Drawbridge (for Alice's sender connection)
  - `proxy-db-bob` → Drawbridge (for Bob's recipient connection)
  - `proxy-db-verify` → Postern (for Drawbridge's DID resolution + key-package
    verification calls)
- Each participant's `moat-cli` subprocess gets
  `--drawbridge-url ws://proxy-db-{name}-url`.
- Postern is configured with `pds_endpoint_override = proxy-db-verify-url`.
- Drawbridge is spawned with `PLC_BASE_URL = proxy-db-verify-url`.

**DrawbridgeHint exchange**: implicit. When `--drawbridge-url` is set, moat-cli includes
its Drawbridge hint in the MLS conversation-start flow. Bob connects to Alice's
Drawbridge as recipient automatically on the next poll after receiving the hint.

**`tests/proptest_drawbridge.rs`** (new file):
- Same prologue as `proptest_two_party`: login + watch + start_conv + Bob joins.
- Additional setup: wait for Drawbridge connections (poll once to exchange hints, then
  call `POST /poll/0` on all participants to disable polling).
- Same random action sequence (length 1–10).
- Same `drain_events` → invariant checks, but drain relies on push-triggered fetches
  rather than timed polls. `drain_events` adds a short sleep (300 ms) for push
  propagation, then checks delivery without explicitly polling.
- 8 proptest cases.

### Phase 5: Binary + replay ✅
- `src/scenarios/` module with `Scenario` registry, shared helpers (`pick_client`,
  `execute_action`, `format_action`), `vlog!` macro, and seed utilities
  (`parse_seed`, `actions_from_seed`, `generate_random_actions`).
- `two_party_chat::run` and `two_party_push::run` extracted from test files; each
  accepts a `verbose: bool` flag for structured `[setup]` / `[action]` / `[check]`
  output.
- `beacon list` — prints name + description for all registered scenarios.
- `beacon run <name>` — generates random actions, runs scenario with verbose output.
- `beacon replay <name> <seed>` — parses `"cc <64-hex>"` seed from proptest
  regression files; reconstructs the same action sequence via `TestRng::from_seed`.
- Test files (`proptest_two_party.rs`, `proptest_drawbridge.rs`) refactored to
  delegate to `scenarios::two_party_chat::run(actions, false)` etc., removing
  duplicate `pick_client` / `execute_action` / `run_scenario` definitions.

### Phase 6: GoOffline / ComeOnline ✅

Full process kill/restart to verify that on-disk MLS state, conversation membership,
and key material survive restarts, and that messages sent while a participant is offline
are delivered after they reconnect — via polling and via Drawbridge push.

#### moat-beacon additions

**`src/actions.rs`**:
- `GoOffline { participant }` and `ComeOnline { participant }` variants added to `Action`.
- `action_sequence_with_offline()` strategy: extends the fold state with a `[bool; 2]`
  online mask so proptest never generates invalid transitions (e.g. going offline when
  already offline).
- `generate_random_actions_offline` / `actions_from_seed_offline` for the binary.

**`src/world.rs`**:
- `ParticipantProcess` gains `spawn_args: Vec<String>` (full CLI args including
  `--http <addr>`) and `child: Option<Child>` (None when offline).
- `kill_participant` — SIGKILL + wait; sets `child = None`.
- `restart_participant` — respawns with the same args; waits up to 10s for HTTP ready.
- `participant_is_online` — `child.is_some()`.

**`src/scenarios/mod.rs`**:
- `execute_action` extended with `world`, `alice_full_handle`, `bob_full_handle`,
  `push_mode` parameters.
- `GoOffline` arm: 100ms sleep (to let any in-flight ATProto publish complete over
  loopback) then `kill_participant`.
- `ComeOnline` arm: `restart_participant` → re-login → re-watch → catch-up `poll` →
  (push mode) `set_poll_interval(0)`.
- `ensure_all_online` helper: brings any offline participant back online with the same
  sequence, used in the drain phase.
- `generate_random_actions_offline` / `actions_from_seed_offline` registered for the
  new scenarios.

**New scenario files**:
- `two_party_restart.rs` — polling delivery with offline/online cycles.
- `two_party_push_restart.rs` — Drawbridge push delivery with offline/online cycles.
  Uses `drain_events_push` from `two_party_push`.

**New test files**:
- `tests/proptest_restart.rs` — 8 cases, delegates to `two_party_restart::run`.
- `tests/proptest_push_restart.rs` — 8 cases, delegates to `two_party_push_restart::run`.

#### Bugs found and fixed during Phase 6

**moat-cli `app.rs` — duplicate poll from watched_dids**:
`spawn_poll_messages` built two separate fetch lists: `dids_with_rkeys` (from
`self.conversations`) and `watched` (from `self.watched_dids`). After a participant
restart and re-watch, the same DID could appear in both, causing its ATProto records to
be fetched and processed twice — producing duplicate messages. Fixed by filtering
`watched_dids` to exclude any DID already in `dids_to_poll` before building the
`watched` list.

**moat-beacon `scenarios/mod.rs` — GoOffline race with async publish**:
`send_message` in moat-cli spawns the ATProto record publish as a background tokio task
and returns immediately. The local message is stored with a `message_id` before the
publish completes. A `GoOffline` immediately after would SIGKILL the process before the
loopback HTTP POST to Postern finished, leaving the record absent from the PDS. The
delivery checker then expected both participants to have the message. Fixed by sleeping
100ms before `kill_participant` in the `GoOffline` handler.

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
| `moat-beacon/src/drawbridge.rs` | ✅ | `DrawbridgeProcess` (build + spawn + health + Drop) |
| `moat-beacon/tests/proptest_drawbridge.rs` | ✅ | Push-delivery property tests (polling disabled) |
| `crates/moat-cli/src/http_server.rs` | ✅ | `POST /poll/{seconds}` endpoint |
| `crates/moat-postern/src/config.rs` | ✅ | `pds_endpoint_override` field on `PosternConfig` |
| `crates/moat-postern/src/server.rs` | ✅ | `GET /{did}` per-user DID doc route; use override in serviceEndpoint |
| `moat-drawbridge/main.go` | ✅ | `PLC_BASE_URL` env var forwarded to PLCResolver |
| `moat-beacon/src/world.rs` | ✅ | Spawn Drawbridge; add proxy-db-{name} + proxy-db-verify proxies |
| `moat-beacon/src/scenarios/mod.rs` | ✅ | Scenario registry, shared helpers, seed utilities, `execute_action`, `ensure_all_online` |
| `moat-beacon/src/scenarios/two_party_chat.rs` | ✅ | Polling delivery scenario (`run` + `run_boxed`) |
| `moat-beacon/src/scenarios/two_party_push.rs` | ✅ | Push delivery scenario (`run` + `run_boxed`) |
| `moat-beacon/src/scenarios/two_party_restart.rs` | ✅ | Polling delivery + offline/online cycles |
| `moat-beacon/src/scenarios/two_party_push_restart.rs` | ✅ | Push delivery + offline/online cycles |
| `moat-beacon/src/main.rs` | ✅ | `list` / `run <name>` / `replay <name> <seed>` |
| `moat-beacon/tests/proptest_restart.rs` | ✅ | Property-based polling + restart scenarios |
| `moat-beacon/tests/proptest_push_restart.rs` | ✅ | Property-based push + restart scenarios |
| `crates/moat-cli/src/app.rs` | ✅ | Fix: deduplicate watched_dids vs dids_to_poll in spawn_poll_messages |
