---
name: local-test
description: Stand up a local Moat test environment (Postern PDS, Drawbridge, moat-cli and Flutter participants) and drive it for manual or exploratory testing. Use this whenever the user wants to try Moat by hand, reproduce a bug outside the test suite, test pairing or history sync end to end, generate conversation history at scale, check how something looks or reads in the TUI or the Flutter app, or asks to "run the app locally", "set up a test env", "seed some messages", or "let me try this myself". Also use it to run the test suites or the verification gate, so that a failure keeps its panic message.
---

# Local test environment

Runs Moat against a local PDS and Drawbridge so no real accounts are involved, and
drives it through the HTTP API — the same surface `moat-beacon` uses, so
anything reproduced here can become a Beacon scenario.

## The division of labour

Most of what a manual pass used to involve is already covered by Beacon, in
every runtime mix, five times over in the verification gate. Re-running it by
hand costs an afternoon and proves less.

**What an agent should do:** everything expressible through the HTTP API —
standing up the stack, creating accounts and conversations, generating history
at scale, pairing devices, interrupting and resuming syncs, measuring timings,
diffing device state.

**What needs a human:** what the screens *render*, what the wording *says*,
whether something is pleasant to use, and wandering off-script. The HTTP API
returns state; it cannot return what the TUI drew or whether a message reads
as success or failure.

Keep that line in mind when the user asks for a "manual test". Offer to do the
mechanical half rather than handing them a forty-step checklist.

## 1. Stand up the stack

```bash
.claude/skills/local-test/scripts/dev-stack.sh up
```

Postern on `:4000`, Drawbridge on `:8080` (`ws://127.0.0.1:8080/ws`). Accounts `alice.postern.test` and `bob.postern.test`, any
password — Postern does not validate one. `down` stops it, `logs` tails both,
`--help` prints the full API crib sheet.

**Start from a fresh stack whenever device state is wiped.** Postern keeps
records across device restarts, so deleting `/tmp/moat-*` without recycling
Postern leaves stale KeyPackages on the PDS. A re-created device then has an
invite claimed against a key it no longer holds, and the invite silently never
arrives — no error, just nothing. `down && up` gives Postern a new data dir;
`delete-all` does not help, because it wipes the credentials it would need to
clear the PDS.

## 2. Start participants

Each device needs its own storage dir, or they share keys and behave as one.

```bash
# TUI — what a human looks at
cargo run -p moat-cli -- -s /tmp/moat-alice --pds-url http://127.0.0.1:4000 \
  --drawbridge-url ws://127.0.0.1:8080/ws

# headless — what an agent drives
cargo run -p moat-cli -- -s /tmp/moat-alice --pds-url http://127.0.0.1:4000 \
  --drawbridge-url ws://127.0.0.1:8080/ws --http 127.0.0.1:9101
```

HTTP devices start logged out; log in explicitly. Without `--drawbridge-url` a
device has no Drawbridge and polls only. For Flutter and Android specifics see
`references/flutter.md`.

## 3. Generate history

```bash
.claude/skills/local-test/scripts/seed-history.py --messages 200
```

Starts two headless devices, logs them in, creates a conversation and fills it,
then waits for both sides to agree and reports what is missing by name.
`--help` lists the knobs; `--messages 1000+` is for when scale is the point.

Read the convergence line, not just the exit code. `Converge NO` with named
missing messages is a finding; re-poll before believing it, and if it persists
it belongs in a Beacon scenario rather than a bug report.

Two things the script deliberately separates, because folding them together
reports false failures: **enqueue rate is not delivery** — `send` returns once
the message is queued locally — and **images upload asynchronously**, so the
sender shows `[image — processing…]` until the blob lands.

## 4. Drive the interesting paths

The HTTP API covers pairing, history sync, restart and push. `dev-stack.sh
--help` has the full endpoint list. Three things that are easy to get wrong:

**Pairing is two steps with a wait between them.** `/pair/new` returns the
code and the Drawbridge it is on, and `/pair/confirm` needs both (the rendezvous is
on the new device's Drawbridge). `/pair/confirm` only joins the rendezvous; the Enroll frame arrives over the pair WebSocket afterwards.
Approving before it lands fails with "no pending Enroll". Poll `/pair/status`
until `awaiting_approval`, then `/pair/approve`.

**Pairing and history sync are separate lanes with separate approvals.**
`/pair/confirm` → `/pair/approve` enrolls a device. `/sync/request` →
`/sync/accept` (or `/sync/decline`) moves history. Using one for the other
fails with a confusing message.

**A sync request rides the device ring**, so the sibling only sees it on its
next ring tick — up to ~30 s. `/ring-tick` forces it. Something that looks
like a broken request is usually this.

To test resume-after-interruption, kill a device mid-sync, restart it, and
finish with a requested sync. Check the message count before and after: the
tally should account for exactly the gap, with no duplicates.

## 5. Hand over to the human

When the mechanical part is done, tell the user what state you have left them
and what specifically needs their eyes. `references/manual-pass.md` has the
checklist of things no test can reach — read it when preparing a handover, and
suggest the subset that is relevant to what changed rather than the whole
list.

Record findings somewhere durable as you go. A finding that only exists in a
terminal scrollback is lost when the session ends.

## Running the suites: keep the full log

Run tests so that a failure leaves its panic message behind. Failures that
pass on rerun are common here (a Beacon world that does not come up, a
timeout under load), and the message of that first failure is all there is
to diagnose them from. A Beacon test that dies in `world setup` names only
the line that called `.expect(..)`; the cause is in the message after it.

**Never filter test output down to its result lines.** Piping `cargo test`
through `grep "test result|FAILED"` drops every panic message.

```bash
# One suite: full log kept, failing tests and panic messages printed
.claude/skills/local-test/scripts/run-tests.sh beacon-smoke \
  cargo test -p moat-beacon --test smoke --no-fail-fast

# Every suite, repeated (default 5): per-step logs and a summary that has
# each failure's panic messages beside its FAIL line
.claude/skills/local-test/scripts/verification-gate.sh

# Any log you already have
.claude/skills/local-test/scripts/failure-summary.sh path/to/log
```

Both scripts keep the log (`/tmp/moat-test-logs/`, and the gate's own
`/tmp/moat-gate-<time>/`) and set `RUST_BACKTRACE=1`. Use `--no-fail-fast`
so one failing test binary does not hide the rest. If you must run a command
by hand, redirect it to a file (`> log 2>&1`) and read the file; do not
filter it on the way.

For a Beacon failure, the participants' own logs are in `/tmp/moat-beacon/`
(`<handle>-<timestamp>.log`), and the panic message usually quotes the
tail of the one that stalled. When a failure does not reproduce, say so and
report the captured message rather than guessing at a cause.

## Cleaning up

```bash
.claude/skills/local-test/scripts/dev-stack.sh down
rm -rf /tmp/moat-alice /tmp/moat-bob1 /tmp/moat-bob2
```

Postern's own state is a temp dir, discarded on stop.

## A caution about stale binaries

Devices started from `target/debug/moat` keep running whatever was built when
they started, while `cargo run` in another terminal rebuilds it. Mixing the two
produces peers on different code, which surfaces as protocol errors that
describe a byte count rather than the real problem. If two devices disagree
about a wire format, check binary mtime against process start time before
believing the error.

Note also that a `--bin` filter applies to a whole `cargo build` invocation, so
building several packages with one `--bin` flag silently skips the others'
binaries.
