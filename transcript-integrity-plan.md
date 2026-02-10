# Transcript Integrity Plan

Implementation and testing plan for verifiable transcripts and
multi-device commit resilience in moat-core. This is the highest-impact
work in the hardening plan — the gap between "the crypto is correct" and
"the protocol is correct."

## Current State

Today `MoatSession` processes each event in isolation. The `Event` struct
carries `(kind, group_id, epoch, payload, message_id)` but has no context
about where it sits in a sequence or what MLS state produced it. The
`decrypt_event` method decrypts, unpads, deserializes, and returns — no
validation beyond what OpenMLS enforces internally. Failures are returned
as `Error::Decryption` or `Error::MergeCommit` with no structured
recovery path.

This means:

- A PDS can **withhold** events (drop M2 from M1, M2, M3) — undetected.
- A PDS can **reorder** events — undetected.
- Two devices can **fork** MLS state via concurrent commits — undetected,
  unrecoverable.
- The epoch field in `Event` is **never validated** against local state.
- Decryption failures in the CLI are **logged and silently dropped**
  (`app.rs:772–775`).

## Design Decisions

The following decisions were made during specification review:

- **Hash chain identity:** Per `device_id` (16-byte random ID from
  MoatSession), not per DID. Each device maintains its own independent
  hash chain. Two devices from the same user are two separate chains.
  This matches MLS's per-leaf-node model.

- **Hash input:** The plaintext Event JSON (serialized Event struct via
  serde, before padding and encryption). The hash is computed inside the
  encryption boundary and is only verifiable by group members who can
  decrypt.

- **Decrypt return type:** `Result<DecryptOutcome, Error>` where
  `DecryptOutcome` is a custom enum with `Success(DecryptResult)` and
  `Warning(DecryptResult, Vec<TranscriptWarning>)` variants. This forces
  callers to explicitly handle the warning case at the function boundary.
  A `.result()` helper method on `DecryptOutcome` extracts the
  `DecryptResult` regardless of variant for callers who want to defer
  warning handling. Unrecoverable errors propagate via `?` as usual.

- **Epoch fingerprint:** Request exactly 16 bytes from
  `MlsGroup::export_secret()` with label `"moat-epoch-fingerprint-v1"`.
  No truncation needed — the exporter accepts a requested length. 128
  bits is sufficient for consistency checking (not a security binding).

- **State format:** Extend `export_state` from v1 to v2. The v2 format
  appends the hash chain state (`HashMap<(GroupId, DeviceId), [u8; 32]>`)
  after the MLS data. Single blob, atomic export/import.

- **v1 backward compatibility:** A v2 client encountering a v1 state
  blob returns `Error::StateVersionMismatch`. No automatic migration.
  The project is in early development with only two test DIDs — manual
  state wipe and re-initialization is acceptable.

- **Error codes:** Freely renumber all `ErrorCode` variants. No need
  to preserve existing u32 values. The Flutter FFI error handling will
  be updated to match.

- **Conflict recovery:** Automatic recovery with a retry limit of 1–2
  attempts. If recovery fails after retries, surface the conflict to the
  caller for manual resolution. This prevents infinite loops from racing
  devices while handling the common case transparently.

- **Pending operation tracking:** In-memory only (not persisted in the
  state blob). Pending ops are transient — if the app restarts
  mid-operation, the user retries manually. Keeps the state format
  simple.

- **Relay enhancement:** Deferred. Not in scope for this work. See
  "Future Work" section.

- **Test harness:** `ConversationSim` supports full dynamic group
  membership (add/remove members) from the start. Required for Phase 2
  conflict tests and avoids rewriting the harness later.

- **Proptest strategy:** Constrained generator that tracks state and
  only produces valid operation sequences. Every generated op is
  meaningful — no silent skipping of invalid operations.

## Design

The work splits into two phases with a clear dependency: phase 1 makes
problems visible, phase 2 makes them recoverable.

### Phase 1: Verifiable Transcript

Expand the `Event` struct with two new fields inside the encryption
boundary (invisible to the PDS, tamper-proof):

```rust
pub struct Event {
    pub kind: EventKind,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub payload: Vec<u8>,
    #[serde(default)]
    pub message_id: Option<Vec<u8>>,

    // --- new fields ---

    /// SHA-256 hash of the plaintext Event JSON of the previous event
    /// sent by this device (identified by device_id) in this group.
    /// Forms a per-device hash chain. `None` for the first event.
    #[serde(default)]
    pub prev_event_hash: Option<Vec<u8>>,

    /// 16-byte fingerprint derived from MLS epoch keys via
    /// `export_secret("moat-epoch-fingerprint-v1", 16)`. Recipients
    /// verify it matches their own derived value.
    #[serde(default)]
    pub epoch_fingerprint: Option<Vec<u8>>,
}
```

Both fields use `Option` with `#[serde(default)]` for backward
compatibility — old events without these fields will deserialize as
`None` and skip validation.

#### Hash Chain (`prev_event_hash`)

- On encrypt: compute `SHA-256(serialized_event_json)` of the previous
  event sent by this device in this group. Store it in the new event.
  The first event has `prev_event_hash = None`. The hash input is the
  plaintext Event struct serialized via serde (before padding/encryption).
- On decrypt: the recipient maintains a map of
  `(group_id, device_id) → last_event_hash`. After decryption,
  verify the received `prev_event_hash` matches the stored value.
  Mismatch or unexpected `None` on a non-first event = **gap or
  reordering detected**.
- The hash chain is per-device (using `MoatSession`'s 16-byte
  `device_id`), not per-DID or global, because events from different
  senders arrive in unpredictable order and a user's devices cannot
  coordinate chain state. Per-device chains let each device's sequence
  be independently verifiable.

**State requirement:** `MoatSession` needs to persist a
`HashMap<(GroupId, DeviceId), [u8; 32]>` — the last event hash per
device per group. This is stored in the v2 `export_state` blob alongside
the MLS state.

#### Epoch Fingerprint (`epoch_fingerprint`)

- On encrypt: call `MlsGroup::export_secret()` with label
  `"moat-epoch-fingerprint-v1"` and requested length 16 bytes. Include
  the 16-byte result in the event.
- On decrypt: after successful decryption, derive the same fingerprint
  from the local group state. Compare with the received value. Mismatch
  = **MLS state has diverged** (fork).
- Note: for commit events, the fingerprint should be derived from the
  epoch *after* the commit is merged, since that's the state both parties
  will agree on.

#### Return type: `DecryptOutcome`

`decrypt_event` returns `Result<DecryptOutcome, Error>` where:

```rust
pub enum DecryptOutcome {
    /// Decryption succeeded with no transcript integrity issues.
    Success(DecryptResult),
    /// Decryption succeeded but transcript integrity checks found issues.
    Warning(DecryptResult, Vec<TranscriptWarning>),
}

pub enum TranscriptWarning {
    /// prev_event_hash didn't match expected value (gap or reorder).
    HashChainMismatch {
        group_id: Vec<u8>,
        sender_device_id: Vec<u8>,
        expected: Option<[u8; 32]>,
        received: Option<Vec<u8>>,
    },
    /// epoch_fingerprint didn't match locally derived value (fork).
    EpochFingerprintMismatch {
        group_id: Vec<u8>,
        epoch: u64,
        local: Vec<u8>,
        received: Vec<u8>,
    },
    /// Duplicate event detected (replay).
    ReplayDetected {
        group_id: Vec<u8>,
        sender_device_id: Vec<u8>,
    },
}

impl DecryptOutcome {
    /// Extract the DecryptResult regardless of warning state.
    pub fn result(&self) -> &DecryptResult { ... }
    pub fn into_result(self) -> DecryptResult { ... }
    pub fn warnings(&self) -> &[TranscriptWarning] { ... }
}
```

Callers handle warnings explicitly at the function boundary:

```rust
match session.decrypt_event(group_id, ciphertext)? {
    DecryptOutcome::Success(result) => { /* use result */ }
    DecryptOutcome::Warning(result, warnings) => {
        for w in &warnings { show_warning(w); }
        /* still use result — message is not dropped */
    }
}
```

#### Relay enhancement (deferred)

*Not in scope for this work.* Future enhancement: accept an optional
`epoch` field in `event_posted`. Track `tag → last_epoch` and flag
anomalies (epoch regression, same epoch from two DIDs, gaps). Send a
`consistency_warning` notification. This is a cheap heuristic — the
relay can't verify, only clients can.

#### Files

- `crates/moat-core/src/event.rs` — new fields on `Event`,
  `TranscriptWarning` enum, `DecryptOutcome` enum
- `crates/moat-core/src/lib.rs` — exporter call in `encrypt_event`,
  fingerprint validation in `decrypt_event`, hash chain bookkeeping,
  v2 state format
- `crates/moat-core/src/error.rs` — `StateVersionMismatch` variant,
  renumbered error codes

### Phase 2: Multi-Device Commit Resilience

Phase 1 makes forks detectable. This phase makes them recoverable.

#### Current problem

`add_member()` calls `group.add_members()` then immediately
`group.merge_pending_commit()`. There is no pending commit tracking. If
device A creates a commit at epoch 2, and device B independently creates
a commit at epoch 2, whichever arrives second will be rejected by
OpenMLS as stale. The error is mapped to `Error::MergeCommit` and logged.
The operation is lost.

#### Design

1. **Track pending operations (in-memory).** When `MoatSession` creates
   a commit (add_member, remove_member, kick_user, leave_group), record
   the operation intent (e.g. "add key_package X to group Y") alongside
   the pending commit. This tracking is in-memory only — not persisted
   in the state blob. If the app restarts mid-operation, the user retries
   manually.

2. **Classify decryption errors.** In `decrypt_event`, distinguish
   between:
   - **Stale commit** — the group has already advanced past this epoch.
     This is the conflict case.
   - **Broken state** — genuinely corrupt or unrecoverable.
   - **Unknown sender** — message from a member not in our tree.

   OpenMLS's `ProcessMessageError` variants provide this information;
   moat-core currently maps them all to `Error::Decryption(string)`.

3. **Conflict recovery with retry limit.** When a stale commit is
   detected:
   - Discard the pending local commit (do not merge it).
   - Merge the incoming remote commit instead.
   - Re-apply the pending operation on the new epoch.
   - If re-apply fails (another conflict), retry up to **2 times total**.
   - If retries are exhausted, surface the conflict to the caller via
     `Error::ConflictUnresolved` so the UI can inform the user and
     request manual action.
   - On successful recovery, return `DecryptOutcome` with a warning
     indicating recovery occurred (so the UI can inform the user).

4. **Expose structured errors.** Replace the generic `Error::Decryption`
   and `Error::MergeCommit` with richer variants that callers (CLI,
   Flutter) can pattern-match on. All `ErrorCode` u32 values will be
   freely renumbered.

#### Files

- `crates/moat-core/src/lib.rs` — pending commit tracking (in-memory),
  conflict detection, recovery logic with retry limit
- `crates/moat-core/src/error.rs` — richer error variants (renumbered),
  `StaleCommit`, `StateDiverged`, `UnknownSender`, `ConflictUnresolved`
- `crates/moat-cli/src/app.rs` — handle recovery in `process_poll_results`
- `moat-flutter/rust/src/api/simple.rs` — expose recovery to FFI
- `moat-drawbridge/messages.go` — optional `commit_posted` subtype
  *(deferred)*

---

## Testing Plan

The testing strategy for this work is fundamentally different from the
existing moat-core tests. The existing tests are **single-operation
property tests** (pad/unpad roundtrip, tag determinism) and
**two-party smoke tests** (Alice encrypts, Bob decrypts). What's needed
is **multi-step, multi-party state-machine testing** that exercises the
protocol over sequences of operations.

### Test Harness: `ConversationSim`

Build a test harness in `crates/moat-core/tests/` that simulates a
conversation without network or PDS:

```rust
/// A simulated participant with their own MoatSession.
struct Participant {
    name: String,
    session: MoatSession,
    credential: MoatCredential,
    key_bundle: Vec<u8>,
}

/// A simulated conversation between participants.
/// Maintains the "network" — a queue of events per participant
/// that can be delivered, reordered, or dropped.
/// Supports dynamic membership (add/remove) from the start.
struct ConversationSim {
    participants: Vec<Participant>,
    group_id: Vec<u8>,
    /// Per-participant inbound event queue (simulates PDS).
    inboxes: Vec<VecDeque<EventRecord>>,
}

struct EventRecord {
    ciphertext: Vec<u8>,
    tag: [u8; 16],
    sender_index: usize,
}
```

This harness is the foundation for all tests below. It handles the
boilerplate of creating sessions, generating key packages, creating
groups, distributing welcomes, adding/removing members, and routing
encrypted events between participants.

### Unit Tests (Deterministic)

These are concrete scenarios written as `#[test]` functions using
`ConversationSim`. They exercise specific failure modes.

#### Hash chain tests

1. **Complete delivery.** Alice sends M1, M2, M3 to Bob. Bob verifies
   the hash chain is contiguous — each `prev_event_hash` matches the
   hash of the previous event.

2. **Withholding.** Alice sends M1, M2, M3. Deliver only M1 and M3 to
   Bob (drop M2 from the inbox). Bob should detect a gap: M3's
   `prev_event_hash` doesn't match the hash of M1.

3. **Reordering.** Alice sends M1, M2, M3. Deliver M1, M3, M2 to Bob.
   Bob should detect that M3's `prev_event_hash` doesn't match M1, and
   M2's `prev_event_hash` doesn't match M3.

4. **Replay.** Deliver M1 twice. The second delivery should be detected
   (same `prev_event_hash` seen twice for the same sender).

5. **Multi-sender interleaving.** Alice sends A1, A2. Bob sends B1, B2.
   Deliver in order A1, B1, A2, B2 to Charlie. Each sender's chain
   should verify independently, regardless of interleaving.

6. **First event.** The first event from a sender should have
   `prev_event_hash = None`. A subsequent event with `None` is a reset
   or anomaly.

7. **Backward compatibility.** An old event without `prev_event_hash`
   (deserialized as `None`) should not trigger a validation failure.

#### Epoch fingerprint tests

8. **Agreement after message.** Alice encrypts at epoch N. Bob decrypts.
   Both derive the same `epoch_fingerprint`.

9. **Agreement after commit.** Alice adds Charlie (epoch N → N+1). Bob
   processes the commit. Both derive the same fingerprint for epoch N+1.

10. **Divergence detection.** Manually construct a scenario where two
    sessions have different MLS state for the same group_id (e.g. by
    applying different commits). The epoch fingerprints should differ.

#### Commit conflict tests

11. **Sequential commits succeed.** Device A commits, device B receives
    and processes it, then device B commits. No conflict.

12. **Concurrent commits detected.** Device A and device B both create
    commits at epoch N. Deliver A's commit to B. B should detect the
    conflict with its own pending commit.

13. **Conflict recovery.** Same as 12, but after detecting the conflict,
    B discards its pending commit, merges A's commit, and retries its
    operation on epoch N+1. Verify the group converges to the same state.

14. **Three-device conflict.** Devices A, B, C all create commits at
    epoch N. Deliver them in a specific order and verify the recovery
    logic converges.

15. **Recovery retry exhaustion.** Simulate a scenario where automatic
    recovery fails after 2 retries. Verify `Error::ConflictUnresolved`
    is returned with the pending operation info.

### Property-Based Tests (Proptest)

These are `proptest` tests in `crates/moat-core/tests/` that generate
random operation sequences and verify invariants hold for all of them.

#### State machine model

Define an enum of operations that can happen in a conversation, using
a **constrained generator** that tracks conversation state and only
produces valid operations (no sending before joining, no removing
non-members, etc.):

```rust
#[derive(Debug, Clone)]
enum Op {
    /// Participant i sends a message.
    SendMessage { sender: usize },
    /// Participant i adds a new member.
    AddMember { adder: usize },
    /// Participant i removes participant j.
    RemoveMember { remover: usize, target: usize },
    /// Deliver next event from participant i's outbox to participant j.
    Deliver { from: usize, to: usize },
    /// Drop the next event in participant j's inbox (simulate withholding).
    Drop { target: usize },
    /// Reorder: swap the next two events in participant j's inbox.
    Reorder { target: usize },
}

/// Constrained strategy that tracks group membership, inbox state,
/// and only generates valid operations.
fn valid_op_sequence(max_len: usize) -> impl Strategy<Value = Vec<Op>> {
    // Stateful generation: maintains which participants are members,
    // which inboxes have events, etc. Every generated op is meaningful.
}
```

Generate random `Vec<Op>` sequences, apply them to a `ConversationSim`,
and assert invariants.

#### Property: hash chain detects all withholding

> For any operation sequence, if an event is dropped from a
> participant's inbox, the next event from the same sender triggers a
> hash chain validation failure.

```rust
proptest! {
    #[test]
    fn hash_chain_detects_withholding(
        ops in valid_op_sequence(50),
        drop_index in any::<usize>(),
    ) {
        // Apply ops to ConversationSim.
        // At drop_index, drop an event.
        // Assert that the next event from that sender fails hash chain
        // validation on the recipient.
    }
}
```

#### Property: hash chain detects all reordering

> For any operation sequence, if two consecutive events from the same
> sender are swapped in a participant's inbox, hash chain validation
> fails on the first delivered (which is actually the second sent).

#### Property: epoch fingerprint agreement

> For any sequence of operations where all events are delivered
> honestly (no drops, no reordering), all participants derive the same
> epoch fingerprint at every epoch.

```rust
proptest! {
    #[test]
    fn epoch_fingerprints_agree(
        ops in valid_honest_op_sequence(30),
    ) {
        // Apply ops. After each epoch change, assert all participants
        // who have processed the commit derive the same fingerprint.
    }
}
```

#### Property: epoch fingerprint diverges on fork

> If two participants apply different commits at the same epoch, their
> epoch fingerprints differ.

#### Property: commit conflict recovery converges

> For any sequence of concurrent commits by different devices on the
> same group, after all commits are delivered and conflicts resolved,
> all devices end up at the same MLS epoch with the same epoch
> fingerprint.

This is the most important property test. It exercises the core claim
of phase 2: that the recovery logic always converges.

```rust
proptest! {
    #[test]
    fn concurrent_commits_converge(
        num_devices in 2..5usize,
        num_concurrent_ops in 1..4usize,
    ) {
        // Create a group with num_devices.
        // All devices simultaneously create a commit (add member,
        // remove member, or self-update).
        // Deliver all commits in a random order.
        // Apply conflict recovery.
        // Assert: all devices agree on the same epoch and fingerprint.
    }
}
```

#### Property: export/import preserves hash chain state

> For any operation sequence, exporting and re-importing MoatSession
> state (v2 format) preserves the hash chain bookkeeping — subsequent
> events validate correctly.

### Integration Tests

These test the full stack from `MoatSession` through to the CLI/Flutter
event processing loop, using the `ConversationSim` harness but verifying
that the application-level code (not just moat-core) handles the new
validation results correctly.

1. **CLI processes hash chain warning.** Set up a two-party conversation
   in `App`, simulate a withholding scenario, verify the CLI surfaces a
   warning (not a silent log entry).

2. **CLI handles commit conflict.** Set up multi-device scenario, inject
   a conflicting commit, verify the CLI retries the operation.

3. **Flutter FFI roundtrip.** Verify the new `Event` fields survive the
   Rust → Dart FFI boundary via `flutter_rust_bridge`.

### Test File Layout

```
crates/moat-core/tests/
├── proptest_padding_tag.rs          # existing
├── conversation_sim.rs              # ConversationSim harness
├── test_hash_chain.rs               # deterministic hash chain tests
├── test_epoch_fingerprint.rs        # deterministic fingerprint tests
├── test_commit_conflict.rs          # deterministic conflict tests
└── proptest_transcript_integrity.rs # property-based tests
```

### What "Done" Looks Like

Phase 1 is done when:
- All 10 deterministic tests (1–10) pass.
- All 4 property tests (hash chain withholding, reordering, fingerprint
  agreement, fingerprint divergence) pass with 256+ cases each.
- The export/import property test passes.
- `decrypt_event` returns `Result<DecryptOutcome, Error>`.
- State format is v2. Loading v1 returns `Error::StateVersionMismatch`.
- Old events without the new fields still deserialize and decrypt
  correctly (backward compatibility at the event level).

Phase 2 is done when:
- All conflict tests (11–15) pass.
- The convergence property test passes with 256+ cases.
- The CLI integration test demonstrates conflict recovery.
- `Error::Decryption` has been replaced with structured variants that
  distinguish stale commits from genuine failures.
- Error codes are renumbered and Flutter FFI is updated.
- Automatic recovery retries up to 2 times, then surfaces
  `Error::ConflictUnresolved`.

## Future Work

- **Relay epoch tracking:** Accept optional `epoch` in `event_posted`,
  track `tag → last_epoch`, flag anomalies. Files:
  `moat-drawbridge/relay.go`, `moat-drawbridge/messages.go`.
