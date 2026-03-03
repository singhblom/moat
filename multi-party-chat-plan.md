# Multi-Party Group Chat — TDD Implementation Plan

## Overview

Add 3+ member group chat support across moat-cli (app layer) and moat-beacon (test harness). The MLS core is already multi-party ready. Red/green TDD: write failing tests first, then implement.

## Phase 1: App Layer — Multi-Member Data Model

The data model changes are foundational. Everything else builds on them.

### Step 1.1: GroupMetadata supports multiple members

**RED**: Add a unit test in `keystore.rs` that stores and loads `GroupMetadata` with multiple participant DIDs/handles. It will fail because GroupMetadata only has singular fields.

**GREEN**: Change `GroupMetadata` to:
```rust
pub struct GroupMetadata {
    pub participant_dids: Vec<String>,
    pub participant_handles: Vec<String>,
}
```
Add `#[serde(alias = "participant_did")]` migration support so existing single-value JSON still deserializes. Fix all compilation errors from the field rename.

**Files**: `crates/moat-cli/src/keystore.rs`

### Step 1.2: Conversation supports multiple members

**RED**: Compilation will fail because `Conversation.participant_did` no longer exists.

**GREEN**: Change `Conversation` to:
```rust
pub struct Conversation {
    pub id: String,
    pub name: String,
    pub participant_dids: Vec<String>,
    pub current_epoch: u64,
    pub unread: usize,
}
```

Update all usages in `app.rs`:
- `start_new_conversation`: store `vec![recipient_did]`
- `try_process_welcome_sync`: store `vec![author_did]` (improved in Phase 2)
- Duplicate check: check if recipient_did is in any conversation's `participant_dids`
- Polling DID collection: iterate all `participant_dids` per conversation
- Drawbridge hint filtering: check if DID is in `participant_dids`

Update `ConversationDto` in `http_server.rs` to expose `participant_dids: Vec<String>`.
Update `Conversation` DTO in `moat-beacon/src/client.rs` to match.

**Files**: `crates/moat-cli/src/app.rs`, `crates/moat-cli/src/http_server.rs`, `moat-beacon/src/client.rs`

### Step 1.3: Existing 2-party tests still pass

**GREEN**: Run `cargo test -p moat-cli` and `cargo test -p moat-beacon --test smoke`. All existing tests must pass. The 2-party flow is unchanged — it's just a group with `participant_dids` of length 1.

## Phase 2: App Layer — Add Member to Existing Group

### Step 2.1: `add_member_to_group` method + HTTP endpoint

**RED**: Write a unit test (or add an integration assertion) that calls `POST /conversations/:group_id/members` with `{ "handle": "carol" }`. It will 404 because the endpoint doesn't exist.

**GREEN**: Implement `App::add_member_to_group(group_id, handle)`:
1. Resolve handle → DID
2. Check DID not already in group (`mls.is_did_in_group()`)
3. Fetch stealth addresses + key package for new member
4. Call `mls.add_member(group_id, key_bundle, kp_bytes)` → Welcome + Commit
5. Encrypt Welcome for new member's stealth keys, publish with random tag
6. Encrypt Commit as a group event, publish with group-derived tag (existing members scan for it)
7. Update `GroupMetadata` to add the new DID/handle
8. Update `Conversation.participant_dids`
9. Re-populate candidate tags (new member generates new tags)

Add HTTP endpoint: `POST /conversations/:group_id/members` with `{ "handle": "..." }`.
Add `MoatCliClient::add_member(group_id, handle)` in beacon client.

**Files**: `crates/moat-cli/src/app.rs`, `crates/moat-cli/src/http_server.rs`, `moat-beacon/src/client.rs`

### Step 2.2: Welcome processing learns all group members

**RED**: After Carol joins via Welcome, her `Conversation.participant_dids` only contains the Welcome author (Alice), not Bob. Write an assertion that after joining, the conversation lists all member DIDs.

**GREEN**: In `try_process_welcome_sync`, after `mls.process_welcome()`, call `mls.get_group_dids(group_id)` to get all members. Filter out own DID. Store full list in `GroupMetadata` and `Conversation.participant_dids`.

**Files**: `crates/moat-cli/src/app.rs`

### Step 2.3: Commit processing updates member list

**RED**: When Bob processes the Commit adding Carol, his `Conversation.participant_dids` should grow to include Carol. Write assertion.

**GREEN**: In `process_matched_event` when handling `ControlKind::Commit`, after processing the commit, call `mls.get_group_dids(group_id)` and update the conversation's `participant_dids` and `GroupMetadata`. Re-populate candidate tags (they may change with the new epoch/members).

**Files**: `crates/moat-cli/src/app.rs`

### Step 2.4: Integration smoke test — 3-party conversation

**RED**: Write `moat-beacon/tests/smoke_three_party.rs`:
1. Create TestWorld with `["alice", "bob", "carol"]`
2. Login all three, sleep for key package publication
3. Bob and Carol watch Alice
4. Alice starts conversation with Bob → group_id
5. Alice adds Carol to group → `POST /conversations/:group_id/members`
6. Bob and Carol poll — both should join (Bob already in, Carol via Welcome)
7. Alice sends "hello" → all poll → Bob and Carol both see it
8. Bob sends "hey" → all poll → Alice and Carol both see it
9. Carol sends "hi" → all poll → Alice and Bob both see it

This test validates the full 3-party flow end-to-end. It should fail initially (no add_member endpoint), then pass after Phase 2 implementation.

**Files**: `moat-beacon/tests/smoke_three_party.rs`

## Phase 3: Test Harness — Generalize for N Participants

### Step 3.1: ParticipantId becomes indexed

**RED**: Change `ParticipantId` from enum to `ParticipantId(usize)` with constants:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParticipantId(pub usize);

impl ParticipantId {
    pub const ALICE: Self = Self(0);
    pub const BOB: Self = Self(1);
    pub const CAROL: Self = Self(2);
}
```

This will break all pattern matches. Fix them.

**GREEN**: Update `short_name()` to use an array lookup. Update `Display` impl. Fix all match arms in `actions.rs`, `scenarios/mod.rs`, `invariants.rs`.

**Files**: `moat-beacon/src/actions.rs`

### Step 3.2: Scenario helpers take participant slices

**RED**: Refactor helper signatures. Compilation errors everywhere.

**GREEN**: Change:
- `pick_client(id, &[&MoatCliClient]) -> &MoatCliClient` (index by ordinal)
- `execute_action(action, &[&MoatCliClient], world, &[String], push_mode, state, verbose)`
- `ensure_all_online(world, &[&MoatCliClient], &[String], push_mode)`
- `drain_events(clients: &[&MoatCliClient])`
- All invariant checkers: `check_delivery(clients: &[&MoatCliClient], state)`

The implementations become loops over the client slice instead of hardcoded alice/bob.

**Files**: `moat-beacon/src/scenarios/mod.rs`, `moat-beacon/src/invariants.rs`

### Step 3.3: Existing 2-party scenarios still work

**GREEN**: Update `two_party_chat.rs`, `two_party_push.rs`, `two_party_restart.rs`, etc. to pass `&[&alice, &bob]` slices. All existing proptests must still pass.

**Files**: `moat-beacon/src/scenarios/*.rs`, `moat-beacon/tests/proptest_*.rs`

### Step 3.4: Action generation supports N participants

**GREEN**: Parameterize `arb_participant(n: usize)` to generate `ParticipantId(0..n)`. Parameterize `action_sequence` and `action_sequence_with_offline` to accept participant count. `OfflineFoldState.online` becomes `Vec<bool>`. Export `action_sequence_3p()` and `action_sequence_3p_with_offline()` convenience functions.

**Files**: `moat-beacon/src/actions.rs`

## Phase 4: 3-Party Proptest Scenarios

### Step 4.1: `three_party_chat` scenario (polling)

**RED**: Write `moat-beacon/src/scenarios/three_party_chat.rs`:
- Prologue: Alice creates group with Bob, adds Carol, everyone polls to join
- Action loop: random sends/polls/reacts across 3 participants
- Invariants: delivery, ordering, no duplicates — all checked across 3 clients

Write `moat-beacon/tests/proptest_three_party.rs` with 8 cases.

**GREEN**: Should pass once Phase 2 + Phase 3 are complete.

**Files**: `moat-beacon/src/scenarios/three_party_chat.rs`, `moat-beacon/tests/proptest_three_party.rs`

### Step 4.2: `three_party_push` scenario (Drawbridge)

**RED**: Same as above but with Drawbridge push notifications.

**Files**: `moat-beacon/src/scenarios/three_party_push.rs`, `moat-beacon/tests/proptest_three_party_push.rs`

### Step 4.3: `three_party_restart` scenario (offline/online)

**RED**: 3-party with GoOffline/ComeOnline actions.

**Files**: `moat-beacon/src/scenarios/three_party_restart.rs`, `moat-beacon/tests/proptest_three_party_restart.rs`

### Step 4.4: Register new scenarios

**GREEN**: Add to `SCENARIOS` array in `scenarios/mod.rs`. Update `beacon list` output.

**Files**: `moat-beacon/src/scenarios/mod.rs`

## Implementation Order

```
Phase 1 (data model)     ←  Start here, small, foundational
  1.1  GroupMetadata
  1.2  Conversation + all usages
  1.3  Verify existing tests pass

Phase 2 (add-member flow) ← Core new functionality
  2.1  add_member_to_group + HTTP endpoint + client method
  2.2  Welcome learns all members
  2.3  Commit updates member list
  2.4  3-party smoke test (end-to-end validation)

Phase 3 (harness refactor) ← No new functionality, just generalization
  3.1  ParticipantId indexed
  3.2  Helpers take slices
  3.3  Existing 2-party still passes
  3.4  N-participant action generation

Phase 4 (3-party proptests) ← The payoff
  4.1  three-party-chat (polling)
  4.2  three-party-push (Drawbridge)
  4.3  three-party-restart (offline)
  4.4  Register scenarios
```

## Key Risks

1. **Commit fan-out**: When Alice adds Carol, the Commit must be published so Bob can process it. Currently `add_member` only publishes the Welcome. The Commit needs to be encrypted and published as a regular group event. This is the trickiest new code path.

2. **Tag derivation after add**: After adding Carol, the epoch changes, so tags rotate. All existing members must re-derive candidate tags. This should already happen via `populate_candidate_tags` but needs verification.

3. **Polling race**: Bob might poll and see Carol's Welcome before processing Alice's Commit. The Welcome is encrypted for Carol's stealth key so Bob can't decrypt it — he should just skip it. But the ordering of Commit processing matters.

4. **Conversation name**: With 3+ members, `name` can't just be one handle. Use "Alice, Bob, Carol" or similar. Not critical for tests but needs thought for the TUI.
