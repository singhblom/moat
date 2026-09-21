---
name: check-tests
description: Review tests for whether they actually earn their place, and rank them so the weak half can be cut. Use after writing or generating tests, before committing a diff that adds them, when a suite has grown noisy or slow, when asked to "check the tests", "review these tests", "are these tests any good", "which of these should I keep", or when deciding what to cover in a new area.
---

# Checking tests

Assume half the tests in front of you are not worth keeping. That is the
working prior, and it holds most strongly for tests that were generated in a
batch — a model writing tests for a module will produce a handful that would
catch a real regression and an equal number that restate the implementation,
cover a branch that cannot fail, or duplicate a neighbour with different
literals.

So the job is never "do these tests pass" or "is coverage up". It is
**ranking**: sort what is there, name the top half, and say plainly what the
bottom half is and why it should go. A review that keeps everything has not
been done.

## Rank by one question

*If this test failed tomorrow, would it point at a bug — and would that bug
otherwise have shipped?*

Both halves matter. A test that fails only when someone deliberately changes
the behavior it pins is not catching a bug, it is objecting to a decision. A
test covering a path that three other tests already cover is catching a bug
that would not have shipped anyway.

**Top half — keep, and say why:**

- Pins a **boundary or error path**: empty input, the padding bucket at
  exactly 256 bytes, the epoch immediately after a commit, a missing blob, a
  duplicate rkey, a peer that went away mid-handshake.
- Covers an invariant that **spans components** and no single function owns —
  transcript integrity, tag derivation agreeing across two sessions, state
  surviving a restart.
- Encodes a **bug that actually happened**. These are the highest-value tests
  in any suite; link the commit or issue in the test name or a one-line
  comment.
- Would **fail today** if you reverted the change it accompanies. Check this
  literally when a test's value is unclear: break the code and see if it goes
  red. A test that stays green against a deliberately broken implementation is
  dead weight, no matter how it reads.
- Guards something **expensive to get wrong** — anything where a silent
  failure means plaintext leaks, a message is lost, or two devices diverge.

**Bottom half — cut, or say what would make it worth keeping:**

- **Restates the implementation.** Asserts that a function called the helper it
  obviously calls, or that a struct field holds the value just assigned to it.
  It breaks on refactors and never on bugs.
- **Trivially true.** Asserts output is non-empty, that a `Vec` has the length
  you pushed, that a constructor does not panic — with no branch in the code
  that could make it otherwise.
- **Duplicate with different literals.** Three tests differing only in the
  message string are one test. Collapse them, or turn them into a table/
  parametrized case if the inputs genuinely differ in kind.
- **Weak property.** A proptest asserting only that the output is non-empty or
  that serialization does not error passes trivially for a broken
  implementation. Tighten it to a real invariant — roundtrip, idempotence,
  ordering independence, length-class preservation — or drop it.
- **Mock choreography.** Asserts a sequence of calls on mocks rather than an
  observable outcome. It tests that the code is written the way it is written.
- **Flaky or order-dependent.** Worse than absent: it teaches people to re-run
  rather than investigate. Fix the isolation or delete it; never leave it
  ignored with a TODO.

## What the survivors should look like

Once the cut is made, hold the rest to these:

**One reason to fail.** You should know what broke from the test name alone,
without opening the file. Name the behavior (`decrypt_rejects_tag_from_wrong_epoch`)
not the method (`test_decrypt`). Several unrelated assertion clusters in one
test just say "something around here".

**Behavior at a stable boundary.** The test should survive a rewrite of the
internals. Assert on what a caller can observe — return values, persisted
state, emitted events. If renaming a private helper reddens twenty tests, those
tests were coupled to structure.

**Deterministic and isolated.** No shared global state, no real clock, no
ordering dependence, no network. `tempfile::tempdir()` for Rust file I/O,
`Directory.systemTemp.createTempSync()` for Dart storage tests. If it passes
alone and fails under parallelism, it is not done.

**Readable arrange step.** Most unusable tests are unusable because fifty lines
of fixture scaffolding hide what is actually being varied. Defaults plus the
two fields that matter. When setup is genuinely irreducible, that is a signal
about the seam, not about the test.

**Failure output that tells the story.** `assert_eq!` on two 32-byte arrays is
far worse than the same assertion naming which tag mismatched. Failure output
gets read far more often than test bodies do.

## In this codebase

- **Property tests earn their keep where invariants are crisp** — blob crypto
  roundtrips, padding never leaking a length class, tag derivation, transcript
  integrity. The failure mode to watch is the weak property above.
- **Some correctness cannot be unit-tested honestly.** MLS forbids
  self-decryption, so encrypt/decrypt needs two sessions — a small integration
  test in a unit test's clothes. That is the right call. Faking the boundary to
  keep it "unit" tests a protocol that does not exist.
- **Know where the real coverage lives.** Delivery, ordering, restart and push
  behavior belong in `moat-beacon`, against the HTTP API. A unit test that
  reimplements a slice of that in mocks is a bottom-half test even when it
  looks thorough — and per the architecture rules, logic reachable only outside
  the HTTP surface is untested by Beacon regardless of how many unit tests
  surround it.
- **Dart app and server must not diverge.** A test asserting behavior that
  holds only in the Flutter app or only in the headless server is pinning a
  bug. Shared behavior belongs in `moat-dart/common`, tested once.

## Reporting

Say the ranking out loud. Do not hand back a uniformly approving list.

1. **Keep** — each test with a one-line reason it earns its place.
2. **Cut** — each test with the specific failure above it matches. Be
   concrete: "duplicate of the case two tests up, only the message string
   differs", not "low value".
3. **Missing** — the boundary or error path nothing covers. This is usually
   the most useful part of the review; a batch of generated tests almost
   always over-covers the happy path and skips the case that actually breaks.

When reviewing tests written in the same session, apply this to your own work
first and without softening. If the cut list comes back empty, the ranking was
not real.
