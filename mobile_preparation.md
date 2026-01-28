# Mobile Preparation

This document tracks work to prepare moat-core for mobile (iOS/Android) before starting actual mobile implementation.

---

## Goals

1. **Make moat-core FFI-ready** - APIs should be callable from any language via FFI
2. **Optimize for mobile constraints** - Memory, battery, and storage considerations
3. **Decouple storage from operations** - Let callers control persistence timing
4. **Keep all cryptography in Rust** - Security and single-implementation benefits
5. **Keep moat-cli working** - CLI remains a working reference implementation and integration test
6. **Remove unused code aggressively** - Keep the API surface and codebase as lean as possible. Dead code is a liability: it adds maintenance burden, confuses contributors, and bloats the FFI surface. If code isn't used by moat-cli or tests, remove it.

**Note:** This preparation phase focuses on making the Rust API clean and FFI-friendly. We won't implement actual bindings yet - that comes when we start the mobile app.

---

## Moat as a Protocol/Library

Moat should be thought of as **a protocol and reusable libraries** for encrypted messaging on ATProto, not just an app. This affects our FFI strategy.

### FFI Strategy: UniFFI

**Decision:** Use UniFFI as the canonical FFI layer with **proc macros** (not UDL files).

For a library meant to be used by others, **UniFFI is the better choice** over flutter_rust_bridge:

| | UniFFI | flutter_rust_bridge |
|---|---|---|
| **Target languages** | Swift, Kotlin, Python, Ruby, C# | Dart only |
| **If someone wants a native iOS app** | Already supported | Need separate bindings |
| **If someone wants a native Android app** | Already supported | Need separate bindings |
| **For our Flutter MVP** | Use via `dart:ffi` + `ffigen` | Native support |
| **Maintenance burden** | One binding system for all | Flutter-only, others need UniFFI anyway |

- UniFFI generates bindings for Swift, Kotlin, Python, etc.
- For Flutter: UniFFI generates C headers -> use `ffigen` to create Dart bindings
- Anyone building native apps gets first-class support
- We maintain one FFI system, not two

### Flutter MVP Path

For our Flutter MVP, the path with UniFFI:

1. Add UniFFI proc macros to moat-core
2. Generate C header via `uniffi-bindgen-cs` or similar
3. Use Dart's `ffigen` to generate Dart bindings from C header
4. Write thin Dart wrapper for ergonomics

This is slightly more work than flutter_rust_bridge for the MVP, but:
- We get Swift/Kotlin bindings "for free"
- Others can use moat-core in native apps without us doing extra work
- No duplicate FFI systems to maintain

### Implications for moat-core

Regardless of which FFI tool we eventually use, the Rust API requirements are similar:

1. **Synchronous operations** - Already done. Simpler FFI story.

2. **FFI-friendly errors** - Add error codes. UniFFI maps these cleanly.

3. **`Vec<u8>` is fine** - Both UniFFI and FRB handle byte arrays well.

4. **Opaque handles for stateful types** - `MoatSession` will be an opaque pointer.

5. **No callbacks** - Keep the API request/response style. Callbacks complicate FFI.

---

## Design Principle: CLI as Reference Implementation

**The moat-cli app must continue working throughout all refactoring.**

The CLI is now a working end-to-end encrypted messenger. This makes it invaluable:

1. **Integration test** - If the CLI works, the API is correct
2. **API validation** - If an API change is awkward for CLI, it's probably awkward for mobile too
3. **Regression detection** - Run `cargo test` + manual CLI testing after every change
4. **Documentation by example** - CLI code shows how to use moat-core correctly
5. **Same code path as mobile** - The CLI must use the exact same moat-core APIs a mobile app would. No special CLI-only constructors or convenience methods in moat-core. If the CLI needs file I/O, it does that itself — moat-core only provides `MoatSession::new()`, `from_state()`, and `export_state()`. This way, the CLI is a true integration test for the mobile API surface.

### Breaking Changes Are OK

**Now is the time for breaking changes.** Before we have multiple apps depending on moat-core, we should:

- Redesign APIs that are awkward or inefficient
- Remove cruft and simplify interfaces
- Make the API mobile-friendly from the start

The constraint is: **get CLI working again after each major refactor**. The CLI is our validation that the new API is usable and correct.

Workflow for breaking changes:
1. Make the breaking change in moat-core
2. Update moat-cli to use the new API
3. Run tests + manual CLI verification
4. Commit once everything works

### Testing Workflow

For every moat-core change:

```bash
# 1. Run unit tests
cargo test -p moat-core

# 2. Run all tests
cargo test

# 3. Manual CLI test (two terminals)
cargo run -p moat-cli -- -s /tmp/moat-alice
cargo run -p moat-cli -- -s /tmp/moat-bob
# Verify: login, create conversation, exchange messages
```

---

## Current State Analysis

### What's Already Done

- **Synchronous operations** - `MoatSession` methods are already sync (no async), which simplifies FFI
- **Pure in-memory model** - `MoatSession` is already purely in-memory with `new()` and `from_state()`. No file I/O in moat-core.
- **Caller-managed persistence** - CLI already handles persistence via `export_state()`/`from_state()`, saving after every mutating operation
- **Clean API surface** - Methods take `&[u8]` and return `Vec<u8>`, which maps well to FFI
- **Pure crypto in moat-core** - No network IO, just MLS operations

### What Needs Work

| Issue | Impact | Priority |
|-------|--------|----------|
| `std::sync::RwLock` in MlsStorage | Poisoning issues at FFI boundary; switch to `parking_lot` | Medium |

---

## Decisions Log

Decisions made during specification review:

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Storage model | Pure in-memory only | Remove any remaining FileStorage. Callers use `export_state()`/`from_state()` for all persistence. |
| CLI save frequency | After every mutation | Safest against crashes; matches current behavior but explicit. |
| Batch API | Dropped | Not needed with pure in-memory model. Callers control persistence timing naturally. |
| UniFFI dependency | Not yet | Make types FFI-compatible now, add UniFFI as dependency when we start mobile. |
| State versioning | Magic bytes + version | `b"MOAT"` + `u16` version prefix (6 bytes) on exported state. Cheap insurance for future migration. |
| api.rs role | Future binding home | Dedicated module for public API surface; will also contain UniFFI annotations later. |
| RwLock implementation | `parking_lot` | Better FFI story (no poisoning), faster, smaller. |
| Cancellation/interruptibility | Not needed | MLS operations are fast (sub-millisecond). Defer entirely. |
| Phase 6 (group enum, state inspection) | Deferred to mobile | Skip in preparation phase. Add when mobile actually needs them. |
| Multi-device | Add device_id field | Include device_id in exported state as minimal future-proofing. Don't implement sync logic. |
| UniFFI style | Proc macros | Simpler than UDL files for our case. Confirmed decision. |

---

## Task List

### Phase 1: Storage Decoupling (High Priority)

**Status: Already Complete**

The codebase already implements the target design:
- `MoatSession::new()` creates a fresh in-memory session
- `MoatSession::from_state(state: &[u8])` restores from bytes
- `MoatSession::export_state()` serializes state to bytes
- CLI handles all file I/O via `save_mls_state()` after every mutation
- No auto-save, no `FileStorage` with disk I/O in moat-core

~~Task 1.1: Add Explicit Save API~~ - Already implemented
~~Task 1.2: Remove Auto-Save~~ - Already implemented (never had auto-save in current design)
~~Task 1.3: Batch Operations~~ - Dropped (unnecessary with pure in-memory model)

---

### Phase 2: State Format Versioning (Medium Priority)

**Status: Complete**

#### Task 2.1: Add Version Header to Exported State

**Status:** Complete

`export_state()` now writes a 22-byte header before the raw MLS state:

```
[M][O][A][T][version:u16 LE][device_id:16 bytes][...raw MLS state...]
```

`from_state()` validates the magic bytes and version, rejecting invalid or unsupported formats. See `lib.rs:90-97` for constants and `lib.rs:155-172` for parsing.

#### Task 2.2: Add Device ID to State

**Status:** Complete

`MoatSession` now holds a `device_id: [u8; 16]` field:
- Generated randomly via `rand::thread_rng()` on `MoatSession::new()`
- Serialized in the state header between version and MLS data
- Accessible via `session.device_id() -> &[u8; 16]`
- Persists through `export_state()`/`from_state()` round-trips

6 new tests added in `tests.rs:368-439`: header validation, invalid magic rejection, unsupported version rejection, too-short rejection, device ID persistence, device ID uniqueness.

---

### Phase 3: FFI-Friendly Error Types (High Priority)

**Status: Complete**

#### Task 3.1: Add Error Codes

**Status:** Complete

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    KeyGeneration = 1,
    KeyPackageGeneration = 2,
    KeyPackageValidation = 3,
    GroupCreation = 4,
    GroupLoad = 5,
    Storage = 6,
    Serialization = 7,
    Deserialization = 8,
    InvalidMessageType = 9,
    AddMember = 10,
    MergeCommit = 11,
    ProcessWelcome = 12,
    Encryption = 13,
    Decryption = 14,
    ProcessCommit = 15,
    TagDerivation = 16,
    StealthEncryption = 17,
}

impl Error {
    pub fn code(&self) -> ErrorCode;
    pub fn message(&self) -> &str;
}
```

No UniFFI dependency yet — just ensure the types are compatible with future `#[derive(uniffi::Error)]`.

`ErrorCode` is `#[repr(u32)]` with stable numeric values (1–17). `Error` exposes `code() -> ErrorCode` and `message() -> &str` accessors. 3 new tests verify error code values, accessor correctness, and real failure codes.

#### Task 3.2: Result Type for FFI

**Status:** Complete (no custom type needed)

**Decision:** Rely on UniFFI's error handling when we add bindings. No custom `FfiResult<T>` type. Just ensure `Error` has `code()` and `message()` accessors.

---

### Phase 4: FFI-Ready API Design (Medium Priority)

**Status: Complete**

#### Task 4.1: Create Dedicated api.rs Module

**Status:** Complete

Created `src/api.rs` as the explicit public API surface. All internal modules (`error`, `event`, `padding`, `stealth`, `storage`, `tag`) are `pub(crate)`. Only types re-exported through `api.rs` and `lib.rs` are accessible to downstream crates.

Public API surface:
```rust
// Types
MoatSession, Error, ErrorCode, Event, EventKind,
EncryptResult, DecryptResult, WelcomeResult, KeyBundle,
Bucket, CIPHERSUITE

// Functions
generate_stealth_keypair, encrypt_for_stealth, try_decrypt_stealth,
derive_tag_from_group_id, pad_to_bucket, unpad
```

Internal-only types (not FFI-exposed):
- `MoatProvider`, `MlsStorage`, `MlsStorageError` — OpenMLS storage internals

**Removed dead code:**
- `MoatCore` struct (~150 lines) — stateless duplicate of `MoatSession` that created throwaway providers per call. Only used by tests (rewritten to use `MoatSession`).
- `GroupState` struct — only used by `MoatCore` to serialize minimal state.
- `derive_conversation_tag` — unused wrapper; all callers use `derive_tag_from_group_id` directly.

#### Task 4.2: Handle Opaque Types

**Status:** Complete

- `load_group()` leaked `MlsGroup` (an OpenMLS internal type) through the public API. Replaced with `get_group_epoch(&self, group_id: &[u8]) -> Result<Option<u64>>`. `load_group()` is now `pub(crate)`.
- CLI updated to use `get_group_epoch()` at all 4 call sites.
- `MoatSession` is `Send + Sync` verification deferred to Phase 5.

#### Task 4.3: Avoid FFI Anti-Patterns

**Status:** Complete (verified)

- No callbacks — request/response style throughout
- No iterators in public API — returns `Vec`
- No lifetimes in return types — returns owned data
- No complex generics in public API
- No async in moat-core
- CLI uses only the public API surface (validated: no `pub(crate)` APIs used by moat-cli)

---

### Phase 5: Thread Safety (Medium Priority)

#### Task 5.1: Switch to parking_lot::RwLock

**Status:** Complete

Replaced `std::sync::RwLock` with `parking_lot::RwLock` in `MlsStorage`:

- No poisoning (cleaner FFI boundary — panics don't leave locks in broken state)
- Better performance on contended workloads
- Smaller memory footprint
- Simpler API (`.read()` / `.write()` return guards directly, no `Result`)

All `.unwrap()` calls on lock acquisition removed since `parking_lot` returns guards directly.

#### Task 5.2: Verify Send + Sync

**Status:** Complete

Added compile-time assertions in `lib.rs` that `MoatSession` is `Send + Sync`:

```rust
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() { assert_send_sync::<MoatSession>(); }
};
```

If `MoatSession` ever loses `Send` or `Sync` (e.g., by adding a non-Send field), the build will fail immediately.

#### Task 5.3: Document Thread Safety

**Status:** Complete

Added thread safety documentation to both `MlsStorage` and `MoatSession`:

- `MoatSession` is `Send + Sync`
- Read-only methods (`export_state`, `get_group_epoch`, `has_pending_changes`, `device_id`) are safe to call concurrently
- Mutating MLS operations (`encrypt_event`, `decrypt_event`, `add_member`) are not atomic at the session level — callers should ensure exclusive access (e.g., via `Mutex` on mobile side)

---

### Phase 6: Additional APIs for Mobile (Deferred)

**Deferred to when mobile development starts.** Not in scope for this preparation phase.

Will include when needed:
- `list_groups()` - enumerate all group IDs
- `delete_group()` - remove a group and its state
- `get_group_member_count()` - member count
- `storage_size()` - total storage size in bytes

Note: `get_group_epoch()` was added in Phase 4 as it was needed to replace the leaky `load_group()` API.

---

## Implementation Order

Recommended order based on dependencies and impact:

1. ~~**Task 2.1: Add Version Header**~~ - Done
2. ~~**Task 2.2: Add Device ID**~~ - Done
3. ~~**Task 3.1: Add Error Codes**~~ - Done
4. ~~**Task 4.1: Create api.rs Module**~~ - Done
5. ~~**Task 4.2: Handle Opaque Types**~~ - Done
6. ~~**Task 4.3: Avoid FFI Anti-Patterns**~~ - Done
7. **Task 5.1: Switch to parking_lot** - Independent, can be done early
8. **Task 5.2: Verify Send + Sync** - Quick check after parking_lot switch
9. **Task 5.3: Document Thread Safety** - Final documentation pass

**What we're NOT doing in this phase:**
- Actually implementing UniFFI bindings (no `uniffi` dependency yet)
- Generating Swift/Kotlin/Dart code
- Building the Flutter app
- Phase 6 APIs (group enumeration, state inspection)

The goal is a clean, FFI-ready Rust API. Bindings come when we start mobile development.

---

## Testing Strategy

### Unit Tests (moat-core)
- Test versioned `export_state()` / `from_state()` round-trip
- Test rejection of invalid/unsupported version headers
- Test error codes match expected values
- Test device_id persists through export/import
- All 66 existing tests must continue passing

### CLI Integration Tests
- **After every moat-core change**, verify CLI still works:
  ```bash
  cargo test
  cargo run -p moat-cli -- -s /tmp/moat-alice  # Terminal 1
  cargo run -p moat-cli -- -s /tmp/moat-bob    # Terminal 2
  ```
- Test: login, watch for invites, create conversation, exchange messages
- This catches regressions that unit tests might miss

### FFI Integration Tests (Future - when we start mobile)
- Build sample app that links moat-core via UniFFI
- Verify no ANRs during crypto operations
- Test state persistence across app restarts

### Performance Tests
- Measure encryption/decryption latency
- Profile memory usage during operations
- Test with large number of groups

---

## Resolved Questions

1. **State migration?** -> **Resolved:** Add `b"MOAT"` + u16 version prefix to exported state. Migration logic added per-version as needed.

2. **Multi-device sync?** -> **Resolved:** Not in scope for MVP. Add a 16-byte device_id to state as minimal future-proofing. No sync logic.

3. **Background operation limits?** -> **Resolved:** Not needed. MLS operations are sub-millisecond. No cancellation/interruptibility support.

4. **UniFFI proc macros vs UDL?** -> **Resolved:** Proc macros. Simpler for our case.

---

## Notes from implementation.md

The existing documentation already identified key FFI considerations:

> **Design implications for moat-core:**
> - Keep operations synchronous (no async) — much simpler FFI story -> Already done
> - Prefer fixed-size arrays (`[u8; 32]`) over `Vec<u8>` where possible
> - Error types should be FFI-friendly (consider error codes + message accessors)
> - Storage should be controllable by the native side (see FFI Storage Considerations)

The recommended refactoring from implementation.md:

```rust
impl MoatSession {
    /// Operations modify in-memory state only (no disk I/O)
    pub fn encrypt_event(&self, ...) -> Result<EncryptResult> { ... }

    /// Explicit persistence — native side calls when appropriate
    pub fn save(&self) -> Result<()> { ... }

    /// Export full state as bytes (for native-managed storage)
    pub fn export_state(&self) -> Result<Vec<u8>> { ... }

    /// Import state from bytes
    pub fn import_state(&mut self, data: &[u8]) -> Result<()> { ... }
}
```

This is already implemented (using `from_state()` instead of `import_state()`).

---

## Mobile App Structure (Future)

When creating mobile apps:

### Flutter MVP (our first mobile app)

```
moat-flutter/
├── lib/
│   ├── main.dart
│   ├── src/
│   │   ├── ffi/                # Generated by ffigen from UniFFI headers
│   │   │   └── moat_core.dart
│   │   ├── services/
│   │   │   ├── moat_service.dart    # Wrapper around FFI
│   │   │   └── atproto_service.dart # Native Dart ATProto client
│   │   └── ui/
│   └── ...
└── pubspec.yaml
```

### Native iOS/Android (available to others)

UniFFI generates:
- `MoatCore.swift` for iOS
- `MoatCore.kt` for Android

Third parties can use these directly in native apps without Flutter.

### ATProto Client: Per-Platform

Per implementation.md:

> **moat-atproto**: Will likely be re-implemented natively per platform. ATProto is pure HTTP/REST, and each platform has superior networking libraries.

- **Flutter**: Dart ATProto client using `http` or `dio`
- **iOS**: Swift ATProto client using URLSession
- **Android**: Kotlin ATProto client using OkHttp

Only moat-core (MLS cryptography) needs to be in Rust and shared via FFI.
