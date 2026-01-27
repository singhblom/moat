# Mobile Preparation

This document tracks work to prepare moat-core for mobile (iOS/Android) before starting actual mobile implementation.

---

## Goals

1. **Make moat-core FFI-ready** - APIs should be callable from any language via FFI
2. **Optimize for mobile constraints** - Memory, battery, and storage considerations
3. **Decouple storage from operations** - Let callers control persistence timing
4. **Keep all cryptography in Rust** - Security and single-implementation benefits
5. **Keep moat-cli working** - CLI remains a working reference implementation and integration test

**Note:** This preparation phase focuses on making the Rust API clean and FFI-friendly. We won't implement actual bindings yet - that comes when we start the mobile app.

---

## Moat as a Protocol/Library

Moat should be thought of as **a protocol and reusable libraries** for encrypted messaging on ATProto, not just an app. This affects our FFI strategy.

### FFI Strategy: UniFFI (Recommended)

For a library meant to be used by others, **UniFFI is the better choice** over flutter_rust_bridge:

| | UniFFI | flutter_rust_bridge |
|---|---|---|
| **Target languages** | Swift, Kotlin, Python, Ruby, C# | Dart only |
| **If someone wants a native iOS app** | Already supported | Need separate bindings |
| **If someone wants a native Android app** | Already supported | Need separate bindings |
| **For our Flutter MVP** | Use via `dart:ffi` + `ffigen` | Native support |
| **Maintenance burden** | One binding system for all | Flutter-only, others need UniFFI anyway |

**Decision:** Use UniFFI as the canonical FFI layer.

- UniFFI generates bindings for Swift, Kotlin, Python, etc.
- For Flutter: UniFFI generates C headers → use `ffigen` to create Dart bindings
- Anyone building native apps gets first-class support
- We maintain one FFI system, not two

### Flutter MVP Path

For our Flutter MVP, the path with UniFFI:

1. Add UniFFI to moat-core (proc macros or UDL file)
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

### What's Good

- **Synchronous operations** - `MoatSession` methods are already sync (no async), which simplifies FFI
- **In-memory mode exists** - `MoatSession::in_memory()` provides a foundation for decoupled storage
- **Clean API surface** - Methods take `&[u8]` and return `Vec<u8>`, which maps well to FFI
- **Pure crypto in moat-core** - No network IO, just MLS operations

### What Needs Work

| Issue | Impact | Priority |
|-------|--------|----------|
| Auto-save on every operation | Blocking I/O causes UI jank/ANRs on mobile | High |
| `Vec<u8>` everywhere | Extra allocations; fixed-size arrays preferred where possible | Medium |
| Error types use `String` | Not FFI-friendly; need error codes | Medium |
| No state export/import | Can't serialize state for native-managed storage | High |
| `RwLock` in FileStorage | Potential issues with FFI threading model | Medium |
| No group enumeration | Can't list all groups without external tracking | Low |

---

## Task List

### Phase 1: Storage Decoupling (High Priority)

The current `MoatSession` writes to disk on every operation via `FileStorage::save_to_file()`. This is problematic for mobile:

1. **Blocking I/O on main thread** - Mobile platforms are sensitive; can cause UI jank or ANRs
2. **No control over persistence timing** - Native apps often want to batch writes or persist on app suspend
3. **Platform storage expectations** - iOS/Android have specific locations (app sandbox, `getFilesDir()`)

#### Task 1.1: Add Explicit Save API

**Status:** Not Started

Add methods to `MoatSession` for explicit state management:

```rust
impl MoatSession {
    /// Create session from serialized state (for native-managed storage)
    pub fn from_state(state: &[u8]) -> Result<Self>;

    /// Export full state as bytes (for native-managed storage)
    pub fn export_state(&self) -> Result<Vec<u8>>;

    /// Explicit save - native side calls when appropriate
    pub fn save(&self) -> Result<()>;

    /// Check if there are unsaved changes
    pub fn has_pending_changes(&self) -> bool;
}
```

**Implementation notes:**
- Refactor `FileStorage` to track dirty state instead of auto-saving
- Add a `dirty` flag that operations set
- `save()` only writes if dirty
- `export_state()` serializes the in-memory HashMap

**CLI migration:**
- Update CLI to use new storage API
- This validates the API design is practical

#### Task 1.2: Remove Auto-Save

**Status:** Not Started

**Decision:** Go all-in on explicit save. No auto-save mode.

- Remove auto-save from `FileStorage` entirely
- All callers must call `save()` when they want to persist
- Simpler API, predictable behavior, one code path

The CLI will need to add `save()` calls after operations that modify state.

#### Task 1.3: Batch Operations

**Status:** Not Started

Consider adding batch operation support to reduce state churn:

```rust
impl MoatSession {
    /// Execute multiple operations, saving state once at the end
    pub fn batch<F, T>(&self, f: F) -> Result<T>
    where F: FnOnce(&mut BatchContext) -> Result<T>;
}
```

---

### Phase 2: FFI-Friendly Error Types (Medium Priority)

Current errors use `String` for details, which doesn't map cleanly to FFI.

#### Task 2.1: Add Error Codes

**Status:** Not Started

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

#### Task 2.2: Consider Result Type for FFI

**Status:** Not Started

Evaluate whether to use a C-compatible result type:

```rust
#[repr(C)]
pub struct FfiResult<T> {
    pub value: Option<T>,
    pub error_code: u32,
    pub error_message: *const c_char,
}
```

Or rely on UniFFI's error handling (likely the better choice).

---

### Phase 3: Fixed-Size Types (Medium Priority)

Where sizes are known, prefer fixed-size arrays over `Vec<u8>`.

#### Task 3.1: Audit Return Types

**Status:** Not Started

Current types that could use fixed sizes:
- `tag: [u8; 16]` - Already fixed, good
- `group_id` - Variable length (OpenMLS generates), keep as `Vec<u8>`
- Stealth keys - Already `[u8; 32]`, good
- Key packages - Variable length, keep as `Vec<u8>`

**Conclusion:** Most variable-length types are genuinely variable. Low priority.

---

### Phase 4: FFI-Ready API Design (Medium Priority)

**Note:** We won't implement actual FFI bindings in this preparation phase. The goal is to ensure the Rust API is ready for FFI when we start mobile development.

#### Task 4.1: Design FFI-Safe Public API

**Status:** Not Started

Create a dedicated `api` module that exposes only FFI-safe types:

```rust
// src/api.rs - Public API surface for FFI
//
// This module defines what gets exposed via FFI.
// All types here must be FFI-friendly.

pub use crate::{MoatSession, Error, Event, EventKind};
pub use crate::{EncryptResult, DecryptResult, WelcomeResult};
pub use crate::stealth::{generate_stealth_keypair, encrypt_for_stealth, try_decrypt_stealth};
```

Review each type for FFI compatibility:
- No lifetimes in public types
- No generic parameters that leak internal types
- Simple data types (primitives, `Vec<u8>`, structs of these)

#### Task 4.2: Handle Opaque Types

**Status:** Not Started

`MoatSession` contains `RwLock` and can't cross FFI directly. Options:

1. **Opaque pointer** - FFI sees it as an opaque handle
2. **Arc wrapper** - `Arc<MoatSession>` for safe sharing across FFI

```rust
// MoatSession becomes an opaque handle in generated bindings
// Callers get a pointer/handle, not the actual struct
```

For UniFFI, this is handled via `[Object]` in UDL or `#[uniffi::export]` on impl blocks.

#### Task 4.3: Avoid FFI Anti-Patterns

**Status:** Not Started

Review API for patterns that complicate FFI:

- **Callbacks** - Avoid. Keep request/response style.
- **Iterators** - Return `Vec` instead of iterators.
- **Lifetimes in return types** - Return owned data.
- **Complex generics** - Use concrete types in public API.
- **Async** - Keep sync. Caller can wrap in async if needed.

---

### Phase 5: Thread Safety Audit (Medium Priority)

#### Task 5.1: Review Lock Usage

**Status:** Not Started

Current `FileStorage` uses `RwLock<HashMap<...>>`. Consider:
- Is this compatible with FFI threading models?
- Should we use `parking_lot` instead of `std::sync`?
- Do we need `Send + Sync` bounds explicitly?

UniFFI requires `Send + Sync` for `[Object]` types. Verify `MoatSession` satisfies this.

#### Task 5.2: Document Thread Safety

**Status:** Not Started

Add documentation about which methods are safe to call from which threads.

---

### Phase 6: Additional APIs for Mobile (Low Priority)

#### Task 6.1: Group Enumeration

**Status:** Not Started

Mobile apps need to know which groups exist:

```rust
impl MoatSession {
    /// List all group IDs in storage
    pub fn list_groups(&self) -> Result<Vec<Vec<u8>>>;

    /// Delete a group and all its state
    pub fn delete_group(&self, group_id: &[u8]) -> Result<()>;
}
```

#### Task 6.2: State Inspection

**Status:** Not Started

For debugging and UI display:

```rust
impl MoatSession {
    /// Get epoch for a group
    pub fn get_group_epoch(&self, group_id: &[u8]) -> Result<u64>;

    /// Get member count for a group
    pub fn get_group_member_count(&self, group_id: &[u8]) -> Result<usize>;

    /// Get storage size in bytes
    pub fn storage_size(&self) -> usize;
}
```

---

## Implementation Order

Recommended order based on dependencies and impact:

1. **Task 1.1: Add Explicit Save API** - Foundation for everything else
2. **Task 1.2: Remove Auto-Save** - Single mode, simpler API
3. **Task 2.1: Add Error Codes** - Important for UniFFI error mapping
4. **Task 4.1: Design FFI-Safe Public API** - Define the API surface
5. **Task 4.2: Handle Opaque Types** - Make MoatSession FFI-compatible
6. **Task 4.3: Avoid FFI Anti-Patterns** - Clean up any problematic patterns
7. **Task 5.1: Review Lock Usage** - Ensure thread safety for FFI
8. Remaining tasks as needed

**What we're NOT doing in this phase:**
- Actually implementing UniFFI bindings
- Generating Swift/Kotlin/Dart code
- Building the Flutter app

The goal is a clean, FFI-ready Rust API. Bindings come when we start mobile development.

---

## Testing Strategy

### Unit Tests (moat-core)
- Test `export_state()` / `from_state()` round-trip
- Test explicit save doesn't write until `save()` is called
- Test error codes match expected values
- All 46+ existing tests must continue passing

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

## Open Questions

1. **State migration?** - When storage format changes, how do we handle migration? Should we version the state format?

2. **Multi-device sync?** - Not in scope for MVP, but the storage design should consider future sync needs.

3. **Background operation limits?** - iOS limits background execution. Should crypto operations be interruptible?

4. **UniFFI vs UDL?** - UniFFI supports both proc macros and UDL files. Proc macros are simpler for our case.

---

## Notes from implementation.md

The existing documentation already identified key FFI considerations:

> **Design implications for moat-core:**
> - Keep operations synchronous (no async) — much simpler FFI story ✓ Already done
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

This aligns with our Task 1.1.

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
