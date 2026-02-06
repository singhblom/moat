# Testing Plan

## Current State

| Crate | Tests | Coverage |
|-------|-------|----------|
| **moat-core** | 73 | Excellent — padding, tags, stealth, credentials, multi-device, 2-party messaging, state serialization |
| **moat-atproto** | 3 | Minimal — only JSON serialization for record types |
| **moat-cli** | 5 | Keystore persistence only (identity key, credentials, stealth key, groups, pagination) |
| **moat-flutter** | 1 | Single integration test ("app starts") |
| **moat-flutter/rust** | 0 | Zero tests for the FFI wrapper |

## What moat-cli Tests That moat-flutter Doesn't

Both apps implement equivalent functionality but moat-cli at least tests its **KeyStore** persistence layer. moat-flutter has **zero unit tests** for any of its equivalent services:

- **Credential storage** — CLI tests roundtrips; Flutter's `SecureStorage` is untested
- **Stealth key storage** — CLI tests roundtrips; Flutter's equivalent untested
- **Conversation metadata storage** — CLI tests listing groups; Flutter's `ConversationStorage` (native + web) untested
- **Pagination state** — CLI tests rkey tracking; Flutter's `last_rkey` tracking in `SecureStorage` untested

## Shared Gaps (Missing in Both)

These are tested in **moat-core** but the application-level integration of them is untested in both CLI and Flutter:

1. **End-to-end message flow** — create group → add member → encrypt → publish → fetch → decrypt → display. Core tests the crypto, but neither app tests the orchestration.
2. **Welcome/invite processing** — stealth decrypt → process welcome → join group → register tags. Core tests stealth + welcome separately, but the combined flow is untested.
3. **Multi-device sync** — polling own DID for welcomes from other devices, adding devices to existing groups.
4. **Tag map management** — registering tags after epoch changes, looking up groups by tag during polling.
5. **MLS state persistence across operations** — export → mutate → re-export cycle in the app context.
6. **Error recovery** — corrupted MLS state, network failures mid-operation, expired sessions.
7. **ATProto client** — login, session refresh, event fetching/publishing (0 tests in moat-atproto for the client itself).

## Where Property-Based Testing Would Help

Property-based testing (e.g., `proptest` for Rust, `fast_check` for Dart) would be valuable for:

1. **Padding roundtrips** — `forall msg: pad(msg) |> unpad == msg` and `len(pad(msg)) in {256, 1024, 4096}`. Currently tested with 3 fixed sizes + empty; proptest would cover arbitrary message lengths including boundary values (255, 256, 257, 1023, 1024, etc.).

2. **Tag derivation properties** — `forall (group, epoch1, epoch2) where epoch1 != epoch2: tag(group, epoch1) != tag(group, epoch2)`. Currently tested with a few examples.

3. **Event serialization** — `forall event: deserialize(serialize(event)) == event`. Currently only tests a few fixed events; proptest would generate arbitrary event kinds, payloads, and tags.

4. **Stealth encryption** — `forall (msg, keys): decrypt(encrypt(msg, pubkeys), privkey) == msg`. The unlinkability property (`encrypt(m, k) != encrypt(m, k)`) is also a natural proptest.

5. **Credential parsing** — `forall (did, device_name): parse(serialize(MoatCredential(did, device_name))) == Ok(...)`. Would catch edge cases in DID/device name formats.

6. **MLS state export/import** — `forall operations: import(export(state)) preserves all group memberships and epoch counters`. This is hard to test exhaustively by hand.

7. **JSON storage roundtrips** (Flutter) — `forall conversation: fromJson(toJson(conversation)) == conversation`. Same for messages. Would catch serialization bugs with special characters, empty strings, unicode, etc.

## Recommendations

### Quick wins (high value, low effort)

- Add model serialization tests in Flutter (`Message`, `Conversation`, `BlueskyProfile` — `fromJson`/`toJson` roundtrips)
- Add `ConversationStorage` and `MessageStorage` tests in Flutter (mirror CLI's keystore tests)
- Add Rust FFI wrapper tests in `moat-flutter/rust/` (session create → export → import roundtrip)
- Add `proptest` to moat-core for padding and tag derivation

### Medium effort

- Integration tests for the invite flow (both apps): create group → stealth encrypt → publish → poll → decrypt → join
- ATProto client tests with mock HTTP responses
- `SecureStorage` roundtrip tests in Flutter

### Larger effort

- Full end-to-end integration tests with two simulated users
- Error injection / recovery tests
- Property-based tests for MLS state export/import
