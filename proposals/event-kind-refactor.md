# Event Kind Hierarchy Proposal

## Goals

1. Encode the semantic split between **MLS control traffic**, **user messages**, and **message modifiers** directly in the protocol instead of relying on nested JSON conventions that each client must remember.
2. Provide a stable, typed API in `moat-core` so every downstream client sees strongly-typed enums (`EventKind::Control`, `EventKind::Message`, `EventKind::Modifier`) without caring how that hierarchy is serialized on the wire.
3. Keep message-rendering extensible: new user-visible content types (audio, polls, files, …) should not require every client to touch MLS/control handling code paths.

## Proposed Wire Format

`social.moat.event` keeps its schema (`{v, tag, ciphertext, createdAt}`). Inside the ciphertext we replace the single `kind` string with a namespaced discriminator:

```
kind = "<domain>.<variant>"
domain ∈ { "control", "message", "modifier" }
```

Example values:

| Domain     | Examples                                                                           |
|------------|------------------------------------------------------------------------------------|
| `control`  | `control.commit`, `control.welcome`, `control.checkpoint`                          |
| `message`  | `message.short_text`, `message.medium_text`, `message.long_text`, `message.image`  |
| `modifier` | `modifier.reaction`, `modifier.reply`, `modifier.read_receipt` (future)            |

The JSON payload can then omit the inner `type` field for message variants because the discriminator communicates both the domain and the specific subtype.

### Encoding

* `control.*` payloads stay byte blobs as today (TLS commit/welcome, etc.).
* `message.*` payloads become structured objects with the shared `message_id`, transcript fields, and (for blob-backed types) the `externalPayloadBase` fields.
* `modifier.*` payloads describe toggles that point at a `message_id` plus modifier-specific data (`emoji`, `reaction_type`, etc.).

`moat-core` implements `serde` (de)serialization so clients simply see a typed enum.

## Rust API Surface

```rust
pub enum EventKind {
    Control(ControlKind),
    Message(MessageKind),
    Modifier(ModifierKind),
}

pub enum ControlKind {
    Commit { payload: Vec<u8> },
    Welcome { payload: Vec<u8> },
    Checkpoint { payload: Vec<u8> },
}

pub enum MessageKind {
    ShortText(TextMessage),
    MediumText(TextMessage),
    LongText(LongTextMessage),
    Image(ImageMessage), // Clients will add rendering + blob fetch when ready.
    // future: Video, Audio, File, Poll, etc.
}

pub enum ModifierKind {
    Reaction(ReactionPayload),
    // future: Reply, Edit, Delete, ReadReceipt, etc.
}
```

`Event` retains `group_id`, `epoch`, transcript fields, and `message_id` (for message+modifier types). MLS control events simply omit `message_id` as today.

## Client Responsibilities

* CLI / Flutter see the new enum via FRB DTOs and switch on the top-level variant:
  * `Control(_)`: feed into MLS state machine.
  * `Message(kind)`: render bubble, fetch blobs if necessary using metadata.
  * `Modifier(kind)`: fold into existing message (toggle reaction, link reply).
* Sending helpers move into `moat-core`: e.g., `build_text_payload(text: &str) -> MessageKind`.
* Attachment upload helpers will return `(MessageKind, ExternalBlob)` so Flutter/CLI don't implement hashing logic themselves.

## Migration

1. **Lexicons**: update `social.moat.internal.paddedPayload` to document the `domain.variant` discriminator and list the enumerants.
2. **moat-core**:
   * Replace `EventKind` with the nested enum.
   * Implement serde serialization to/from the new discriminator.
   * Update `Event::message`/`Event::reaction` helpers to produce the right variants.
3. **Clients**:
   * Regenerate FRB bindings so Dart sees the nested DTOs.
   * Update CLI message rendering switches from `match event.kind` → `match event.kind { EventKind::Message(..) => … }`.
4. **Transitional compatibility**: since no users exist yet, we can wipe all staging repos once the new format lands—no dual-encoding period required.

## Open Questions

Resolved decisions:

* Modifiers reuse the `message_id` namespace so toggles/replies target the same IDs as full messages.
* Reserve extending the `domain` prefix for later (`system.*`, `admin.*`, etc.) but keep the serialization format flexible enough to add them.
* Introduce `MessageKind::Unknown { kind: String, payload: Vec<u8> }` so older clients can display “Unsupported attachment” instead of dropping the event.

## Implementation Plan

### 1. Schema & Documentation

1. Update `lexicons/social/moat/internal/paddedPayload.json`:
   * Replace `eventKind` values with the `domain.variant` strings (`control.commit`, `message.short_text`, etc.).
   * Add a short explanation of the domain prefix convention.
2. Update `lexicons/social/moat/internal/eventPayloads.json`:
   * Move message payload definitions under `message.*` entries.
   * Define `modifier.reaction` schema alongside control entries.
3. Refresh `PROTOCOL.md` to describe the new discriminator, giving concrete tables for:
   * Control events (commit/welcome/checkpoint).
   * Message events (short/medium/long text, image, future types).
   * Modifiers (reaction now, future reply/edit).

### 2. moat-core Refactor

1. Introduce the new enums in `message.rs` (or a new `event_kind.rs`):
   * `EventKind`, `ControlKind`, `MessageKind`, `ModifierKind`, `MessageKind::Unknown`.
2. Update `Event` struct:
   * Replace `kind: EventKind` usage throughout.
   * Ensure `message_id` remains optional but automatically populated for message/modifier kinds.
3. Implement custom `Serialize`/`Deserialize` for `EventKind` so:
   * `kind` is stored as `"<domain>.<variant>"`.
   * `payload` maps to the appropriate inner struct (`TextMessage`, `ReactionPayload`, raw bytes for control).
   * Unknown `message.*` variants land in `MessageKind::Unknown`.
4. Adjust constructors:
   * `Event::message_with_payload` → `EventKind::Message(...)`.
   * `Event::reaction` → `EventKind::Modifier(ModifierKind::Reaction(..))`.
   * Control helpers (`commit`, `welcome`, `checkpoint`) → `EventKind::Control(..)`.
5. Update parsing helpers (`parse_message_payload`, etc.) to return the new enums rather than ad-hoc structs.
6. Regenerate FRB bindings so Dart sees the new DTO hierarchy.

### 3. Client Updates

**moat-cli**
1. Adjust imports to use `EventKind`/`MessageKind`/`ModifierKind`.
2. Update send path to call `MessageKind` builders directly (still using `build_text_payload`).
3. Update message display logic:
   * `match event.kind` on the top-level enum.
   * For modifiers, apply reaction UI updates.
4. Ensure CLI storage (`StoredMessage`) continues to store preview strings derived from `MessageKind`.

**Flutter**
1. Regenerate FRB bindings (Rust + Dart).
2. Update `SendService` to accept the new DTO (likely `EventKindDto::Message(MessageKindDto::ShortText { .. })`).
3. Update `MessageService` and `PollingService` to branch on the new enum rather than assuming `kind == message`.
4. Ensure Dart helper (`message_payload.dart`) can still render `MessageKindDto::Unknown`.

### 4. Testing

1. Expand Rust unit tests to cover serialization round-trips for each new variant (`message.short_text`, `modifier.reaction`, etc.).
2. Add regression tests to ensure unknown `message.*` variants deserialize into `MessageKind::Unknown`.
3. Update CLI integration tests (if any) to send and receive the new event kinds.
4. (Future) Add Flutter/Dart tests for the new DTO conversions once FRB bindings are updated.

### 5. Deployment Steps

1. Once Rust + CLI + Flutter changes are merged, wipe staging repos so only the new encoding exists.
2. Regenerate any snapshots/docs or example payloads used in README/PROTOCOL.
