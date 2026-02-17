# Phase 2: DrawbridgeHint Event — Detailed Implementation Plan

Phase 1 (commit `184675b`) added ticket-based auth, new message types (`ticket_auth`, `register_ticket`, `revoke_ticket`, `request_challenge`), dual auth modes (Sender/Recipient), ticket storage, and operation authorization to `moat-drawbridge` (Go). All protocol messages and Go tests are complete.

Phase 2 adds the `DrawbridgeHint` event kind to `moat-core` so clients can exchange Drawbridge connection info (URL + ticket) inside MLS-encrypted messages.

---

## Step 1: Add `DrawbridgeHint` to `ControlKind`

**File:** `crates/moat-core/src/event.rs`

`DrawbridgeHint` is a control-plane event (not a user message or modifier). Add a new variant to `ControlKind`:

```rust
pub enum ControlKind {
    Commit,
    Welcome,
    Checkpoint,
    DrawbridgeHint, // <-- new
    Unknown(String),
}
```

### Serialization format

The existing `EventKind` serialization maps `ControlKind::Commit` → `"control.commit"`, etc. Following the same pattern, `DrawbridgeHint` serializes as `"control.drawbridge_hint"`.

Update these locations in `event.rs`:
- `impl Serialize for EventKind` — add `ControlKind::DrawbridgeHint => "control.drawbridge_hint"`
- `impl<'de> Deserialize<'de> for EventKind` — add `("control", "drawbridge_hint") => EventKind::Control(ControlKind::DrawbridgeHint)` and legacy single-token fallback `"drawbridge_hint" => EventKind::Control(ControlKind::DrawbridgeHint)`

---

## Step 2: Define `DrawbridgeHintPayload`

**File:** `crates/moat-core/src/event.rs` (or a new `drawbridge.rs` if preferred, but keeping it in `event.rs` is simpler and matches `ReactionPayload`)

The structured data travels in the `Event.payload` field as serialized JSON, identical to how `ReactionPayload` works today.

```rust
/// Payload for DrawbridgeHint events.
/// Serialized to JSON and stored in Event.payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DrawbridgeHintPayload {
    /// WebSocket URL of the Drawbridge (e.g. "wss://relay.example.com/ws")
    pub url: String,
    /// Device ID this hint applies to (16 bytes, the sender's own device)
    pub device_id: Vec<u8>,
    /// Ticket for recipient authentication (32 bytes, hex or raw)
    pub ticket: Vec<u8>,
}
```

This approach is consistent with the existing pattern — `Event.kind` identifies the event type, `Event.payload` carries the structured body.

---

## Step 3: Add `Event::drawbridge_hint()` factory method

**File:** `crates/moat-core/src/event.rs`

Follow the existing factory method pattern (`Event::commit()`, `Event::welcome()`, `Event::checkpoint()`, `Event::reaction()`):

```rust
impl Event {
    /// Create a DrawbridgeHint event.
    /// `url` — WebSocket URL of the Drawbridge server.
    /// `device_id` — sender's 16-byte device ID.
    /// `ticket` — 32-byte ticket for recipient auth.
    pub fn drawbridge_hint(
        group_id: &[u8],
        epoch: u64,
        url: &str,
        device_id: &[u8; 16],
        ticket: &[u8; 32],
    ) -> Self {
        let payload = DrawbridgeHintPayload {
            url: url.to_string(),
            device_id: device_id.to_vec(),
            ticket: ticket.to_vec(),
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize DrawbridgeHintPayload");

        Self {
            kind: EventKind::Control(ControlKind::DrawbridgeHint),
            group_id: group_id.to_vec(),
            epoch,
            payload: payload_bytes,
            message_id: None,       // control events don't have message_id
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None, // will be set during encryption
        }
    }

    /// Parse payload as a DrawbridgeHintPayload.
    /// Returns None if this isn't a DrawbridgeHint or payload is malformed.
    pub fn drawbridge_hint_payload(&self) -> Option<DrawbridgeHintPayload> {
        if self.kind != EventKind::Control(ControlKind::DrawbridgeHint) {
            return None;
        }
        serde_json::from_slice(&self.payload).ok()
    }
}
```

---

## Step 4: Add `MoatSession::generate_drawbridge_ticket()`

**File:** `crates/moat-core/src/lib.rs` (in `impl MoatSession`)

```rust
/// Generate a random 32-byte ticket for Drawbridge recipient authentication.
pub fn generate_drawbridge_ticket() -> [u8; 32] {
    let mut ticket = [0u8; 32];
    getrandom::getrandom(&mut ticket).expect("getrandom failed");
    ticket
}
```

This is a static helper (no `&self`) since it doesn't need MLS state. `getrandom` is already a dependency of moat-core.

---

## Step 5: Add `MoatSession::create_drawbridge_hint()`

**File:** `crates/moat-core/src/lib.rs` (in `impl MoatSession`)

Convenience method that uses the session's own device ID:

```rust
/// Create a DrawbridgeHint event for the current device.
pub fn create_drawbridge_hint(
    &self,
    group_id: &[u8],
    url: &str,
    ticket: &[u8; 32],
) -> Event {
    // epoch 0 — the real epoch will be stamped during encrypt_event
    Event::drawbridge_hint(group_id, 0, url, &self.device_id, ticket)
}
```

---

## Step 6: Update FFI layer — `EventKindDto`

**File:** `moat-flutter/rust/src/api/simple.rs`

Add `DrawbridgeHint` variant to `EventKindDto`:

```rust
pub enum EventKindDto {
    Message,
    Commit,
    Welcome,
    Checkpoint,
    Reaction,
    DrawbridgeHint, // <-- new
    Unknown,
}
```

Update `EventDto::from_core()` and `EventDto::into_core()` to map:
- `EventKind::Control(ControlKind::DrawbridgeHint)` ↔ `EventKindDto::DrawbridgeHint`

Add a helper on `EventDto`:

```rust
/// Parse payload as DrawbridgeHintPayload. Returns None if not a DrawbridgeHint.
pub fn drawbridge_hint_payload(&self) -> Option<DrawbridgeHintPayloadDto> {
    if !matches!(self.kind, EventKindDto::DrawbridgeHint) {
        return None;
    }
    serde_json::from_slice(&self.payload).ok()
}
```

Add a DTO struct:

```rust
pub struct DrawbridgeHintPayloadDto {
    pub url: String,
    pub device_id: Vec<u8>,
    pub ticket: Vec<u8>,
}
```

---

## Step 7: Add FFI functions for Flutter

**File:** `moat-flutter/rust/src/api/simple.rs`

```rust
/// Generate a random Drawbridge ticket (32 bytes).
pub fn generate_drawbridge_ticket() -> Vec<u8> {
    MoatSession::generate_drawbridge_ticket().to_vec()
}

/// Create a DrawbridgeHint event for the session's device.
pub fn create_drawbridge_hint(
    handle: &MoatSessionHandle,
    group_id: Vec<u8>,
    url: String,
    ticket: Vec<u8>,
) -> Result<EventDto, String> {
    let ticket_arr: [u8; 32] = ticket.try_into().map_err(|_| "ticket must be 32 bytes")?;
    let session = handle.session.lock().map_err(|e| e.to_string())?;
    let event = session.create_drawbridge_hint(&group_id, &url, &ticket_arr);
    Ok(EventDto::from_core(event))
}
```

---

## Step 8: Unit tests

### 8a. `crates/moat-core/src/event.rs` — inline tests

```rust
#[test]
fn test_drawbridge_hint_roundtrip() {
    let event = Event::drawbridge_hint(
        b"test-group",
        5,
        "wss://relay.example.com/ws",
        &[1u8; 16],
        &[2u8; 32],
    );
    let json = serde_json::to_string(&event).unwrap();
    let parsed: Event = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
    assert_eq!(
        parsed.kind,
        EventKind::Control(ControlKind::DrawbridgeHint)
    );
}

#[test]
fn test_drawbridge_hint_payload_parsing() {
    let event = Event::drawbridge_hint(
        b"g",
        0,
        "wss://example.com",
        &[0u8; 16],
        &[0xAB; 32],
    );
    let payload = event.drawbridge_hint_payload().unwrap();
    assert_eq!(payload.url, "wss://example.com");
    assert_eq!(payload.device_id, vec![0u8; 16]);
    assert_eq!(payload.ticket, vec![0xAB; 32]);
}

#[test]
fn test_drawbridge_hint_payload_on_non_hint() {
    let event = Event::commit(b"g", 0, vec![]);
    assert!(event.drawbridge_hint_payload().is_none());
}
```

### 8b. `crates/moat-core/tests/proptest_padding_tag.rs` — property test

```rust
proptest! {
    #[test]
    fn drawbridge_hint_roundtrip(
        url in "wss://[a-z]{3,10}\\.[a-z]{2,5}/ws",
        device_id in prop::array::uniform16(any::<u8>()),
        ticket in prop::array::uniform32(any::<u8>()),
    ) {
        let event = Event::drawbridge_hint(b"group", 1, &url, &device_id, &ticket);
        let json = serde_json::to_string(&event).unwrap();
        let parsed: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);

        let payload = parsed.drawbridge_hint_payload().unwrap();
        assert_eq!(payload.url, url);
        assert_eq!(payload.device_id, device_id.to_vec());
        assert_eq!(payload.ticket, ticket.to_vec());
    }
}
```

### 8c. `moat-flutter/rust/src/api/simple.rs` — FFI tests

```rust
#[test]
fn test_generate_drawbridge_ticket() {
    let t1 = generate_drawbridge_ticket();
    let t2 = generate_drawbridge_ticket();
    assert_eq!(t1.len(), 32);
    assert_eq!(t2.len(), 32);
    assert_ne!(t1, t2); // random, not equal
}

#[test]
fn test_create_drawbridge_hint_dto() {
    let handle = MoatSessionHandle::new().unwrap();
    let ticket = generate_drawbridge_ticket();
    let dto = create_drawbridge_hint(
        &handle,
        b"group-id".to_vec(),
        "wss://example.com/ws".to_string(),
        ticket.clone(),
    ).unwrap();
    assert!(matches!(dto.kind, EventKindDto::DrawbridgeHint));
    let payload = dto.drawbridge_hint_payload().unwrap();
    assert_eq!(payload.url, "wss://example.com/ws");
    assert_eq!(payload.ticket, ticket);
}

#[test]
fn test_drawbridge_hint_dto_conversion_roundtrip() {
    let event = Event::drawbridge_hint(
        b"group",
        3,
        "wss://relay.example.com",
        &[7u8; 16],
        &[9u8; 32],
    );
    let dto = EventDto::from_core(event.clone());
    let back = dto.into_core();
    assert_eq!(back.kind, event.kind);
    assert_eq!(back.group_id, event.group_id);
    assert_eq!(back.payload, event.payload);
}
```

---

## Step 9: Update PROTOCOL.md

**File:** `PROTOCOL.md`

Add a section documenting:
- The `control.drawbridge_hint` event kind
- `DrawbridgeHintPayload` schema (`url`, `device_id`, `ticket`)
- Lifecycle: sent after group creation or when Drawbridge URL/ticket changes
- One hint per (sender, device) pair per group — latest wins

---

## File changes summary

| File | Change |
|------|--------|
| `crates/moat-core/src/event.rs` | Add `ControlKind::DrawbridgeHint`, `DrawbridgeHintPayload` struct, `Event::drawbridge_hint()` factory, `Event::drawbridge_hint_payload()` accessor, serialization mappings, 3 unit tests |
| `crates/moat-core/src/lib.rs` | Add `MoatSession::generate_drawbridge_ticket()` (static), `MoatSession::create_drawbridge_hint()` |
| `crates/moat-core/tests/proptest_padding_tag.rs` | Add `drawbridge_hint_roundtrip` property test |
| `moat-flutter/rust/src/api/simple.rs` | Add `EventKindDto::DrawbridgeHint`, `DrawbridgeHintPayloadDto`, `generate_drawbridge_ticket()`, `create_drawbridge_hint()`, DTO conversion mappings, 3 FFI tests |
| `PROTOCOL.md` | Document `control.drawbridge_hint` event kind and payload schema |

## Implementation order

1. `event.rs` — `ControlKind::DrawbridgeHint` + serialization (enables everything else)
2. `event.rs` — `DrawbridgeHintPayload` + factory + accessor
3. `lib.rs` — `MoatSession` helper methods
4. `event.rs` + `proptest_padding_tag.rs` — tests (run `cargo test -p moat-core`)
5. `simple.rs` — FFI layer + tests (run `cargo test -p moat-flutter-rust` or equivalent)
6. `PROTOCOL.md` — documentation

Total: ~150 lines of production code, ~80 lines of tests.
