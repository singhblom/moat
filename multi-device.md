# Multi-device Support

## Background

In moat-cli the user generates a key pair and uses that to authenticate with the MLS session. In the moat-flutter app we also want to access conversations.

Initially considered reading all conversation data from participants' PDSes and decrypting it to fill up history on a new client. However, MLS does not allow you to decrypt your own data — messages you send are encrypted to other group members, not to yourself.

## Decision: Each Device is a Separate MLS Member

Each device gets its own MLS key and is added to groups as a separate member (but with the same ATProto DID in the credential). This approach:

- **Enables real-time sync:** When you send from Device A, Device B receives it as a normal group message (since Device B is a separate MLS member)
- **Simplifies key management:** No need to sync private key material between devices
- **Leverages existing MLS semantics:** Standard Add/Remove operations work naturally

## Device Identity

- **Naming:** User chooses a friendly name for each device during setup (e.g., "My iPhone", "Work Laptop")
- **Storage:** Device name is embedded in the MLS key package credential (no separate device registry record needed)
- **Discovery:** To see a user's devices, fetch all key packages for their DID and extract names from credentials

## UI Presentation

- **Collapsed identity:** In conversation view, all devices for a user show as one identity (e.g., "Alice" not "Alice-phone, Alice-laptop")
- **Message Info:** Each message tracks which device sent it; viewable via a "Message Info" feature
- **New device alert:** UI always highlights when a user's new device appears in a conversation for the first time

## Adding a New Device

### Flow

1. User sets up new device with their ATProto credentials
2. New device generates MLS keys and publishes a key package to PDS
3. Existing group members detect the new key package (when polling/fetching events)
4. An existing member adds the new device to the group
5. New device receives Welcome messages and joins the group(s)

### Race Condition Handling

Multiple members might try to add the new device simultaneously. Resolution:

- **Soft coordination:** Before adding, wait a random delay (0-30 seconds) to reduce collision probability
- **MLS-native conflict resolution:** If commits conflict, first one wins (by PDS record ordering); others detect the device was already added and abandon their commit

### Conversation History

- New devices only see messages from after they joined — no history sync
- **UI indicator (on demand):** When user scrolls to top of available messages, show "Messages before [date] are on your other devices"
- History sync and backup/recovery are deferred for later implementation

## Removing Devices

### Rules

- **Users can remove their own devices** — remove any device you own, one at a time
- **Removing your last device = leaving the group** — requires a new invite to return
- **Others can kick you from the group** — removes all your devices; requires re-invite to return
- **Others cannot remove just one of your devices** — kick is all-or-nothing

### Notifications

- When a device is removed, other participants see an event: "Alice removed device: Work Laptop"

### Permissions

- For now, any group member can kick any other member
- Admin/permission model deferred for later

## Verification and Trust

- Trust is based on ATProto authentication — if a device authenticated via the user's DID, it's trusted
- No safety number verification between devices (may add later)

## moat-cli and moat-flutter Relationship

- Completely independent — each is its own device with separate keys
- Even if both are on the same machine, they are treated as two separate devices
- No shared data between them

---

## Implementation Status

### Phase 1: moat-core Changes ✅ COMPLETE

1. **Add device name to MLS credentials** ✅
   - `MoatCredential` struct with `did` and `device_name` fields (`credential.rs`)
   - Key package generation embeds device name via credential
   - `MoatCredential::try_from_bytes()` for parsing credentials

2. **Track device metadata in conversations** ✅
   - `SenderInfo` struct with `did`, `device_name`, and `leaf_index` (`event.rs`)
   - `Event::with_device_id()` for attaching sender device to messages
   - Decrypted messages include sender credential info

3. **Detect new key packages for existing DIDs** ✅
   - `get_group_members()` returns all members with credentials
   - `get_group_dids()` returns unique DIDs in a group
   - `is_did_in_group()` checks if a DID is already a member

4. **Add "add device" operation** ✅
   - `add_device()` method adds a key package for an existing member's DID
   - Validates that the DID is already in the group before adding
   - Random delay not yet implemented (deferred to CLI layer)

5. **Add device removal operations** ✅
   - `remove_member()` - remove a specific member by leaf index
   - `kick_user()` - remove all devices for a DID from group
   - `leave_group()` - remove own device from group

### Phase 2: moat-cli Changes ✅ COMPLETE

1. **Device setup flow** ✅
   - `get_or_create_device_name()` auto-generates device name from hostname
   - Device name stored in `~/.moat/keys/device_name`
   - Device name included when generating key packages via `MoatCredential`

2. **Auto-add new devices** ✅
   - `poll_for_new_devices()` runs every 30s, checks key packages for group members
   - Random delay (0-5s) before adding to reduce race conditions
   - Publishes commit to group and welcome via stealth encryption

3. **UI: Collapsed identity display** ✅
   - `DisplayMessage` now tracks `sender_did` and `sender_device` separately
   - Messages displayed by user name (collapsed by DID)
   - Device info available via Message Info feature

4. **UI: New device alerts** ✅
   - `DeviceAlert` struct tracks new device join events
   - Alert popup shown when new device joins a conversation
   - Dismissable with any key press

5. **UI: Message Info feature** ✅
   - Press 'i' in Messages view to show message info popup
   - Shows sender DID, device name, timestamp, and content preview
   - Press 'i' or Esc to close

6. **Device management commands** ✅
   - `moat devices --conversation <id>` - List all devices in a conversation
   - `moat devices --conversation list` - List all conversations
   - `moat remove-device --conversation <id> --leaf-index <n>` - Remove specific device
   - `moat kick --conversation <id> --did <did>` - Kick user (all devices)
   - `moat leave --conversation <id>` - Leave a conversation

7. **Handle epoch conflicts gracefully** ✅
   - Retry with state refresh when encryption fails due to stale epoch
   - Random delay + re-check pattern for adding devices reduces conflicts
   - Silent skip of decryption failures (may be from different epochs)

### Phase 3: moat-flutter Implementation 🟡 PARTIAL

1. **Device setup screen** ✅ COMPLETE
   - Device name field on login screen (with default "Flutter App")
   - Device name stored in secure storage
   - Device name embedded in key package via `MoatCredential`
   - FFI updated to accept DID + device_name for `generateKeyPackage` and `createGroup`

2. **Waiting for group invites** ❌ NOT STARTED
   - New devices won't have conversations until existing devices add them to groups

3. **Conversation list and messages** ✅
   - Basic conversation list UI implemented
   - Login screen implemented
   - Key package and stealth address publishing implemented

4. **New device notifications** ❌ NOT STARTED

5. **Message Info view** ❌ NOT STARTED

6. **History boundary indicator** ❌ NOT STARTED

7. **Device management UI** ❌ NOT STARTED

### Phase 4: Testing 🟡 PARTIAL

1. **Multi-device scenarios** ✅
   - Unit tests for multi-device same DID (`test_multi_device_same_did`)
   - Unit tests for add device (`test_add_device_for_existing_did`)
   - Manual testing possible with `-s` flag: `cargo run -p moat-cli -- -s /tmp/moat-alice`

2. **Race condition testing** ❌ NOT STARTED

3. **Device removal testing** ✅
   - Unit tests for remove member (`test_remove_member`)
   - Unit tests for kick user (`test_kick_user`)
   - Unit tests for add device fails for non-member (`test_add_device_fails_for_non_member`)

4. **Edge cases** ❌ NOT STARTED

---

## Next Steps

Priority order for completing multi-device support:

1. ~~**moat-cli: Auto-add new devices**~~ ✅ DONE - Poll for new key packages and add them
2. ~~**moat-cli: Collapsed identity display**~~ ✅ DONE - Group messages by DID
3. ~~**moat-flutter: Device name setup**~~ ✅ DONE - Device name on login, embedded in key package
4. ~~**moat-cli: Device management commands**~~ ✅ DONE - CLI interface for remove/kick operations
5. ~~**Race condition handling**~~ ✅ DONE - Random delay + conflict detection (included in auto-add)
