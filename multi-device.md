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

## Implementation Plan

### Phase 1: moat-core Changes

1. **Add device name to MLS credentials**
   - Extend credential structure to include device name field
   - Update key package generation to embed device name
   - Add helper to extract device name from credentials

2. **Track device metadata in conversations**
   - Store which device (credential) sent each message
   - Add device info to decrypted message output

3. **Detect new key packages for existing DIDs**
   - When fetching key packages, identify if a DID has multiple packages
   - Return list of key packages per DID (not just one)

4. **Add "add device" operation**
   - Create MLS Add commit for a new key package belonging to an existing group member's DID
   - Include random delay (0-30s) before committing

5. **Add device removal operations**
   - Self-remove: remove own device from group
   - Kick user: remove all devices for a DID from group
   - Detect "last device removed" = user left group

### Phase 2: moat-cli Changes

1. **Device setup flow**
   - Prompt for device name during first-time setup
   - Store device name locally in KeyStore
   - Include device name when generating key packages

2. **Auto-add new devices**
   - When polling events, check for new key packages from group members' DIDs
   - If new key package found for existing member, trigger add-device flow with random delay

3. **UI: Collapsed identity display**
   - Group messages by DID, not by credential/device
   - Show single name per user in conversation view

4. **UI: New device alerts**
   - Track known devices per DID
   - Show alert when a new device appears: "Alice added a new device: Work Laptop"

5. **UI: Message Info feature**
   - Add keybinding to show message details
   - Display which device sent the message

6. **Device management commands**
   - List own devices
   - Remove own device from a conversation
   - Kick user (remove all their devices) from conversation

7. **Handle epoch conflicts gracefully**
   - Detect when a commit fails due to epoch mismatch
   - Re-fetch events and retry or abandon if already done

### Phase 3: moat-flutter Implementation

1. **Device setup screen**
   - Screen to enter device name on first launch
   - ATProto login flow (reuse credentials if stored, or prompt)
   - Generate MLS keys and publish key package

2. **Waiting for group invites**
   - New device has no groups initially
   - Poll for Welcome messages
   - Display "Waiting to be added to conversations..." state

3. **Conversation list and messages**
   - Fetch and display conversations once Welcome received
   - Show messages from join point forward
   - Collapsed identity view (same as CLI)

4. **New device notifications**
   - Show banner/toast when a group member adds a new device

5. **Message Info view**
   - Tap on message to see details including sending device

6. **History boundary indicator**
   - When scrolling to top, show "Messages before [date] are on your other devices"

7. **Device management UI**
   - Settings screen showing own devices
   - Remove device option
   - Kick user option in conversation settings

### Phase 4: Testing

1. **Multi-device scenarios**
   - Two CLI instances for same user joining same conversation
   - CLI + Flutter for same user
   - Messages sent from one device appear on the other

2. **Race condition testing**
   - Multiple members online when new device publishes key package
   - Verify only one Add commit succeeds

3. **Device removal testing**
   - Remove own device, verify can't decrypt new messages
   - Kick user, verify all their devices removed
   - Remove last device, verify requires re-invite

4. **Edge cases**
   - Device added while offline, syncs when back online
   - Conflicting commits during high activity
