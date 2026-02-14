use flutter_rust_bridge::frb;
use moat_core::{
    self, EncryptResult, Event, EventKind, MoatCredential, MoatSession,
    SenderInfo, WelcomeResult,
};
use std::sync::Mutex;

// --- Error handling ---

/// Moat error with code and message, suitable for Dart exceptions.
pub struct MoatError {
    pub code: u32,
    pub message: String,
}

impl From<moat_core::Error> for MoatError {
    fn from(e: moat_core::Error) -> Self {
        MoatError {
            code: e.code() as u32,
            message: e.message().to_string(),
        }
    }
}

// --- Session wrapper ---

/// Opaque handle to a MoatSession, thread-safe via Mutex.
pub struct MoatSessionHandle {
    inner: Mutex<MoatSession>,
}

impl MoatSessionHandle {
    /// Create a new session with empty state.
    #[frb(sync)]
    pub fn new_session() -> MoatSessionHandle {
        MoatSessionHandle {
            inner: Mutex::new(MoatSession::new()),
        }
    }

    /// Restore a session from previously exported state bytes.
    pub fn from_state(state: Vec<u8>) -> Result<MoatSessionHandle, String> {
        MoatSession::from_state(&state)
            .map(|s| MoatSessionHandle {
                inner: Mutex::new(s),
            })
            .map_err(|e| e.to_string())
    }

    /// Export the full session state as bytes for persistence.
    pub fn export_state(&self) -> Result<Vec<u8>, String> {
        self.inner
            .lock()
            .unwrap()
            .export_state()
            .map_err(|e| e.to_string())
    }

    /// Get the 16-byte device ID.
    #[frb(sync)]
    pub fn device_id(&self) -> Vec<u8> {
        self.inner.lock().unwrap().device_id().to_vec()
    }

    /// Check if there are unsaved changes.
    #[frb(sync)]
    pub fn has_pending_changes(&self) -> bool {
        self.inner.lock().unwrap().has_pending_changes()
    }

    /// Generate a new key package with DID and device name.
    /// Returns (key_package_bytes, key_bundle_bytes).
    pub fn generate_key_package(
        &self,
        did: String,
        device_name: String,
    ) -> Result<KeyPackageResult, String> {
        let device_id = *self.inner.lock().unwrap().device_id();
        let credential = MoatCredential::new(&did, &device_name, device_id);
        let (kp, kb) = self
            .inner
            .lock()
            .unwrap()
            .generate_key_package(&credential)
            .map_err(|e| e.to_string())?;
        Ok(KeyPackageResult {
            key_package: kp,
            key_bundle: kb,
        })
    }

    /// Create a new MLS group with DID and device name. Returns the group ID.
    pub fn create_group(
        &self,
        did: String,
        device_name: String,
        key_bundle: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let device_id = *self.inner.lock().unwrap().device_id();
        let credential = MoatCredential::new(&did, &device_name, device_id);
        self.inner
            .lock()
            .unwrap()
            .create_group(&credential, &key_bundle)
            .map_err(|e| e.to_string())
    }

    /// Get the current epoch of a group. Returns null if group doesn't exist.
    pub fn get_group_epoch(&self, group_id: Vec<u8>) -> Result<Option<u64>, String> {
        self.inner
            .lock()
            .unwrap()
            .get_group_epoch(&group_id)
            .map_err(|e| e.to_string())
    }

    /// Get the DIDs of all members in a group (deduplicated).
    pub fn get_group_dids(&self, group_id: Vec<u8>) -> Result<Vec<String>, String> {
        self.inner
            .lock()
            .unwrap()
            .get_group_dids(&group_id)
            .map_err(|e| e.to_string())
    }

    /// Generate all candidate tags for every member in a group.
    ///
    /// Returns a flat list of candidate tags for recipient scanning.
    #[frb(sync)]
    pub fn populate_candidate_tags(&self, group_id: Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
        self.inner
            .lock()
            .unwrap()
            .populate_candidate_tags(&group_id)
            .map(|tags| tags.into_iter().map(|t| t.to_vec()).collect())
            .map_err(|e| e.to_string())
    }

    /// Mark a tag as seen, advancing the seen counter for that sender.
    ///
    /// Call this after matching a tag from `populate_candidate_tags`.
    /// Returns true if the tag was found and the counter was updated.
    #[frb(sync)]
    pub fn mark_tag_seen(&self, tag: Vec<u8>) -> bool {
        if tag.len() != 16 {
            return false;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&tag);
        self.inner.lock().unwrap().mark_tag_seen(&arr)
    }

    /// Add a member to a group. Returns welcome result.
    pub fn add_member(
        &self,
        group_id: Vec<u8>,
        key_bundle: Vec<u8>,
        new_member_key_package: Vec<u8>,
    ) -> Result<WelcomeResultDto, String> {
        self.inner
            .lock()
            .unwrap()
            .add_member(&group_id, &key_bundle, &new_member_key_package)
            .map(WelcomeResultDto::from)
            .map_err(|e| e.to_string())
    }

    /// Process a welcome message to join a group. Returns the group ID.
    pub fn process_welcome(&self, welcome_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
        self.inner
            .lock()
            .unwrap()
            .process_welcome(&welcome_bytes)
            .map_err(|e| e.to_string())
    }

    /// Encrypt an event for a group. Returns encrypt result.
    pub fn encrypt_event(
        &self,
        group_id: Vec<u8>,
        key_bundle: Vec<u8>,
        event: EventDto,
    ) -> Result<EncryptResultDto, String> {
        let core_event = event.into_core();
        self.inner
            .lock()
            .unwrap()
            .encrypt_event(&group_id, &key_bundle, &core_event)
            .map(EncryptResultDto::from)
            .map_err(|e| e.to_string())
    }

    /// Decrypt a ciphertext for a group. Returns decrypt result with any warnings.
    pub fn decrypt_event(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResultDto, String> {
        let outcome = self
            .inner
            .lock()
            .unwrap()
            .decrypt_event(&group_id, &ciphertext)
            .map_err(|e| e.to_string())?;

        let warnings: Vec<String> = outcome.warnings().iter().map(|w| w.to_string()).collect();
        let result = outcome.into_result();

        Ok(DecryptResultDto {
            new_group_state: result.new_group_state,
            event: EventDto::from_core(result.event),
            sender: result.sender.map(SenderInfoDto::from),
            warnings,
        })
    }
}

// --- DTO types for FRB ---

pub struct KeyPackageResult {
    pub key_package: Vec<u8>,
    pub key_bundle: Vec<u8>,
}

pub struct WelcomeResultDto {
    pub new_group_state: Vec<u8>,
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub group_id: Vec<u8>,
}

impl From<WelcomeResult> for WelcomeResultDto {
    fn from(r: WelcomeResult) -> Self {
        WelcomeResultDto {
            new_group_state: r.new_group_state,
            welcome: r.welcome,
            commit: r.commit,
            group_id: r.group_id,
        }
    }
}

pub struct EncryptResultDto {
    pub new_group_state: Vec<u8>,
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// The message_id assigned to the event (16 bytes for Message/Reaction, None otherwise)
    pub message_id: Option<Vec<u8>>,
}

impl From<EncryptResult> for EncryptResultDto {
    fn from(r: EncryptResult) -> Self {
        EncryptResultDto {
            new_group_state: r.new_group_state,
            tag: r.tag.to_vec(),
            ciphertext: r.ciphertext,
            message_id: r.message_id,
        }
    }
}

pub struct DecryptResultDto {
    pub new_group_state: Vec<u8>,
    pub event: EventDto,
    pub sender: Option<SenderInfoDto>,
    /// Transcript integrity warnings (empty if none).
    pub warnings: Vec<String>,
}

/// Information about the sender of a message, extracted from MLS credentials.
pub struct SenderInfoDto {
    /// The sender's DID (e.g., "did:plc:abc123")
    pub did: String,
    /// The sender's device name (format: "did:plc:xxx/Device Name")
    pub device_name: String,
}

impl From<SenderInfo> for SenderInfoDto {
    fn from(s: SenderInfo) -> Self {
        SenderInfoDto {
            did: s.did,
            device_name: s.device_name,
        }
    }
}

pub enum EventKindDto {
    Message,
    Commit,
    Welcome,
    Checkpoint,
    Reaction,
}

pub struct EventDto {
    pub kind: EventKindDto,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub payload: Vec<u8>,
    /// Unique message identifier (16 random bytes). Present for Message and Reaction events.
    pub message_id: Option<Vec<u8>>,
}

/// Reaction payload extracted from a Reaction event.
pub struct ReactionPayloadDto {
    pub emoji: String,
    pub target_message_id: Vec<u8>,
}

impl EventDto {
    fn into_core(self) -> Event {
        match self.kind {
            EventKindDto::Message => Event::message(self.group_id, self.epoch, &self.payload),
            EventKindDto::Commit => Event::commit(self.group_id, self.epoch, self.payload),
            EventKindDto::Welcome => Event::welcome(self.group_id, self.epoch, self.payload),
            EventKindDto::Checkpoint => Event::checkpoint(self.group_id, self.epoch, self.payload),
            EventKindDto::Reaction => {
                // payload is already a JSON-serialized ReactionPayload from the core Event
                // We need to extract emoji and target_message_id to call Event::reaction
                // Use the core's from_bytes to reconstruct, but payload is the reaction JSON
                // Parse via core's Event::from_bytes won't work since payload is the inner JSON.
                // Instead, reconstruct a core Event directly with the raw payload.
                let mut event = Event::commit(self.group_id, self.epoch, self.payload);
                event.kind = EventKind::Reaction;
                event.message_id = self.message_id;
                event
            }
        }
    }

    fn from_core(e: Event) -> Self {
        EventDto {
            kind: match e.kind {
                EventKind::Message => EventKindDto::Message,
                EventKind::Commit => EventKindDto::Commit,
                EventKind::Welcome => EventKindDto::Welcome,
                EventKind::Checkpoint => EventKindDto::Checkpoint,
                EventKind::Reaction => EventKindDto::Reaction,
            },
            message_id: e.message_id,
            group_id: e.group_id,
            epoch: e.epoch,
            payload: e.payload,
        }
    }

    /// Parse the payload as a reaction. Only valid when kind is Reaction.
    /// Returns None if this is not a Reaction event or if the payload is malformed.
    #[frb(sync)]
    pub fn reaction_payload(&self) -> Option<ReactionPayloadDto> {
        if !matches!(self.kind, EventKindDto::Reaction) {
            return None;
        }
        // Reconstruct a temporary core Event to use its reaction_payload() parser
        let temp_event = Event {
            kind: EventKind::Reaction,
            group_id: vec![],
            epoch: 0,
            payload: self.payload.clone(),
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        };
        let rp = temp_event.reaction_payload()?;
        Some(ReactionPayloadDto {
            emoji: rp.emoji,
            target_message_id: rp.target_message_id,
        })
    }
}

// --- Free functions ---

/// Generate a stealth keypair. Returns (private_key, public_key) each 32 bytes.
#[frb(sync)]
pub fn generate_stealth_keypair() -> StealthKeypair {
    let (privkey, pubkey) = moat_core::generate_stealth_keypair();
    StealthKeypair {
        private_key: privkey.to_vec(),
        public_key: pubkey.to_vec(),
    }
}

pub struct StealthKeypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Encrypt a Welcome for one or more recipients' stealth addresses (multi-device support).
/// Each recipient pubkey must be 32 bytes.
pub fn encrypt_for_stealth(
    recipient_scan_pubkeys: Vec<Vec<u8>>,
    welcome_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let pubkeys: Vec<[u8; 32]> = recipient_scan_pubkeys
        .into_iter()
        .map(|pk| {
            pk.try_into()
                .map_err(|_| "each recipient_scan_pubkey must be 32 bytes".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    moat_core::encrypt_for_stealth(&pubkeys, &welcome_bytes).map_err(|e| e.to_string())
}

/// Try to decrypt a stealth-encrypted payload. Returns None if not for us.
#[frb(sync)]
pub fn try_decrypt_stealth(scan_privkey: Vec<u8>, payload: Vec<u8>) -> Option<Vec<u8>> {
    let privkey: [u8; 32] = scan_privkey.try_into().ok()?;
    moat_core::try_decrypt_stealth(&privkey, &payload)
}

/// Generate candidate tags for recipient scanning.
///
/// Returns a list of (tag, counter) pairs for the given sender in the group.
#[frb(sync)]
pub fn generate_candidate_tags(
    handle: &MoatSessionHandle,
    group_id: Vec<u8>,
    sender_did: String,
    sender_device_id: Vec<u8>,
    from_counter: u64,
    count: u64,
) -> Result<Vec<Vec<u8>>, String> {
    let session = handle.inner.lock().unwrap();
    let device_id: [u8; 16] = sender_device_id
        .try_into()
        .map_err(|_| "device_id must be 16 bytes".to_string())?;
    session
        .generate_candidate_tags(&group_id, &sender_did, &device_id, from_counter, count)
        .map(|tags| tags.into_iter().map(|(tag, _)| tag.to_vec()).collect())
        .map_err(|e| e.to_string())
}

/// Derive the next unique tag for publishing an event (increments counter).
#[frb(sync)]
pub fn derive_next_tag(
    handle: &MoatSessionHandle,
    group_id: Vec<u8>,
    key_bundle: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let session = handle.inner.lock().unwrap();
    session
        .derive_next_tag(&group_id, &key_bundle)
        .map(|t| t.to_vec())
        .map_err(|e| e.to_string())
}

/// Pad plaintext to bucket size (256, 1024, or 4096 bytes).
#[frb(sync)]
pub fn pad_to_bucket(plaintext: Vec<u8>) -> Vec<u8> {
    moat_core::pad_to_bucket(&plaintext)
}

/// Remove padding and extract original plaintext.
#[frb(sync)]
pub fn unpad(padded: Vec<u8>) -> Vec<u8> {
    moat_core::unpad(&padded)
}

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_create() {
        let handle = MoatSessionHandle::new_session();
        let device_id = handle.device_id();
        assert_eq!(device_id.len(), 16);
    }

    #[test]
    fn test_session_device_id_is_stable() {
        let handle = MoatSessionHandle::new_session();
        let id1 = handle.device_id();
        let id2 = handle.device_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_session_device_id_unique() {
        let h1 = MoatSessionHandle::new_session();
        let h2 = MoatSessionHandle::new_session();
        assert_ne!(h1.device_id(), h2.device_id());
    }

    #[test]
    fn test_session_export_import_roundtrip() {
        let handle = MoatSessionHandle::new_session();
        let device_id = handle.device_id();

        let state = handle.export_state().expect("export should succeed");
        assert!(!state.is_empty());

        let restored =
            MoatSessionHandle::from_state(state).expect("import should succeed");
        assert_eq!(restored.device_id(), device_id);
    }

    #[test]
    fn test_new_session_has_no_pending_changes() {
        let handle = MoatSessionHandle::new_session();
        assert!(!handle.has_pending_changes());
    }

    #[test]
    fn test_generate_key_package() {
        let handle = MoatSessionHandle::new_session();
        let result = handle
            .generate_key_package("did:plc:test123".into(), "My Phone".into())
            .expect("key package generation should succeed");

        assert!(!result.key_package.is_empty());
        assert!(!result.key_bundle.is_empty());
    }

    #[test]
    fn test_create_group() {
        let handle = MoatSessionHandle::new_session();
        let kp = handle
            .generate_key_package("did:plc:alice".into(), "Desktop".into())
            .unwrap();

        let group_id = handle
            .create_group("did:plc:alice".into(), "Desktop".into(), kp.key_bundle)
            .expect("group creation should succeed");

        assert!(!group_id.is_empty());
    }

    #[test]
    fn test_group_epoch_starts_at_zero() {
        let handle = MoatSessionHandle::new_session();
        let kp = handle
            .generate_key_package("did:plc:alice".into(), "Desktop".into())
            .unwrap();
        let group_id = handle
            .create_group("did:plc:alice".into(), "Desktop".into(), kp.key_bundle)
            .unwrap();

        let epoch = handle
            .get_group_epoch(group_id)
            .expect("should get epoch")
            .expect("group should exist");

        assert!(epoch <= 1);
    }

    #[test]
    fn test_group_epoch_nonexistent_group() {
        let handle = MoatSessionHandle::new_session();
        let result = handle.get_group_epoch(vec![0xFF; 16]);
        match result {
            Ok(epoch) => assert!(epoch.is_none()),
            Err(_) => {} // also acceptable
        }
    }

    #[test]
    fn test_get_group_dids() {
        let handle = MoatSessionHandle::new_session();
        let kp = handle
            .generate_key_package("did:plc:alice".into(), "Desktop".into())
            .unwrap();
        let group_id = handle
            .create_group("did:plc:alice".into(), "Desktop".into(), kp.key_bundle)
            .unwrap();

        let dids = handle.get_group_dids(group_id).expect("should get DIDs");
        assert_eq!(dids, vec!["did:plc:alice"]);
    }

    #[test]
    fn test_encrypt_decrypt_message_roundtrip() {
        // Alice creates group and adds Bob so Bob can decrypt Alice's messages
        let alice = MoatSessionHandle::new_session();
        let alice_kp = alice
            .generate_key_package("did:plc:alice".into(), "Desktop".into())
            .unwrap();
        let group_id = alice
            .create_group(
                "did:plc:alice".into(),
                "Desktop".into(),
                alice_kp.key_bundle.clone(),
            )
            .unwrap();

        let bob = MoatSessionHandle::new_session();
        let bob_kp = bob
            .generate_key_package("did:plc:bob".into(), "Phone".into())
            .unwrap();

        let welcome = alice
            .add_member(
                group_id.clone(),
                alice_kp.key_bundle.clone(),
                bob_kp.key_package,
            )
            .unwrap();

        bob.process_welcome(welcome.welcome).unwrap();

        // Alice encrypts a message
        let event = EventDto {
            kind: EventKindDto::Message,
            group_id: group_id.clone(),
            epoch: 0,
            payload: b"Hello, world!".to_vec(),
            message_id: None,
        };
        let encrypted = alice
            .encrypt_event(group_id.clone(), alice_kp.key_bundle.clone(), event)
            .expect("encryption should succeed");

        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.tag.len(), 16);

        // Bob decrypts Alice's message (MLS doesn't allow self-decryption)
        let decrypted = bob
            .decrypt_event(group_id, encrypted.ciphertext)
            .expect("decryption should succeed");

        assert_eq!(decrypted.event.payload, b"Hello, world!");
        assert!(matches!(decrypted.event.kind, EventKindDto::Message));
    }

    #[test]
    fn test_two_party_encrypt_decrypt() {
        let alice = MoatSessionHandle::new_session();
        let alice_kp = alice
            .generate_key_package("did:plc:alice".into(), "Desktop".into())
            .unwrap();
        let group_id = alice
            .create_group(
                "did:plc:alice".into(),
                "Desktop".into(),
                alice_kp.key_bundle.clone(),
            )
            .unwrap();

        let bob = MoatSessionHandle::new_session();
        let bob_kp = bob
            .generate_key_package("did:plc:bob".into(), "Phone".into())
            .unwrap();

        let welcome = alice
            .add_member(
                group_id.clone(),
                alice_kp.key_bundle.clone(),
                bob_kp.key_package,
            )
            .expect("add member should succeed");

        assert!(!welcome.welcome.is_empty());
        assert!(!welcome.commit.is_empty());

        let bob_group_id = bob
            .process_welcome(welcome.welcome)
            .expect("process welcome should succeed");

        assert_eq!(bob_group_id, group_id);
    }

    #[test]
    fn test_stealth_keypair_generation() {
        let kp = generate_stealth_keypair();
        assert_eq!(kp.private_key.len(), 32);
        assert_eq!(kp.public_key.len(), 32);
    }

    #[test]
    fn test_stealth_keypair_unique() {
        let kp1 = generate_stealth_keypair();
        let kp2 = generate_stealth_keypair();
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn test_stealth_encrypt_decrypt_roundtrip() {
        let kp = generate_stealth_keypair();
        let message = b"Welcome message bytes".to_vec();

        let encrypted =
            encrypt_for_stealth(vec![kp.public_key.clone()], message.clone())
                .expect("stealth encryption should succeed");

        let decrypted = try_decrypt_stealth(kp.private_key, encrypted)
            .expect("should decrypt successfully");

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_stealth_wrong_key_fails() {
        let sender_kp = generate_stealth_keypair();
        let wrong_kp = generate_stealth_keypair();
        let message = b"Secret".to_vec();

        let encrypted =
            encrypt_for_stealth(vec![sender_kp.public_key], message).unwrap();

        let result = try_decrypt_stealth(wrong_kp.private_key, encrypted);
        assert!(result.is_none());
    }

    #[test]
    fn test_generate_candidate_tags() {
        let handle = MoatSessionHandle::new_session();
        let device_id = handle.inner.lock().unwrap().device_id().to_vec();
        let cred = MoatCredential::new("did:plc:alice", "Phone", {
            let mut id = [0u8; 16];
            id.copy_from_slice(&device_id);
            id
        });
        let (_, key_bundle) = handle.inner.lock().unwrap().generate_key_package(&cred).unwrap();
        let group_id = handle.inner.lock().unwrap().create_group(&cred, &key_bundle).unwrap();

        let tags = generate_candidate_tags(
            &handle,
            group_id.clone(),
            "did:plc:alice".to_string(),
            device_id,
            0,
            5,
        ).unwrap();
        assert_eq!(tags.len(), 5);
        for tag in &tags {
            assert_eq!(tag.len(), 16);
        }
        // All tags should be unique
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j]);
            }
        }
    }

    #[test]
    fn test_derive_next_tag() {
        let handle = MoatSessionHandle::new_session();
        let device_id = *handle.inner.lock().unwrap().device_id();
        let cred = MoatCredential::new("did:plc:alice", "Phone", device_id);
        let (_, key_bundle) = handle.inner.lock().unwrap().generate_key_package(&cred).unwrap();
        let group_id = handle.inner.lock().unwrap().create_group(&cred, &key_bundle).unwrap();

        let tag1 = derive_next_tag(&handle, group_id.clone(), key_bundle.to_vec()).unwrap();
        assert_eq!(tag1.len(), 16);

        let tag2 = derive_next_tag(&handle, group_id, key_bundle.to_vec()).unwrap();
        assert_ne!(tag1, tag2); // Counter increments, so tags differ
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let plaintext = b"Hello, world!".to_vec();
        let padded = pad_to_bucket(plaintext.clone());

        assert_eq!(padded.len(), 256);
        let unpadded = unpad(padded);
        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_pad_bucket_sizes() {
        let small = pad_to_bucket(vec![0x42; 100]);
        assert_eq!(small.len(), 256);

        let medium = pad_to_bucket(vec![0x42; 500]);
        assert_eq!(medium.len(), 1024);

        let large = pad_to_bucket(vec![0x42; 2000]);
        assert_eq!(large.len(), 4096);
    }

    #[test]
    fn test_pad_empty() {
        let padded = pad_to_bucket(vec![]);
        assert_eq!(padded.len(), 256);
        let unpadded = unpad(padded);
        assert!(unpadded.is_empty());
    }

    #[test]
    fn test_event_dto_conversions() {
        for kind in [
            EventKindDto::Message,
            EventKindDto::Commit,
            EventKindDto::Welcome,
            EventKindDto::Checkpoint,
        ] {
            let dto = EventDto {
                kind,
                group_id: vec![1, 2, 3],
                epoch: 42,
                payload: b"test".to_vec(),
                message_id: None,
            };
            let core_event = dto.into_core();
            let restored = EventDto::from_core(core_event);
            assert_eq!(restored.group_id, vec![1, 2, 3]);
            assert_eq!(restored.epoch, 42);
        }
    }

    #[test]
    fn test_reaction_dto_roundtrip() {
        let target_id = vec![0xAB; 16];
        // Create a reaction via core and convert to DTO
        let core_reaction = Event::reaction(vec![1, 2, 3], 5, &target_id, "👍");
        assert_eq!(core_reaction.kind, EventKind::Reaction);

        let rp = core_reaction.reaction_payload().unwrap();
        assert_eq!(rp.emoji, "👍");
        assert_eq!(rp.target_message_id, target_id);

        // Convert to DTO and back
        let dto = EventDto::from_core(core_reaction);
        assert!(matches!(dto.kind, EventKindDto::Reaction));
        assert!(dto.message_id.is_some());

        let dto_rp = dto.reaction_payload().unwrap();
        assert_eq!(dto_rp.emoji, "👍");
        assert_eq!(dto_rp.target_message_id, target_id);

        // Convert back to core
        let restored_core = dto.into_core();
        assert_eq!(restored_core.kind, EventKind::Reaction);
        let restored_rp = restored_core.reaction_payload().unwrap();
        assert_eq!(restored_rp.emoji, "👍");
        assert_eq!(restored_rp.target_message_id, target_id);
    }
}
