use flutter_rust_bridge::frb;
use moat_core::{
    self, DecryptResult, EncryptResult, Event, EventKind, MoatSession, WelcomeResult,
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

    /// Generate a new key package. Returns (key_package_bytes, key_bundle_bytes).
    pub fn generate_key_package(&self, identity: Vec<u8>) -> Result<KeyPackageResult, String> {
        let (kp, kb) = self
            .inner
            .lock()
            .unwrap()
            .generate_key_package(&identity)
            .map_err(|e| e.to_string())?;
        Ok(KeyPackageResult {
            key_package: kp,
            key_bundle: kb,
        })
    }

    /// Create a new MLS group. Returns the group ID.
    pub fn create_group(&self, identity: Vec<u8>, key_bundle: Vec<u8>) -> Result<Vec<u8>, String> {
        self.inner
            .lock()
            .unwrap()
            .create_group(&identity, &key_bundle)
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

    /// Decrypt a ciphertext for a group. Returns decrypt result.
    pub fn decrypt_event(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResultDto, String> {
        self.inner
            .lock()
            .unwrap()
            .decrypt_event(&group_id, &ciphertext)
            .map(DecryptResultDto::from)
            .map_err(|e| e.to_string())
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
}

impl From<EncryptResult> for EncryptResultDto {
    fn from(r: EncryptResult) -> Self {
        EncryptResultDto {
            new_group_state: r.new_group_state,
            tag: r.tag.to_vec(),
            ciphertext: r.ciphertext,
        }
    }
}

pub struct DecryptResultDto {
    pub new_group_state: Vec<u8>,
    pub event: EventDto,
}

impl From<DecryptResult> for DecryptResultDto {
    fn from(r: DecryptResult) -> Self {
        DecryptResultDto {
            new_group_state: r.new_group_state,
            event: EventDto::from_core(r.event),
        }
    }
}

pub enum EventKindDto {
    Message,
    Commit,
    Welcome,
    Checkpoint,
}

pub struct EventDto {
    pub kind: EventKindDto,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender_device_id: Option<String>,
    pub payload: Vec<u8>,
}

impl EventDto {
    fn into_core(self) -> Event {
        let mut event = match self.kind {
            EventKindDto::Message => Event::message(self.group_id, self.epoch, &self.payload),
            EventKindDto::Commit => Event::commit(self.group_id, self.epoch, self.payload),
            EventKindDto::Welcome => Event::welcome(self.group_id, self.epoch, self.payload),
            EventKindDto::Checkpoint => Event::checkpoint(self.group_id, self.epoch, self.payload),
        };
        if let Some(did) = self.sender_device_id {
            event = event.with_device_id(did);
        }
        event
    }

    fn from_core(e: Event) -> Self {
        EventDto {
            kind: match e.kind {
                EventKind::Message => EventKindDto::Message,
                EventKind::Commit => EventKindDto::Commit,
                EventKind::Welcome => EventKindDto::Welcome,
                EventKind::Checkpoint => EventKindDto::Checkpoint,
            },
            group_id: e.group_id,
            epoch: e.epoch,
            sender_device_id: e.sender_device_id,
            payload: e.payload,
        }
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

/// Encrypt a Welcome for a recipient's stealth address.
pub fn encrypt_for_stealth(
    recipient_scan_pubkey: Vec<u8>,
    welcome_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let pubkey: [u8; 32] = recipient_scan_pubkey
        .try_into()
        .map_err(|_| "recipient_scan_pubkey must be 32 bytes".to_string())?;
    moat_core::encrypt_for_stealth(&pubkey, &welcome_bytes).map_err(|e| e.to_string())
}

/// Try to decrypt a stealth-encrypted payload. Returns None if not for us.
#[frb(sync)]
pub fn try_decrypt_stealth(scan_privkey: Vec<u8>, payload: Vec<u8>) -> Option<Vec<u8>> {
    let privkey: [u8; 32] = scan_privkey.try_into().ok()?;
    moat_core::try_decrypt_stealth(&privkey, &payload)
}

/// Derive a 16-byte conversation tag from group ID and epoch.
#[frb(sync)]
pub fn derive_tag(group_id: Vec<u8>, epoch: u64) -> Result<Vec<u8>, String> {
    moat_core::derive_tag_from_group_id(&group_id, epoch)
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
