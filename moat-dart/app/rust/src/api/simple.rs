use flutter_rust_bridge::frb;
use moat_core::{
    self, ControlKind, EncryptResult, Event, EventKind, GroupKind, KeyPackageInput, MoatCredential,
    MoatSession, ModifierKind, OwnEventInput, ReactionPayload as CoreReactionPayload, RingCommand,
    SenderInfo, StepEnv, SyncMessage, TickInputs, WelcomeResult,
};
use moat_core::DeviceRingState;
use moat_core::CoordMsg;
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

    /// Generate a fresh key package reusing the **existing** signing key from `key_bundle`.
    ///
    /// Unlike `generate_key_package`, this preserves the leaf-node public key so that
    /// all MLS groups the caller already belongs to remain usable after the call.
    /// Use this to replenish the PDS key package after a Welcome has consumed the
    /// previous one (e.g. after joining a coord group).
    ///
    /// Returns only the new key package bytes; the key bundle is unchanged.
    pub fn replenish_key_package(
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
            .replenish_key_package(&credential, &key_bundle)
            .map_err(|e| e.to_string())
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

    /// The device name of the member of `group_id` with `device_id`, if any.
    pub fn member_device_name(
        &self,
        group_id: Vec<u8>,
        device_id: Vec<u8>,
    ) -> Result<Option<String>, String> {
        let device_id: moat_core::DeviceId = device_id
            .try_into()
            .map_err(|_| "device_id must be 16 bytes".to_string())?;
        self.inner
            .lock()
            .unwrap()
            .member_device_name(&group_id, &device_id)
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
            .populate_candidate_tags(&group_id, &[])
            .map(|tags| tags.into_iter().map(|t| t.to_vec()).collect())
            .map_err(|e| e.to_string())
    }

    /// Mark a matched tag as seen and extend its sender's scanning window.
    ///
    /// Returns the newly covered tags, for the tag map and watch list.
    #[frb(sync)]
    pub fn advance_scan_window(&self, tag: Vec<u8>) -> Vec<Vec<u8>> {
        let Ok(tag) = <[u8; 16]>::try_from(tag.as_slice()) else {
            return Vec::new();
        };
        self.inner
            .lock()
            .unwrap()
            .advance_scan_window(&tag)
            .into_iter()
            .map(|t| t.to_vec())
            .collect()
    }

    /// Check if a DID already has a device in the group.
    #[frb(sync)]
    pub fn is_did_in_group(&self, group_id: Vec<u8>, did: String) -> Result<bool, String> {
        self.inner
            .lock()
            .unwrap()
            .is_did_in_group(&group_id, &did)
            .map_err(|e| e.to_string())
    }

    /// Extract the credential (DID, device_id, device_name) from a raw key package bytes.
    /// Returns None if the key package has no credential embedded.
    pub fn extract_credential_from_key_package(
        &self,
        key_package: Vec<u8>,
    ) -> Result<Option<CredentialDto>, String> {
        self.inner
            .lock()
            .unwrap()
            .extract_credential_from_key_package(&key_package)
            .map(|opt| {
                opt.map(|c| CredentialDto {
                    did: c.did().to_string(),
                    device_id: c.device_id().to_vec(),
                    device_name: c.device_name().to_string(),
                })
            })
            .map_err(|e| e.to_string())
    }

    /// Return the (DID, device_id, device_name) credential for every member of a group.
    pub fn get_group_member_credentials(
        &self,
        group_id: Vec<u8>,
    ) -> Result<Vec<CredentialDto>, String> {
        let members = self
            .inner
            .lock()
            .unwrap()
            .get_group_members(&group_id)
            .map_err(|e| e.to_string())?;
        Ok(members
            .into_iter()
            .filter_map(|(_, cred_opt)| {
                cred_opt.map(|c| CredentialDto {
                    did: c.did().to_string(),
                    device_id: c.device_id().to_vec(),
                    device_name: c.device_name().to_string(),
                })
            })
            .collect())
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

    // --- Inbox (see `moat_core::inbox`) ---

    /// Queue a fetched event. Returns false if it is already held.
    #[frb(sync)]
    pub fn inbox_push(&self, event: InboxEventDto) -> Result<bool, String> {
        Ok(self.inner.lock().unwrap().inbox_push(event.try_into()?))
    }

    /// The ready event with the lowest rkey.
    #[frb(sync)]
    pub fn inbox_pop_ready(&self) -> Option<InboxEventDto> {
        self.inner.lock().unwrap().inbox_pop_ready().map(Into::into)
    }

    /// Park an event until its tag is generated.
    #[frb(sync)]
    pub fn inbox_park(&self, event: InboxEventDto, now_ms: i64) -> Result<(), String> {
        self.inner.lock().unwrap().inbox_park(event.try_into()?, now_ms);
        Ok(())
    }

    /// Drop events parked too long. Returns how many were dropped.
    #[frb(sync)]
    pub fn inbox_expire(&self, now_ms: i64) -> u32 {
        self.inner.lock().unwrap().inbox_expire(now_ms) as u32
    }

    /// The parked events, serialized for the host to persist.
    #[frb(sync)]
    pub fn export_parked_events(&self) -> Vec<u8> {
        self.inner.lock().unwrap().export_parked_events()
    }

    /// Restore parked events persisted with `export_parked_events`.
    #[frb(sync)]
    pub fn import_parked_events(&self, bytes: Vec<u8>) -> Result<u32, String> {
        self.inner
            .lock()
            .unwrap()
            .import_parked_events(&bytes)
            .map(|n| n as u32)
            .map_err(|e| e.to_string())
    }

    /// The group a candidate tag belongs to, if it is one.
    #[frb(sync)]
    pub fn group_for_tag(&self, tag: Vec<u8>) -> Option<Vec<u8>> {
        let tag: [u8; 16] = tag.try_into().ok()?;
        self.inner.lock().unwrap().group_for_tag(&tag)
    }
}

// --- DTO types for FRB ---

/// A fetched `social.moat.event` record, as the inbox holds it.
pub struct InboxEventDto {
    /// The DID whose PDS the record was fetched from.
    pub source_did: String,
    pub rkey: String,
    pub author_did: String,
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at_ms: i64,
}

impl TryFrom<InboxEventDto> for moat_core::InboxEvent {
    type Error = String;
    fn try_from(e: InboxEventDto) -> Result<Self, String> {
        Ok(moat_core::InboxEvent {
            source_did: e.source_did,
            rkey: e.rkey,
            author_did: e.author_did,
            tag: e.tag.try_into().map_err(|_| "tag must be 16 bytes".to_string())?,
            ciphertext: e.ciphertext,
            created_at_ms: e.created_at_ms,
        })
    }
}

impl From<moat_core::InboxEvent> for InboxEventDto {
    fn from(e: moat_core::InboxEvent) -> Self {
        InboxEventDto {
            source_did: e.source_did,
            rkey: e.rkey,
            author_did: e.author_did,
            tag: e.tag.to_vec(),
            ciphertext: e.ciphertext,
            created_at_ms: e.created_at_ms,
        }
    }
}

pub struct KeyPackageResult {
    pub key_package: Vec<u8>,
    pub key_bundle: Vec<u8>,
}

pub struct WelcomeResultDto {
    pub new_group_state: Vec<u8>,
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub commit_tag: Vec<u8>,
    pub group_id: Vec<u8>,
}

impl From<WelcomeResult> for WelcomeResultDto {
    fn from(r: WelcomeResult) -> Self {
        WelcomeResultDto {
            new_group_state: r.new_group_state,
            welcome: r.welcome,
            commit: r.commit,
            commit_tag: r.commit_tag.to_vec(),
            group_id: r.group_id,
        }
    }
}

pub struct EncryptResultDto {
    pub new_group_state: Vec<u8>,
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
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
    pub did: String,
    /// The sender's device name (format: "did:plc:xxx/Device Name")
    pub device_name: String,
    /// The sender's stable 16-byte device id, from their MLS credential.
    pub device_id: Vec<u8>,
}

impl From<SenderInfo> for SenderInfoDto {
    fn from(s: SenderInfo) -> Self {
        SenderInfoDto {
            did: s.did,
            device_name: s.device_name,
            device_id: s.device_id.to_vec(),
        }
    }
}

pub enum EventKindDto {
    Message,
    Commit,
    Welcome,
    Checkpoint,
    Reaction,
    RingMsg,
    Unknown,
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
            EventKindDto::Message => {
                let mut event =
                    Event::message_from_bytes(self.group_id, self.epoch, &self.payload);
                // A retried send republishes under the id its first attempt used.
                if self.message_id.is_some() {
                    event.message_id = self.message_id;
                }
                event
            }
            EventKindDto::Commit => Event::commit(self.group_id, self.epoch, self.payload),
            EventKindDto::Welcome => Event::welcome(self.group_id, self.epoch, self.payload),
            EventKindDto::Checkpoint => Event::checkpoint(self.group_id, self.epoch, self.payload),
            EventKindDto::Reaction => {
                let reaction: CoreReactionPayload =
                    serde_json::from_slice(&self.payload).expect("invalid reaction payload");
                let mut event = Event::reaction(
                    self.group_id,
                    self.epoch,
                    &reaction.target_message_id,
                    &reaction.emoji,
                );
                event.message_id = self.message_id;
                event
            }
            EventKindDto::RingMsg => Event::ring_msg(self.group_id, self.epoch, self.payload),
            EventKindDto::Unknown => {
                panic!("cannot convert Unknown event to core Event")
            }
        }
    }

    fn from_core(e: Event) -> Self {
        EventDto {
            kind: match e.kind {
                EventKind::Message(_) => EventKindDto::Message,
                EventKind::Control(ControlKind::Commit) => EventKindDto::Commit,
                EventKind::Control(ControlKind::Welcome) => EventKindDto::Welcome,
                EventKind::Control(ControlKind::Checkpoint) => EventKindDto::Checkpoint,
                EventKind::Modifier(ModifierKind::Reaction) => EventKindDto::Reaction,
                EventKind::RingMsg => EventKindDto::RingMsg,
                EventKind::Modifier(_)
                | EventKind::Control(_)
                | EventKind::SiblingMsg
                | EventKind::Unknown(_) => EventKindDto::Unknown,
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
            kind: EventKind::Modifier(ModifierKind::Reaction),
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


/// Sign a Drawbridge challenge with the Ed25519 identity key from a key bundle.
///
/// Returns (signature_bytes, public_key_bytes) as raw bytes (64 and 32 bytes).
/// The caller is responsible for base64-encoding for JSON transport.
///
/// `message` is typically `"{nonce}\n{drawbridge_url}\n{timestamp}\n"`.
pub fn sign_drawbridge_challenge(
    key_bundle: Vec<u8>,
    message: Vec<u8>,
) -> Result<DrawbridgeChallengeSignature, String> {
    let (sig, pubkey) = MoatSession::sign_drawbridge_challenge(&key_bundle, &message)
        .map_err(|e| e.to_string())?;
    Ok(DrawbridgeChallengeSignature {
        signature: sig,
        public_key: pubkey,
    })
}

/// A Drawbridge URL as typed or scanned, in the form a device connects to and
/// signs: `ws://` or `wss://`, a host and a path. A bare host becomes
/// `wss://<host>/ws`. Two spellings of one Drawbridge compare equal once
/// normalised.
#[frb(sync)]
pub fn normalize_drawbridge_url(url: String) -> Result<String, String> {
    moat_core::normalize_drawbridge_url(&url).map_err(|e| e.to_string())
}

/// Result of signing a Drawbridge challenge.
pub struct DrawbridgeChallengeSignature {
    /// Ed25519 signature (64 bytes)
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes)
    pub public_key: Vec<u8>,
}

/// Pad plaintext to bucket size (512, 1024, or 4096 bytes).
///
/// Fails above the largest bucket: there is nothing to round up to, and
/// oversized content belongs in an external blob with only the reference
/// in the event.
#[frb(sync)]
pub fn pad_to_bucket(plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    moat_core::pad_to_bucket(&plaintext).map_err(|e| e.to_string())
}

/// Remove padding and extract original plaintext.
#[frb(sync)]
pub fn unpad(padded: Vec<u8>) -> Vec<u8> {
    moat_core::unpad(&padded)
}

// --- Blob crypto and image processing ---

/// Encrypt a blob. Returns encrypted bytes and metadata for ExternalBlob.
pub fn blob_encrypt(plaintext: Vec<u8>) -> Result<BlobEncryptResult, String> {
    moat_core::blob_encrypt(&plaintext)
        .map(|r| BlobEncryptResult {
            blob: r.blob,
            key: r.key.to_vec(),
            ciphertext_hash: r.ciphertext_hash,
            content_hash: r.content_hash,
        })
        .map_err(|e| e.to_string())
}

/// Decrypt and verify a blob.
pub fn blob_decrypt(
    blob: Vec<u8>,
    key: Vec<u8>,
    ciphertext_hash: Vec<u8>,
    content_hash: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| "key must be 32 bytes".to_string())?;
    moat_core::blob_decrypt(&blob, &key_arr, &ciphertext_hash, &content_hash)
        .map_err(|e| e.to_string())
}

/// Process an image for sending: validate format, resize if >2048px, generate thumbhash.
/// Returns processed bytes, dimensions, thumbhash, and MIME type.
pub fn process_image_for_send(image_bytes: Vec<u8>) -> Result<ImageProcessResult, String> {
    use image::{GenericImageView, ImageFormat};
    use std::io::Cursor;

    let format = image::guess_format(&image_bytes)
        .map_err(|_| "Unsupported format: only JPEG and PNG are accepted".to_string())?;

    let (mime, img_format) = match format {
        ImageFormat::Jpeg => ("image/jpeg", ImageFormat::Jpeg),
        ImageFormat::Png => ("image/png", ImageFormat::Png),
        _ => return Err("Unsupported format: only JPEG and PNG are accepted".to_string()),
    };

    let img = image::load_from_memory(&image_bytes)
        .map_err(|e| format!("Failed to decode image: {}", e))?;

    let (orig_w, orig_h) = img.dimensions();
    const MAX_DIM: u32 = 2048;

    let (final_bytes, width, height) = if orig_w > MAX_DIM || orig_h > MAX_DIM {
        let scale = (MAX_DIM as f64 / orig_w.max(orig_h) as f64).min(1.0);
        let new_w = ((orig_w as f64 * scale).round() as u32).max(1);
        let new_h = ((orig_h as f64 * scale).round() as u32).max(1);
        let resized = img.resize(new_w, new_h, image::imageops::FilterType::Lanczos3);
        let mut buf = Vec::new();
        resized
            .write_to(&mut Cursor::new(&mut buf), img_format)
            .map_err(|e| format!("Failed to encode image: {}", e))?;
        (buf, new_w, new_h)
    } else {
        (image_bytes, orig_w, orig_h)
    };

    // Re-decode from final bytes for thumbhash generation.
    let for_hash = image::load_from_memory(&final_bytes)
        .map_err(|e| format!("Failed to re-decode for ThumbHash: {}", e))?;

    let thumbhash = {
        const HASH_MAX: u32 = 100;
        let (w, h) = for_hash.dimensions();
        let scale = (HASH_MAX as f64 / w.max(h) as f64).min(1.0);
        let tw = ((w as f64 * scale).round() as u32).max(1);
        let th = ((h as f64 * scale).round() as u32).max(1);
        let small = if tw < w || th < h {
            for_hash.resize(tw, th, image::imageops::FilterType::Triangle)
        } else {
            for_hash.clone()
        };
        let rgba = small.to_rgba8();
        let (rw, rh) = rgba.dimensions();
        thumbhash::rgba_to_thumb_hash(rw as usize, rh as usize, rgba.as_raw())
    };

    Ok(ImageProcessResult {
        image_bytes: final_bytes,
        width,
        height,
        thumbhash,
        mime_type: mime.to_string(),
    })
}

/// Decode a thumbhash to RGBA pixels for placeholder rendering.
pub fn decode_thumbhash(hash: Vec<u8>) -> Result<ThumbHashResult, String> {
    let result = std::panic::catch_unwind(|| thumbhash::thumb_hash_to_rgba(&hash));
    let (w, h, rgba) = result
        .map_err(|_| "thumbhash decode panicked".to_string())?
        .map_err(|_| "thumbhash decode failed".to_string())?;
    Ok(ThumbHashResult {
        rgba,
        width: w as u32,
        height: h as u32,
    })
}

/// Credential fields for a group member or key package.
pub struct CredentialDto {
    pub did: String,
    pub device_id: Vec<u8>,
    pub device_name: String,
}

pub struct BlobEncryptResult {
    /// Encrypted bytes: nonce (24 bytes) || ciphertext.
    pub blob: Vec<u8>,
    /// 32-byte symmetric key.
    pub key: Vec<u8>,
    /// SHA-256 of blob (pre-decryption integrity check).
    pub ciphertext_hash: Vec<u8>,
    /// SHA-256 of plaintext (post-decryption integrity check and cache key).
    pub content_hash: Vec<u8>,
}

pub struct ImageProcessResult {
    /// Processed image bytes (JPEG or PNG, resized if >2048px).
    pub image_bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// ThumbHash bytes for blurry placeholder preview.
    pub thumbhash: Vec<u8>,
    /// MIME type: "image/jpeg" or "image/png".
    pub mime_type: String,
}

pub struct ThumbHashResult {
    /// Raw RGBA pixel data (width * height * 4 bytes).
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

// ---- FCM push decrypt (native-only: uses std::fs) ----
//
// The web platform uses a different I/O model (IndexedDB); a companion
// `decrypt_push_payload_web` function will be added when Web Push is
// implemented, taking state bytes directly instead of a file path.

/// Result of decrypting a push notification payload.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct DecryptedPush {
    /// DID of the message sender, extracted from their MLS credential.
    pub sender_did: Option<String>,
    /// Human-readable preview for the notification body (truncated to 200 chars).
    /// `None` for protocol messages (commit, welcome, checkpoint) that should not
    /// generate a visible notification.
    pub plaintext_preview: Option<String>,
    /// The MLS group ID the message belongs to.
    pub group_id: Vec<u8>,
    /// 16-byte message ID for deduplication (present for Message and Reaction events).
    pub message_id: Option<Vec<u8>>,
}

/// Decrypt a push notification payload for use in a background message handler
/// or iOS Notification Service Extension.
///
/// Reads the MLS session state from `state_path`, scans `group_ids` to find
/// which group the `tag` belongs to, decrypts `ciphertext`, advances the seen
/// counter, and writes the updated state back to `state_path` atomically
/// (write to `<state_path>.push_tmp`, then rename).
///
/// Returns `Err` if the tag is not matched in any group or if decrypt fails.
///
/// # Concurrency
/// The rename is atomic on POSIX. If the foreground app races to write state
/// simultaneously one update will win; the dedup map in moat-core makes
/// double-processing safe.
#[cfg(not(target_arch = "wasm32"))]
pub fn decrypt_push_payload(
    state_path: String,
    group_ids: Vec<Vec<u8>>,
    tag: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<DecryptedPush, String> {
    // 1. Load session.
    let state_bytes = std::fs::read(&state_path)
        .map_err(|e| format!("failed to read state file: {e}"))?;
    let session = MoatSession::from_state(&state_bytes).map_err(|e| e.to_string())?;

    // 2. Validate tag length.
    let tag_arr: [u8; 16] = tag
        .try_into()
        .map_err(|_| "tag must be 16 bytes".to_string())?;

    // 3. Find the group whose candidate tags include this tag.
    let mut matched_group: Option<Vec<u8>> = None;
    'outer: for group_id in &group_ids {
        let candidates = session
            .populate_candidate_tags(group_id, &[])
            .map_err(|e| e.to_string())?;
        for candidate in candidates {
            if candidate == tag_arr {
                matched_group = Some(group_id.clone());
                break 'outer;
            }
        }
    }
    let group_id = matched_group.ok_or_else(|| "tag not matched in any group".to_string())?;

    // 4. Decrypt.
    let outcome = session
        .decrypt_event(&group_id, &ciphertext)
        .map_err(|e| e.to_string())?;
    let result = outcome.into_result();

    // 5. Advance seen counter so the next populate_candidate_tags starts past this message.
    session.mark_tag_seen(&tag_arr);

    // 6. Persist updated state atomically.
    let new_state = session.export_state().map_err(|e| e.to_string())?;
    let tmp_path = format!("{}.push_tmp", state_path);
    std::fs::write(&tmp_path, &new_state)
        .map_err(|e| format!("failed to write tmp state: {e}"))?;
    std::fs::rename(&tmp_path, &state_path)
        .map_err(|e| format!("failed to rename state: {e}"))?;

    // 7. Build and return the result.
    let plaintext_preview = push_plaintext_preview(&result.event);
    let sender_did = result.sender.map(|s| s.did);
    Ok(DecryptedPush {
        sender_did,
        plaintext_preview,
        group_id,
        message_id: result.event.message_id,
    })
}

/// Derive a notification preview string from a decrypted event.
#[cfg(not(target_arch = "wasm32"))]
fn push_plaintext_preview(event: &Event) -> Option<String> {
    use moat_core::{MessagePayload, ParsedMessagePayload};
    match &event.kind {
        EventKind::Message(_) => match ParsedMessagePayload::from_bytes(&event.payload) {
            ParsedMessagePayload::Structured(MessagePayload::ShortText(m))
            | ParsedMessagePayload::Structured(MessagePayload::MediumText(m)) => {
                let t = &m.text;
                Some(if t.len() > 200 {
                    format!("{}…", &t[..200])
                } else {
                    t.clone()
                })
            }
            ParsedMessagePayload::Structured(MessagePayload::LongText(m)) => {
                let t = &m.preview_text;
                Some(if t.len() > 200 {
                    format!("{}…", &t[..200])
                } else {
                    t.clone()
                })
            }
            ParsedMessagePayload::Structured(MessagePayload::Image(media)) => {
                Some(push_media_label(media.mime.as_deref()).to_string())
            }
            ParsedMessagePayload::LegacyPlaintext(bytes) => String::from_utf8(bytes).ok(),
        },
        EventKind::Modifier(ModifierKind::Reaction) => event
            .reaction_payload()
            .map(|rp| format!("Reacted with {}", rp.emoji)),
        _ => None,
    }
}

/// Map a MIME type to a human-readable emoji label for media messages.
#[cfg(not(target_arch = "wasm32"))]
fn push_media_label(mime: Option<&str>) -> &'static str {
    match mime {
        Some("image/gif") => "🎞️ GIF",
        Some(m) if m.starts_with("video/") => "🎬 Video",
        _ => "📷 Photo",
    }
}

// On wasm32 the push-decrypt code path is unavailable (uses std::fs). Provide
// stubs so the FRB-generated bindings still compile; the function returns an
// error if called.
#[cfg(target_arch = "wasm32")]
pub struct DecryptedPush {
    pub sender_did: Option<String>,
    pub plaintext_preview: Option<String>,
    pub group_id: Vec<u8>,
    pub message_id: Option<Vec<u8>>,
}

#[cfg(target_arch = "wasm32")]
pub fn decrypt_push_payload(
    _state_path: String,
    _group_ids: Vec<Vec<u8>>,
    _tag: Vec<u8>,
    _ciphertext: Vec<u8>,
) -> Result<DecryptedPush, String> {
    Err("decrypt_push_payload is not available on web".to_string())
}

// --- Device ring driver ---

/// Opaque handle to a `DeviceRingState`, thread-safe via Mutex.
pub struct RingDriverHandle {
    inner: Mutex<DeviceRingState>,
}

impl RingDriverHandle {
    /// Create a new ring state with empty state.
    #[frb(sync)]
    pub fn new_empty() -> RingDriverHandle {
        RingDriverHandle { inner: Mutex::new(DeviceRingState::default()) }
    }

    /// Restore a ring state from its persisted JSON.
    pub fn from_state_json(json: String) -> Result<RingDriverHandle, String> {
        let state: DeviceRingState = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        Ok(RingDriverHandle { inner: Mutex::new(state) })
    }

    /// Serialise the current ring state as JSON.
    pub fn to_state_json(&self) -> Result<String, String> {
        serde_json::to_string(&*self.inner.lock().unwrap()).map_err(|e| e.to_string())
    }

    /// Raw ring group ID, if a ring exists.
    #[frb(sync)]
    pub fn ring_group_id(&self) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().ring_id().map(<[u8]>::to_vec)
    }

    /// One-line snapshot of ring membership and peer states, for the Dart
    /// host's debug log. Same renderer as `moat-cli` uses, so a mixed-runtime
    /// beacon failure produces comparable lines from both sides.
    #[frb(sync)]
    pub fn debug_summary(&self) -> String {
        self.inner.lock().unwrap().debug_summary()
    }

    /// Cursor (rkey) for incremental own-PDS stealth scan.
    #[frb(sync)]
    pub fn own_events_cursor(&self) -> Option<String> {
        self.inner.lock().unwrap().own_events_cursor().map(str::to_string)
    }

    /// Record that we are now an MLS member of `ring_id`, looking up our
    /// own leaf index from the group's member list. Called once, host-side,
    /// when a pairing exchange completes — the new device from
    /// `PairingCommandDto.persistRing`, the existing device right after a
    /// successful `PairingSessionHandle.approve` (which has no command of
    /// its own for this, since it already knows it just created/joined
    /// `ring_id`). Mirrors `moat-cli`'s `App`-level interpreter.
    pub fn record_ring_membership(
        &self,
        session: &MoatSessionHandle,
        ring_id: Vec<u8>,
        now_ms: i64,
    ) -> Result<(), String> {
        let session_lock = session.inner.lock().unwrap();
        self.inner
            .lock()
            .unwrap()
            .record_ring_membership(&session_lock, ring_id, now_ms)
            .map_err(|e| e.to_string())
    }

    /// Device ids of siblings confirmed to be in the ring.  Drives the
    /// same-user fan-out loop in the host.
    #[frb(sync)]
    pub fn ring_joined_siblings(&self, session: &MoatSessionHandle) -> Vec<Vec<u8>> {
        let session_lock = session.inner.lock().unwrap();
        self.inner
            .lock()
            .unwrap()
            .ring_joined_siblings(&session_lock)
            .into_iter()
            .map(|d| d.to_vec())
            .collect()
    }

    /// Claim one unused key package from the local pool for `owner`, marking
    /// its seq consumed.  `None` means the pool is drained — the host should
    /// emit a `KpRequest` via [`Self::emit_kp_request_for`] and defer the add
    /// until a `KpBatch` arrives.  Single-use enforcement lives here, not in
    /// the host: a seq is never returned twice, even if replayed into the
    /// pool.
    #[frb(sync)]
    pub fn claim_kp(&self, owner_device_id: Vec<u8>) -> Result<Option<OfferedKpDto>, String> {
        let owner: [u8; 16] = owner_device_id
            .try_into()
            .map_err(|_| "owner_device_id must be 16 bytes".to_string())?;
        Ok(self.inner.lock().unwrap().claim_kp(&owner).map(|kp| OfferedKpDto {
            rkey: kp.rkey,
            seq: kp.seq,
            key_package: kp.key_package,
        }))
    }

    /// Emit a `KpRequest` to `owner` asking it to top up our pool.  The host
    /// publishes the returned commands.  Empty if not in a ring or if the
    /// sibling's stealth record is not yet known (self-healing: the next poll
    /// retries).
    pub fn emit_kp_request_for(
        &self,
        session: &MoatSessionHandle,
        my_did: String,
        key_bundle: Vec<u8>,
        sibling_stealth: Vec<SiblingStealthDto>,
        owner_device_id: Vec<u8>,
    ) -> Result<Vec<RingCommandDto>, String> {
        let owner: [u8; 16] = owner_device_id
            .try_into()
            .map_err(|_| "owner_device_id must be 16 bytes".to_string())?;
        let sibling_stealth = to_core_sibling_stealth(sibling_stealth)?;
        let session_lock = session.inner.lock().unwrap();
        let credential = MoatCredential::new(&my_did, "", *session_lock.device_id());
        let env = StepEnv {
            my_did: &my_did,
            credential: &credential,
            key_bundle: &key_bundle,
            now_ms: 0,
            sibling_stealth: &sibling_stealth,
        };
        let cmds = self.inner.lock().unwrap().emit_kp_request_for(&session_lock, &env, &owner);
        Ok(cmds.into_iter().map(RingCommandDto::from).collect())
    }

    /// Build the stealth-publish command carrying a `CoordMsg::UserConvWelcome`
    /// for `owner`.  The CoordMsg framing stays in Rust so the wire format has
    /// a single owner.  `None` if not in a ring or the sibling's stealth
    /// record is unknown.
    ///
    /// Flat parameter list rather than a bundled struct: each `#[frb]`
    /// parameter becomes a named argument in the generated Dart binding, so
    /// callers get the same readability a struct would give without an
    /// extra DTO to keep in sync.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_user_conv_welcome(
        &self,
        session: &MoatSessionHandle,
        my_did: String,
        key_bundle: Vec<u8>,
        sibling_stealth: Vec<SiblingStealthDto>,
        owner_device_id: Vec<u8>,
        group_id: Vec<u8>,
        welcome: Vec<u8>,
    ) -> Result<Option<RingCommandDto>, String> {
        let owner: [u8; 16] = owner_device_id
            .clone()
            .try_into()
            .map_err(|_| "owner_device_id must be 16 bytes".to_string())?;
        let sibling_stealth = to_core_sibling_stealth(sibling_stealth)?;
        let session_lock = session.inner.lock().unwrap();
        let credential = MoatCredential::new(&my_did, "", *session_lock.device_id());
        let env = StepEnv {
            my_did: &my_did,
            credential: &credential,
            key_bundle: &key_bundle,
            now_ms: 0,
            sibling_stealth: &sibling_stealth,
        };
        let msg = CoordMsg::UserConvWelcome {
            owner_device_id,
            group_id,
            welcome,
        };
        let cmd = self
            .inner
            .lock()
            .unwrap()
            .encrypt_for_sibling(&session_lock, &env, &owner, &msg);
        Ok(cmd.map(RingCommandDto::from))
    }

    /// Drive one ring coordination tick. Returns commands for the host to interpret.
    pub fn tick(
        &self,
        session: &MoatSessionHandle,
        inputs: TickInputsDto,
    ) -> Result<Vec<RingCommandDto>, String> {
        let key_packages: Vec<KeyPackageInput> = inputs
            .key_packages
            .into_iter()
            .map(|key_package| KeyPackageInput { key_package })
            .collect();
        let sibling_stealth = to_core_sibling_stealth(inputs.sibling_stealth)?;
        let own_events: Vec<OwnEventInput> = inputs
            .own_events
            .into_iter()
            .map(|e| OwnEventInput { rkey: e.rkey, ciphertext: e.ciphertext })
            .collect();
        let stealth_privkey: [u8; 32] = inputs
            .stealth_privkey
            .try_into()
            .map_err(|_| "stealth_privkey must be 32 bytes".to_string())?;

        let session_lock = session.inner.lock().unwrap();
        let device_id = *session_lock.device_id();
        let credential = MoatCredential::new(&inputs.did, &inputs.device_name, device_id);

        let core_inputs = TickInputs {
            key_packages: &key_packages,
            sibling_stealth: &sibling_stealth,
            own_events: &own_events,
            stealth_privkey: &stealth_privkey,
            credential: &credential,
            key_bundle: &inputs.key_bundle,
            now_ms: inputs.now_ms,
            my_did: &inputs.did,
        };

        let cmds = self.inner.lock().unwrap().tick(&session_lock, core_inputs);
        Ok(cmds.into_iter().map(RingCommandDto::from).collect())
    }
}

pub struct TickInputsDto {
    /// Sibling key packages fetched from our own PDS (driver filters out our own).
    pub key_packages: Vec<Vec<u8>>,
    /// Per-sibling stealth addressing: `scan_pubkey` paired with the stable
    /// `device_id` it belongs to.  Required for the ring driver to address
    /// steady-state `SiblingMsg` payloads at a specific sibling.  Callers
    /// should filter out their own device.
    pub sibling_stealth: Vec<SiblingStealthDto>,
    /// Own-PDS events since `own_events_cursor`.
    pub own_events: Vec<OwnEventInputDto>,
    /// Our stealth scan private key (32 bytes).
    pub stealth_privkey: Vec<u8>,
    /// Our DID.
    pub did: String,
    /// Our device name.
    pub device_name: String,
    /// Identity key bundle.
    pub key_bundle: Vec<u8>,
    /// Wall-clock time (ms since epoch); used as `ring_created_at` for new rings.
    pub now_ms: i64,
}

pub struct OwnEventInputDto {
    pub rkey: String,
    pub ciphertext: Vec<u8>,
}

/// One key package drawn from the same-user KP pool.
pub struct OfferedKpDto {
    pub rkey: Vec<u8>,
    pub seq: u64,
    pub key_package: Vec<u8>,
}

/// A sibling device's stealth address: the 32-byte X25519 scan pubkey plus the
/// stable 16-byte device id it belongs to.  Mirrors `moat_core::SiblingStealth`.
pub struct SiblingStealthDto {
    pub scan_pubkey: Vec<u8>,
    pub device_id: Vec<u8>,
}

fn to_core_sibling_stealth(
    dtos: Vec<SiblingStealthDto>,
) -> Result<Vec<moat_core::SiblingStealth>, String> {
    dtos.into_iter()
        .map(|s| {
            Ok(moat_core::SiblingStealth {
                scan_pubkey: s
                    .scan_pubkey
                    .try_into()
                    .map_err(|_| "sibling scan_pubkey must be 32 bytes".to_string())?,
                device_id: s
                    .device_id
                    .try_into()
                    .map_err(|_| "sibling device_id must be 16 bytes".to_string())?,
            })
        })
        .collect()
}

#[derive(Debug)]
pub enum GroupKindDto {
    User,
    Ring,
}

impl From<GroupKind> for GroupKindDto {
    fn from(k: GroupKind) -> Self {
        match k {
            GroupKind::User => GroupKindDto::User,
            GroupKind::Ring => GroupKindDto::Ring,
        }
    }
}

#[derive(Debug)]
pub enum RingCommandDto {
    PublishStealthEvent { tag: Vec<u8>, ciphertext: Vec<u8> },
    ReplenishKeyPackage,
    RegisterGroup { group_id: Vec<u8>, kind: GroupKindDto },
    PollForNewDevices,
}

impl From<RingCommand> for RingCommandDto {
    fn from(c: RingCommand) -> Self {
        match c {
            RingCommand::PublishStealthEvent { tag, ciphertext } => {
                RingCommandDto::PublishStealthEvent { tag: tag.to_vec(), ciphertext }
            }
            RingCommand::ReplenishKeyPackage => RingCommandDto::ReplenishKeyPackage,
            RingCommand::RegisterGroup { group_id, kind } => {
                RingCommandDto::RegisterGroup { group_id, kind: kind.into() }
            }
            RingCommand::PollForNewDevices => RingCommandDto::PollForNewDevices,
        }
    }
}

// --- Pair channel: pairing, sync requests and history transfer ---

/// Mirrors `moat_core::SyncProgress`, with its `fraction()` computed.
pub enum SyncProgressDto {
    Starting,
    Transferring {
        received: u64,
        receive_total: u64,
        sent: u64,
        send_total: u64,
        fraction: f64,
    },
}

impl From<moat_core::SyncProgress> for SyncProgressDto {
    fn from(p: moat_core::SyncProgress) -> Self {
        let fraction = p.fraction().unwrap_or(0.0);
        match p {
            moat_core::SyncProgress::Starting => Self::Starting,
            moat_core::SyncProgress::Transferring { received, receive_total, sent, send_total } => {
                Self::Transferring { received, receive_total, sent, send_total, fraction }
            }
        }
    }
}

pub struct SyncMessageDto {
    pub rkey: String,
    pub message_id: Option<Vec<u8>>,
    pub sender_did: String,
    pub sender_device_name: String,
    pub timestamp_ms: i64,
    pub content: String,
    pub blob_uri: Option<String>,
    pub blob_key: Option<Vec<u8>>,
    pub blob_ciphertext_hash: Option<Vec<u8>>,
    pub blob_ciphertext_size: Option<u64>,
    pub blob_content_hash: Option<Vec<u8>>,
    pub blob_mime: Option<String>,
    pub blob_width: Option<u32>,
    pub blob_height: Option<u32>,
    /// The image's blurry placeholder, shown while the blob downloads.
    pub blob_thumbhash: Option<Vec<u8>>,
    /// Emoji reactions on this message. Carried because the receiving
    /// device cannot rebuild them: reaction events predating its
    /// membership are not decryptable to it.
    pub reactions: Vec<SyncReactionDto>,
}

/// One emoji reaction, as carried by a synced message.
pub struct SyncReactionDto {
    pub emoji: String,
    pub sender_did: String,
}

impl From<moat_core::SyncReaction> for SyncReactionDto {
    fn from(r: moat_core::SyncReaction) -> Self {
        SyncReactionDto { emoji: r.emoji, sender_did: r.sender_did }
    }
}

impl From<SyncReactionDto> for moat_core::SyncReaction {
    fn from(r: SyncReactionDto) -> Self {
        moat_core::SyncReaction { emoji: r.emoji, sender_did: r.sender_did }
    }
}

impl From<SyncMessage> for SyncMessageDto {
    fn from(m: SyncMessage) -> Self {
        SyncMessageDto {
            rkey: m.rkey,
            message_id: m.message_id,
            sender_did: m.sender_did,
            sender_device_name: m.sender_device_name,
            timestamp_ms: m.timestamp_ms,
            content: m.content,
            blob_uri: m.blob_uri,
            blob_key: m.blob_key,
            blob_ciphertext_hash: m.blob_ciphertext_hash,
            blob_ciphertext_size: m.blob_ciphertext_size,
            blob_content_hash: m.blob_content_hash,
            blob_mime: m.blob_mime,
            blob_width: m.blob_width,
            blob_height: m.blob_height,
            blob_thumbhash: m.blob_thumbhash,
            reactions: m.reactions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<SyncMessageDto> for SyncMessage {
    fn from(m: SyncMessageDto) -> Self {
        SyncMessage {
            rkey: m.rkey,
            message_id: m.message_id,
            sender_did: m.sender_did,
            sender_device_name: m.sender_device_name,
            timestamp_ms: m.timestamp_ms,
            content: m.content,
            blob_uri: m.blob_uri,
            blob_key: m.blob_key,
            blob_ciphertext_hash: m.blob_ciphertext_hash,
            blob_ciphertext_size: m.blob_ciphertext_size,
            blob_content_hash: m.blob_content_hash,
            blob_mime: m.blob_mime,
            blob_width: m.blob_width,
            blob_height: m.blob_height,
            blob_thumbhash: m.blob_thumbhash,
            reactions: m.reactions.into_iter().map(Into::into).collect(),
        }
    }
}

/// Mirrors `moat_core::PairingUiState` 1:1. Every host (this Dart app, the
/// headless server, moat-cli) renders this; none derives its own.
pub enum PairingUiStateDto {
    /// No pairing in flight.
    Idle,
    /// New device: code generated, waiting for the peer to enter it.
    ShowingCode { code: String, drawbridge_url: String, uri: String },
    /// Existing device: code accepted, waiting for the peer's `Enroll`.
    AwaitingPeer,
    /// Existing device: `Enroll` received, waiting on the approve/reject
    /// decision.
    AwaitingApproval { device_name: String, did: String },
    /// Enroll/Admit exchange complete. Says nothing about history sync —
    /// that stays observable via `syncStatus`.
    Done { ring_id: Vec<u8> },
    /// Terminal failure, with a reason retained on the session rather than
    /// thrown away.
    Failed { reason: String },
}

impl From<moat_core::PairingUiState> for PairingUiStateDto {
    fn from(s: moat_core::PairingUiState) -> Self {
        use moat_core::PairingUiState;
        match s {
            PairingUiState::Idle => PairingUiStateDto::Idle,
            PairingUiState::ShowingCode { code, drawbridge_url, uri } => {
                PairingUiStateDto::ShowingCode { code, drawbridge_url, uri }
            }
            PairingUiState::AwaitingPeer => PairingUiStateDto::AwaitingPeer,
            PairingUiState::AwaitingApproval { device_name, did } => {
                PairingUiStateDto::AwaitingApproval { device_name, did }
            }
            PairingUiState::Done { ring_id } => PairingUiStateDto::Done { ring_id },
            PairingUiState::Failed { reason } => PairingUiStateDto::Failed { reason },
        }
    }
}

fn credential_from_dto(dto: CredentialDto) -> Result<MoatCredential, String> {
    let device_id: [u8; 16] = dto
        .device_id
        .try_into()
        .map_err(|_| "device_id must be 16 bytes".to_string())?;
    Ok(MoatCredential::new(&dto.did, &dto.device_name, device_id))
}

/// An enum rather than a message, because the same fact reads differently
/// on each side: a rendezvous nobody joined is "no device answered" to the
/// device that asked and "this expired before you answered" to the device
/// that was prompted. Each screen supplies its own words.
pub enum SyncFailureDto {
    /// Requester: nobody joined the rendezvous before it expired.
    NoAnswer,
    /// Responder: the request expired before this device answered it.
    RequestExpired,
    /// This device's user declined a sibling's request.
    Declined,
    /// The pair channel closed before the transfer finished.
    ChannelClosed { detail: String },
    /// The request could not be published to the ring at all.
    PublishFailed { detail: String },
}

impl From<moat_core::SyncFailure> for SyncFailureDto {
    fn from(f: moat_core::SyncFailure) -> Self {
        use moat_core::SyncFailure as F;
        match f {
            F::NoAnswer => SyncFailureDto::NoAnswer,
            F::RequestExpired => SyncFailureDto::RequestExpired,
            F::Declined => SyncFailureDto::Declined,
            F::ChannelClosed { detail } => SyncFailureDto::ChannelClosed { detail },
            F::PublishFailed { detail } => SyncFailureDto::PublishFailed { detail },
        }
    }
}

/// What a finished sync moved in each direction. See `moat_core::SyncTally`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncTallyDto {
    pub messages: u64,
    pub conversations: u64,
    pub sent_messages: u64,
    pub sent_conversations: u64,
}

impl From<moat_core::SyncTally> for SyncTallyDto {
    fn from(t: moat_core::SyncTally) -> Self {
        Self {
            messages: t.messages,
            conversations: t.conversations,
            sent_messages: t.sent_messages,
            sent_conversations: t.sent_conversations,
        }
    }
}

pub enum SyncRequestUiStateDto {
    /// No sync request in flight.
    Idle,
    /// Waiting on the rendezvous, in either role.
    AwaitingPeer,
    /// A sibling asked for history; this device's user has not decided.
    AwaitingApproval { device_name: String },
    /// Channel up, transfer running.
    Active,
    /// Transfer finished, with what it moved and where from.
    Complete {
        tally: SyncTallyDto,
        device_name: Option<String>,
    },
    /// Terminal failure, with the structured reason retained.
    Failed { reason: SyncFailureDto },
}

impl From<moat_core::SyncRequestUiState> for SyncRequestUiStateDto {
    fn from(s: moat_core::SyncRequestUiState) -> Self {
        use moat_core::SyncRequestUiState as S;
        match s {
            S::Idle => SyncRequestUiStateDto::Idle,
            S::AwaitingPeer => SyncRequestUiStateDto::AwaitingPeer,
            S::AwaitingApproval { device_name } => {
                SyncRequestUiStateDto::AwaitingApproval { device_name }
            }
            S::Active => SyncRequestUiStateDto::Active,
            S::Complete { tally, device_name } => SyncRequestUiStateDto::Complete {
                tally: tally.into(),
                device_name,
            },
            S::Failed { reason } => {
                SyncRequestUiStateDto::Failed { reason: reason.into() }
            }
        }
    }
}

/// This device's identity, which a pairing keeps for its steps.
pub struct PairIdentityDto {
    pub credential: CredentialDto,
    pub key_bundle: Vec<u8>,
    /// 32-byte X25519 stealth scan public key.
    pub stealth_pubkey: Vec<u8>,
}

/// One conversation's settled messages, for a transfer's `Hello`.
pub struct ConvHistoryDto {
    pub group_id: Vec<u8>,
    pub messages: Vec<SyncMessageDto>,
}

/// Mirrors `moat_core::PairChannelCommand`: host I/O, to be carried out in
/// order.
pub enum PairChannelCommandDto {
    /// Send `pair_offer` on an authenticated main WS to `drawbridge_url`.
    SendPairOffer { drawbridge_url: String, token: Vec<u8> },
    /// Send `pair_join` on an authenticated main WS to `drawbridge_url`.
    SendPairJoin { drawbridge_url: String, token: Vec<u8> },
    ConnectPair { url: String, token: Vec<u8> },
    SendFrame { data: Vec<u8> },
    /// Close the pair WS behind the frames already sent.
    ClosePair,
    /// Tear the pair WS down now, and stop resending any unacknowledged
    /// offer or join.
    DropPair,
    /// Publish to this device's repo and tell the relay; report a failure
    /// through `on_ring_publish_failed`.
    PublishRingEvent { tag: Vec<u8>, ciphertext: Vec<u8> },
    /// Load every conversation's settled history and hand it to
    /// `provide_history` with this token.
    LoadHistory { token: Vec<u8> },
    StoreMessages { conv_id: String, messages: Vec<SyncMessageDto> },
    SaveMlsState,
    SaveRingState,
    RingJoined { ring_id: Vec<u8> },
    DeviceAdmitted { ring_id: Vec<u8> },
    SiblingStealthLearned { device_id: Vec<u8>, scan_pubkey: Vec<u8> },
    TransferComplete { tally: SyncTallyDto },
    TransferFailed { detail: String, during_pairing: bool },
    Log { line: String },
}

impl From<moat_core::PairChannelCommand> for PairChannelCommandDto {
    fn from(c: moat_core::PairChannelCommand) -> Self {
        use moat_core::PairChannelCommand as C;
        match c {
            C::SendPairOffer { drawbridge_url, token } => Self::SendPairOffer { drawbridge_url, token: token.to_vec() },
            C::SendPairJoin { drawbridge_url, token } => Self::SendPairJoin { drawbridge_url, token: token.to_vec() },
            C::ConnectPair { url, token } => Self::ConnectPair { url, token: token.to_vec() },
            C::SendFrame { data } => Self::SendFrame { data },
            C::ClosePair => Self::ClosePair,
            C::DropPair => Self::DropPair,
            C::PublishRingEvent { tag, ciphertext } => {
                Self::PublishRingEvent { tag: tag.to_vec(), ciphertext }
            }
            C::LoadHistory { token } => Self::LoadHistory { token: token.to_vec() },
            C::StoreMessages { conv_id, messages } => Self::StoreMessages {
                conv_id,
                messages: messages.into_iter().map(Into::into).collect(),
            },
            C::SaveMlsState => Self::SaveMlsState,
            C::SaveRingState => Self::SaveRingState,
            C::RingJoined { ring_id } => Self::RingJoined { ring_id },
            C::DeviceAdmitted { ring_id } => Self::DeviceAdmitted { ring_id },
            C::SiblingStealthLearned { device_id, scan_pubkey } => Self::SiblingStealthLearned {
                device_id: device_id.to_vec(),
                scan_pubkey: scan_pubkey.to_vec(),
            },
            C::TransferComplete { tally } => Self::TransferComplete { tally: tally.into() },
            C::TransferFailed { detail, during_pairing } => {
                Self::TransferFailed { detail, during_pairing }
            }
            C::Log(line) => Self::Log { line },
        }
    }
}

/// `pair_new`'s code, and the commands that start its rendezvous.
pub struct PairNewDto {
    pub code: String,
    pub commands: Vec<PairChannelCommandDto>,
}

fn commands_dto(cmds: Vec<moat_core::PairChannelCommand>) -> Vec<PairChannelCommandDto> {
    cmds.into_iter().map(Into::into).collect()
}

fn token_from(token: &[u8]) -> Result<[u8; moat_core::PAIRING_TOKEN_LEN], String> {
    token.try_into().map_err(|_| "token must be 16 bytes".to_string())
}

fn device_id_from(device_id: &[u8]) -> Result<moat_core::DeviceId, String> {
    device_id.try_into().map_err(|_| "device_id must be 16 bytes".to_string())
}

/// Opaque handle to a `moat_core::PairChannelDriver`, the one owner of
/// this device's pair channel. Methods taking a session and ring run
/// against this device's local state; locks are taken session, ring, then
/// driver, the same order `RingDriverHandle` uses.
pub struct PairChannelHandle {
    inner: Mutex<moat_core::PairChannelDriver>,
}

impl PairChannelHandle {
    #[frb(sync)]
    pub fn new_driver() -> PairChannelHandle {
        PairChannelHandle { inner: Mutex::new(moat_core::PairChannelDriver::new()) }
    }

    fn with_env<T>(
        &self,
        session: &MoatSessionHandle,
        ring: &RingDriverHandle,
        now_ms: i64,
        f: impl FnOnce(&mut moat_core::PairChannelDriver, &mut moat_core::PairEnv<'_>) -> T,
    ) -> T {
        let mls = session.inner.lock().unwrap();
        let mut ring = ring.inner.lock().unwrap();
        let mut driver = self.inner.lock().unwrap();
        let mut env = moat_core::PairEnv { mls: &mls, ring: &mut ring, now_ms };
        f(&mut driver, &mut env)
    }

    #[frb(sync)]
    pub fn pairing_ui_state(&self) -> PairingUiStateDto {
        self.inner.lock().unwrap().pairing_ui_state().into()
    }

    #[frb(sync)]
    pub fn sync_request_ui_state(&self) -> SyncRequestUiStateDto {
        self.inner.lock().unwrap().sync_request_ui_state().into()
    }

    #[frb(sync)]
    pub fn is_transferring(&self) -> bool {
        self.inner.lock().unwrap().is_transferring()
    }

    /// The Drawbridge the live rendezvous is on, if there is one.
    #[frb(sync)]
    pub fn rendezvous_drawbridge_url(&self) -> Option<String> {
        self.inner.lock().unwrap().rendezvous_drawbridge_url().map(str::to_string)
    }

    #[frb(sync)]
    pub fn progress(&self) -> Option<SyncProgressDto> {
        self.inner.lock().unwrap().progress().map(Into::into)
    }

    /// New device: start a pairing on `drawbridge_url`, this device's Drawbridge; the code
    /// is what the screen shows, beside the Drawbridge.
    #[frb(sync)]
    pub fn pair_new(&self, identity: PairIdentityDto, drawbridge_url: String) -> Result<PairNewDto, String> {
        let identity = identity_from_dto(identity)?;
        let (code, cmds) = self
            .inner
            .lock()
            .unwrap()
            .pair_new(identity, &drawbridge_url)
            .map_err(|e| e.to_string())?;
        Ok(PairNewDto { code, commands: commands_dto(cmds) })
    }

    /// Existing device: enter a code, in its text or `moat-pair:` form, with
    /// the Drawbridge shown beside it (a `moat-pair:` URI names its own).
    #[frb(sync)]
    pub fn pair_confirm(
        &self,
        identity: PairIdentityDto,
        code: String,
        drawbridge_url: Option<String>,
    ) -> Result<Vec<PairChannelCommandDto>, String> {
        let identity = identity_from_dto(identity)?;
        self.inner
            .lock()
            .unwrap()
            .pair_confirm(identity, &code, drawbridge_url.as_deref())
            .map(commands_dto)
            .map_err(|e| e.to_string())
    }

    /// Existing device: approve the pending `Enroll`. A failure while
    /// approving fails the pairing rather than returning `Err`.
    pub fn pair_approve(
        &self,
        session: &MoatSessionHandle,
        ring: &RingDriverHandle,
        now_ms: i64,
        sibling_stealth: Vec<SiblingStealthDto>,
    ) -> Result<Vec<PairChannelCommandDto>, String> {
        let sibling_stealth = to_core_sibling_stealth(sibling_stealth)?;
        self.with_env(session, ring, now_ms, |d, env| d.pair_approve(env, &sibling_stealth))
            .map(commands_dto)
            .map_err(|e| e.to_string())
    }

    #[frb(sync)]
    pub fn pair_reject(&self) -> Result<Vec<PairChannelCommandDto>, String> {
        self.inner.lock().unwrap().pair_reject().map(commands_dto).map_err(|e| e.to_string())
    }

    #[frb(sync)]
    pub fn pair_cancel(&self) -> Result<Vec<PairChannelCommandDto>, String> {
        self.inner.lock().unwrap().pair_cancel().map(commands_dto).map_err(|e| e.to_string())
    }

    /// Ask the user's other devices for history; `target` names one.
    /// `key_bundle` seals the request to the ring; `drawbridge_url` is this device's
    /// Drawbridge, where the rendezvous happens.
    pub fn sync_request(
        &self,
        session: &MoatSessionHandle,
        ring: &RingDriverHandle,
        now_ms: i64,
        key_bundle: Vec<u8>,
        target: Option<Vec<u8>>,
        drawbridge_url: String,
    ) -> Result<Vec<PairChannelCommandDto>, String> {
        let target = target.as_deref().map(device_id_from).transpose()?;
        self.with_env(session, ring, now_ms, |d, env| {
            d.sync_request(env, &key_bundle, target, &drawbridge_url)
        })
            .map(commands_dto)
            .map_err(|e| e.to_string())
    }

    /// Offer this device's history to `target`.
    pub fn sync_offer(
        &self,
        session: &MoatSessionHandle,
        ring: &RingDriverHandle,
        now_ms: i64,
        key_bundle: Vec<u8>,
        target: Vec<u8>,
        drawbridge_url: String,
    ) -> Result<Vec<PairChannelCommandDto>, String> {
        let target = device_id_from(&target)?;
        self.with_env(session, ring, now_ms, |d, env| {
            d.sync_offer(env, &key_bundle, target, &drawbridge_url)
        })
            .map(commands_dto)
            .map_err(|e| e.to_string())
    }

    #[frb(sync)]
    pub fn sync_accept(&self) -> Result<Vec<PairChannelCommandDto>, String> {
        self.inner.lock().unwrap().sync_accept().map(commands_dto).map_err(|e| e.to_string())
    }

    #[frb(sync)]
    pub fn sync_decline(&self) -> Result<(), String> {
        self.inner.lock().unwrap().sync_decline().map_err(|e| e.to_string())
    }

    /// A sibling's `ring.msg` payload. `sender_name` must come from the
    /// sender's MLS leaf credential, `sender_drawbridge_url` from the sender's
    /// `drawbridgeConfig` record.
    #[frb(sync)]
    pub fn on_ring_msg(
        &self,
        payload: Vec<u8>,
        sender_name: String,
        sender_drawbridge_url: String,
        own_device_id: Vec<u8>,
        now_ms: i64,
    ) -> Result<Vec<PairChannelCommandDto>, String> {
        let msg = moat_core::decode_ring_msg(&payload).map_err(|e| e.to_string())?;
        let own = device_id_from(&own_device_id)?;
        Ok(commands_dto(
            self.inner
                .lock()
                .unwrap()
                .on_ring_msg(msg, sender_name, &sender_drawbridge_url, &own, now_ms),
        ))
    }

    #[frb(sync)]
    pub fn on_ring_publish_failed(
        &self,
        tag: Vec<u8>,
        detail: String,
    ) -> Result<Vec<PairChannelCommandDto>, String> {
        let tag: [u8; 16] = tag.try_into().map_err(|_| "tag must be 16 bytes".to_string())?;
        Ok(commands_dto(self.inner.lock().unwrap().on_ring_publish_failed(&tag, detail)))
    }

    /// The main WS to `drawbridge_url` (re)authenticated.
    #[frb(sync)]
    pub fn on_drawbridge_connected(&self, drawbridge_url: String) -> Vec<PairChannelCommandDto> {
        commands_dto(self.inner.lock().unwrap().on_drawbridge_connected(&drawbridge_url))
    }

    /// `pair_ready` from `drawbridge_url`.
    #[frb(sync)]
    pub fn on_pair_ready(
        &self,
        drawbridge_url: String,
        token: Vec<u8>,
        url: String,
    ) -> Vec<PairChannelCommandDto> {
        commands_dto(self.inner.lock().unwrap().on_pair_ready(&drawbridge_url, &token, url))
    }

    /// The pair WS for `token` reached `paired`.
    pub fn on_paired(
        &self,
        session: &MoatSessionHandle,
        ring: &RingDriverHandle,
        now_ms: i64,
        token: Vec<u8>,
    ) -> Vec<PairChannelCommandDto> {
        commands_dto(self.with_env(session, ring, now_ms, |d, env| d.on_paired(env, &token)))
    }

    /// A binary frame from the pair WS for `token`.
    pub fn on_frame(
        &self,
        session: &MoatSessionHandle,
        ring: &RingDriverHandle,
        now_ms: i64,
        token: Vec<u8>,
        data: Vec<u8>,
    ) -> Vec<PairChannelCommandDto> {
        commands_dto(self.with_env(session, ring, now_ms, |d, env| d.on_frame(env, &token, data)))
    }

    pub fn provide_history(
        &self,
        session: &MoatSessionHandle,
        ring: &RingDriverHandle,
        now_ms: i64,
        token: Vec<u8>,
        history: Vec<ConvHistoryDto>,
    ) -> Result<Vec<PairChannelCommandDto>, String> {
        let token = token_from(&token)?;
        let history = history
            .into_iter()
            .map(|h| moat_core::ConvHistory {
                group_id: h.group_id,
                messages: h.messages.into_iter().map(Into::into).collect(),
            })
            .collect();
        Ok(commands_dto(
            self.with_env(session, ring, now_ms, |d, env| d.provide_history(env, &token, history)),
        ))
    }

    /// The pair WS for `token` closed or failed to connect.
    #[frb(sync)]
    pub fn on_pair_closed(&self, token: Vec<u8>, reason: String) -> Vec<PairChannelCommandDto> {
        commands_dto(self.inner.lock().unwrap().on_pair_closed(Some(&token), reason))
    }

    /// Expire an unanswered sync request.
    #[frb(sync)]
    pub fn tick(&self, now_ms: i64) -> Vec<PairChannelCommandDto> {
        commands_dto(self.inner.lock().unwrap().tick(now_ms))
    }
}

fn identity_from_dto(identity: PairIdentityDto) -> Result<moat_core::PairIdentity, String> {
    Ok(moat_core::PairIdentity {
        credential: credential_from_dto(identity.credential)?,
        key_bundle: identity.key_bundle,
        stealth_pubkey: identity
            .stealth_pubkey
            .try_into()
            .map_err(|_| "stealth_pubkey must be 32 bytes".to_string())?,
    })
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
        if let Ok(epoch) = result {
            assert!(epoch.is_none());
        }
        // Err is also acceptable.
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
    fn test_pad_unpad_roundtrip() {
        let plaintext = b"Hello, world!".to_vec();
        let padded = pad_to_bucket(plaintext.clone()).unwrap();

        assert_eq!(padded.len(), 512);
        let unpadded = unpad(padded);
        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_pad_bucket_sizes() {
        let small = pad_to_bucket(vec![0x42; 100]).unwrap();
        assert_eq!(small.len(), 512);

        let standard = pad_to_bucket(vec![0x42; 600]).unwrap();
        assert_eq!(standard.len(), 1024);

        let large = pad_to_bucket(vec![0x42; 2000]).unwrap();
        assert_eq!(large.len(), 4096);
    }

    #[test]
    fn test_pad_empty() {
        let padded = pad_to_bucket(vec![]).unwrap();
        assert_eq!(padded.len(), 512);
        let unpadded = unpad(padded);
        assert!(unpadded.is_empty());
    }

    /// The bucket ladder has a ceiling; above it `pad_to_bucket` reports
    /// rather than producing a frame of some other size.
    #[test]
    fn test_pad_rejects_oversized() {
        assert!(pad_to_bucket(vec![0x42; 20_000]).is_err());
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

    /// A retry must republish under the id its first attempt used, and a
    /// first send without one still gets a fresh id.
    #[test]
    fn a_message_event_keeps_the_id_it_is_given() {
        let dto = |message_id| EventDto {
            kind: EventKindDto::Message,
            group_id: vec![1, 2, 3],
            epoch: 1,
            payload: b"test".to_vec(),
            message_id,
        };
        assert_eq!(dto(Some(vec![7u8; 16])).into_core().message_id, Some(vec![7u8; 16]));
        assert_eq!(dto(None).into_core().message_id.map(|id| id.len()), Some(16));
    }

    #[test]
    fn test_reaction_dto_roundtrip() {
        let target_id = vec![0xAB; 16];
        // Create a reaction via core and convert to DTO
        let core_reaction = Event::reaction(vec![1, 2, 3], 5, &target_id, "👍");
        assert!(matches!(
            core_reaction.kind,
            EventKind::Modifier(ModifierKind::Reaction)
        ));

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
        assert!(matches!(
            restored_core.kind,
            EventKind::Modifier(ModifierKind::Reaction)
        ));
        let restored_rp = restored_core.reaction_payload().unwrap();
        assert_eq!(restored_rp.emoji, "👍");
        assert_eq!(restored_rp.target_message_id, target_id);
    }

    #[test]
    fn test_sign_drawbridge_challenge() {
        let handle = MoatSessionHandle::new_session();
        let kp = handle
            .generate_key_package("did:plc:alice".into(), "Desktop".into())
            .unwrap();

        let message = b"nonce123\nwss://relay.example.com/ws\n1700000000\n".to_vec();
        let result = sign_drawbridge_challenge(kp.key_bundle.clone(), message.clone())
            .expect("signing should succeed");

        assert_eq!(result.signature.len(), 64);
        assert_eq!(result.public_key.len(), 32);

        // Verify signature with ed25519_dalek
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&result.public_key.try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(&result.signature.try_into().unwrap());
        vk.verify(&message, &sig).expect("signature should verify");
    }

    #[test]
    fn test_sign_drawbridge_challenge_wrong_message_fails() {
        let handle = MoatSessionHandle::new_session();
        let kp = handle
            .generate_key_package("did:plc:bob".into(), "Phone".into())
            .unwrap();

        let result = sign_drawbridge_challenge(kp.key_bundle, b"correct".to_vec()).unwrap();

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&result.public_key.try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(&result.signature.try_into().unwrap());
        assert!(vk.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn test_sign_drawbridge_challenge_invalid_bundle() {
        let result = sign_drawbridge_challenge(b"not-json".to_vec(), b"msg".to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_event_maps_to_unknown_dto() {
        let event = Event {
            kind: EventKind::Unknown("future.thing".into()),
            group_id: vec![1, 2, 3],
            epoch: 0,
            payload: b"opaque".to_vec(),
            message_id: None,
            prev_event_hash: None,
            epoch_fingerprint: None,
            sender_device_id: None,
        };
        let dto = EventDto::from_core(event);
        assert!(matches!(dto.kind, EventKindDto::Unknown));
        assert_eq!(dto.group_id, vec![1, 2, 3]);
        assert_eq!(dto.payload, b"opaque");
    }
}

#[cfg(test)]
mod ring_sync_ffi_tests {
    use super::*;

    #[test]
    fn ring_driver_state_json_roundtrip() {
        let h = RingDriverHandle::new_empty();
        let json = h.to_state_json().unwrap();
        let restored = RingDriverHandle::from_state_json(json).unwrap();
        assert!(restored.ring_group_id().is_none());
        assert!(restored.own_events_cursor().is_none());
    }

    #[test]
    fn ring_driver_tick_no_inputs_returns_no_commands() {
        let session = MoatSessionHandle::new_session();
        let kp = session
            .generate_key_package("did:plc:alice".into(), "Phone".into())
            .unwrap();
        // `replenish_own_key_packages` runs on every tick regardless of ring
        // membership and tops up to `KP_SELF_POOL_TARGET` (4) live published
        // packages (see its doc comment in device_ring.rs) — so the pool
        // snapshot needs 4 still-live packages, not just 1, for the tick to
        // go quiet. Mint 3 more sharing the same signing identity.
        let mut key_packages = vec![kp.key_package];
        for _ in 0..3 {
            let fresh = session
                .replenish_key_package(
                    "did:plc:alice".into(),
                    "Phone".into(),
                    kp.key_bundle.clone(),
                )
                .unwrap();
            key_packages.push(fresh);
        }
        let driver = RingDriverHandle::new_empty();
        let inputs = TickInputsDto {
            key_packages,
            sibling_stealth: vec![],
            own_events: vec![],
            stealth_privkey: vec![0u8; 32],
            did: "did:plc:alice".into(),
            device_name: "Phone".into(),
            key_bundle: kp.key_bundle,
            now_ms: 1_000_000,
        };
        let cmds = driver.tick(&session, inputs).unwrap();
        assert!(cmds.is_empty());
    }

    #[test]
    fn ring_driver_tick_rejects_bad_stealth_privkey_len() {
        let session = MoatSessionHandle::new_session();
        let kp = session
            .generate_key_package("did:plc:alice".into(), "Phone".into())
            .unwrap();
        let driver = RingDriverHandle::new_empty();
        let inputs = TickInputsDto {
            key_packages: vec![],
            sibling_stealth: vec![],
            own_events: vec![],
            stealth_privkey: vec![0u8; 31],
            did: "did:plc:alice".into(),
            device_name: "Phone".into(),
            key_bundle: kp.key_bundle,
            now_ms: 0,
        };
        let err = driver.tick(&session, inputs).unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn sync_message_dto_roundtrip() {
        let core = SyncMessage {
            rkey: "rk1".into(),
            message_id: Some(vec![1u8; 16]),
            sender_did: "did:plc:bob".into(),
            sender_device_name: "phone".into(),
            timestamp_ms: 1234,
            content: "hi".into(),
            blob_uri: Some("at://x".into()),
            blob_key: Some(vec![2u8; 32]),
            blob_ciphertext_hash: Some(vec![3u8; 32]),
            blob_ciphertext_size: Some(99),
            blob_content_hash: Some(vec![4u8; 32]),
            blob_mime: Some("image/png".into()),
            blob_width: Some(100),
            blob_height: Some(200),
            // Non-default so the round trip actually covers them: both
            // were dropped by the Dart mapping until they were carried
            // here, and a receiving device cannot recover either from the
            // PDS.
            blob_thumbhash: Some(vec![5u8; 24]),
            reactions: vec![moat_core::SyncReaction {
                emoji: "👍".into(),
                sender_did: "did:plc:bob".into(),
            }],
        };
        let dto: SyncMessageDto = core.clone().into();
        let back: SyncMessage = dto.into();
        assert_eq!(back, core);
    }
}

#[cfg(test)]
mod blob_image_tests {
    use super::*;

    fn make_png_bytes(w: u32, h: u32) -> Vec<u8> {
        use image::{DynamicImage, ImageFormat};
        use std::io::Cursor;
        let img = DynamicImage::new_rgba8(w, h);
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .unwrap();
        buf
    }

    #[test]
    fn blob_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello, encrypted blob!".to_vec();
        let result = blob_encrypt(plaintext.clone()).unwrap();
        let decrypted = blob_decrypt(
            result.blob,
            result.key,
            result.ciphertext_hash,
            result.content_hash,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn blob_decrypt_wrong_key_returns_error() {
        let plaintext = b"test data".to_vec();
        let result = blob_encrypt(plaintext).unwrap();
        let wrong_key = vec![0u8; 32];
        let err = blob_decrypt(result.blob, wrong_key, result.ciphertext_hash, result.content_hash);
        assert!(err.is_err());
    }

    #[test]
    fn blob_decrypt_corrupted_ciphertext_hash_returns_error() {
        let plaintext = b"test data".to_vec();
        let result = blob_encrypt(plaintext).unwrap();
        let wrong_hash = vec![0u8; 32];
        let err = blob_decrypt(result.blob, result.key, wrong_hash, result.content_hash);
        assert!(err.is_err());
    }

    #[test]
    fn process_image_small_png() {
        let png = make_png_bytes(32, 32);
        let result = process_image_for_send(png).unwrap();
        assert_eq!(result.mime_type, "image/png");
        assert_eq!(result.width, 32);
        assert_eq!(result.height, 32);
        assert!(!result.thumbhash.is_empty());
        assert!(!result.image_bytes.is_empty());
    }

    #[test]
    fn process_image_large_resized() {
        let png = make_png_bytes(4096, 2048);
        let result = process_image_for_send(png).unwrap();
        assert!(result.width <= 2048);
        assert!(result.height <= 2048);
    }

    #[test]
    fn process_image_rejects_non_image_bytes() {
        let err = process_image_for_send(b"not an image".to_vec());
        assert!(err.is_err());
    }

    #[test]
    fn decode_thumbhash_roundtrip() {
        let png = make_png_bytes(32, 32);
        let processed = process_image_for_send(png).unwrap();
        let decoded = decode_thumbhash(processed.thumbhash).unwrap();
        assert!(decoded.width > 0 && decoded.height > 0);
        assert_eq!(decoded.rgba.len(), (decoded.width * decoded.height * 4) as usize);
    }
}

#[cfg(test)]
mod proptest_drawbridge {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use proptest::prelude::*;

    /// Helper: create a fresh key bundle for each test case.
    fn fresh_key_bundle() -> Vec<u8> {
        let handle = MoatSessionHandle::new_session();
        let kp = handle
            .generate_key_package("did:plc:proptest".into(), "device".into())
            .unwrap();
        kp.key_bundle
    }

    proptest! {
        /// For any random message, signing produces a 64-byte signature that
        /// verifies against the returned 32-byte public key.
        #[test]
        fn sign_produces_valid_signature(message in proptest::collection::vec(any::<u8>(), 1..256)) {
            let kb = fresh_key_bundle();
            let result = sign_drawbridge_challenge(kb, message.clone())
                .expect("signing should succeed");

            prop_assert_eq!(result.signature.len(), 64);
            prop_assert_eq!(result.public_key.len(), 32);

            let vk = VerifyingKey::from_bytes(&result.public_key.try_into().unwrap()).unwrap();
            let sig = Signature::from_bytes(&result.signature.try_into().unwrap());
            prop_assert!(vk.verify(&message, &sig).is_ok());
        }

        /// The same key bundle always produces the same public key.
        #[test]
        fn same_bundle_same_pubkey(
            msg_a in proptest::collection::vec(any::<u8>(), 1..64),
            msg_b in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let kb = fresh_key_bundle();
            let res_a = sign_drawbridge_challenge(kb.clone(), msg_a).unwrap();
            let res_b = sign_drawbridge_challenge(kb, msg_b).unwrap();
            prop_assert_eq!(res_a.public_key, res_b.public_key);
        }

        /// Different key bundles produce different public keys.
        #[test]
        fn different_bundles_different_pubkeys(_ in 0..50u32) {
            let kb_a = fresh_key_bundle();
            let kb_b = fresh_key_bundle();
            let res_a = sign_drawbridge_challenge(kb_a, b"msg".to_vec()).unwrap();
            let res_b = sign_drawbridge_challenge(kb_b, b"msg".to_vec()).unwrap();
            prop_assert_ne!(res_a.public_key, res_b.public_key);
        }

        /// Signature does not verify against a different message.
        #[test]
        fn signature_rejects_wrong_message(
            correct in proptest::collection::vec(any::<u8>(), 1..128),
            wrong in proptest::collection::vec(any::<u8>(), 1..128),
        ) {
            prop_assume!(correct != wrong);
            let kb = fresh_key_bundle();
            let result = sign_drawbridge_challenge(kb, correct).unwrap();

            let vk = VerifyingKey::from_bytes(&result.public_key.try_into().unwrap()).unwrap();
            let sig = Signature::from_bytes(&result.signature.try_into().unwrap());
            prop_assert!(vk.verify(&wrong, &sig).is_err());
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod push_tests {
    use super::*;
    use moat_core::{MessagePayload, TextMessage};

    /// Helper: set up a two-party group (Alice creator, Bob member) and return the
    /// group_id, Alice's key bundle, and both session handles.
    fn two_party_group() -> (Vec<u8>, Vec<u8>, MoatSessionHandle, MoatSessionHandle) {
        let alice = MoatSessionHandle::new_session();
        let alice_kp = alice
            .generate_key_package("did:plc:alice".into(), "Desktop".into())
            .unwrap();
        let group_id = alice
            .create_group("did:plc:alice".into(), "Desktop".into(), alice_kp.key_bundle.clone())
            .unwrap();

        let bob = MoatSessionHandle::new_session();
        let bob_kp = bob
            .generate_key_package("did:plc:bob".into(), "Phone".into())
            .unwrap();

        let welcome = alice
            .add_member(group_id.clone(), alice_kp.key_bundle.clone(), bob_kp.key_package)
            .unwrap();
        bob.process_welcome(welcome.welcome).unwrap();

        (group_id, alice_kp.key_bundle, alice, bob)
    }

    #[test]
    fn test_decrypt_push_payload_text_message() {
        let (group_id, alice_kb, alice, bob) = two_party_group();

        // Alice encrypts a structured short-text message.
        let payload = serde_json::to_vec(&MessagePayload::ShortText(TextMessage {
            text: "Hello, Bob!".into(),
        }))
        .unwrap();
        let encrypted = alice
            .encrypt_event(
                group_id.clone(),
                alice_kb,
                EventDto {
                    kind: EventKindDto::Message,
                    group_id: group_id.clone(),
                    epoch: 0,
                    payload,
                    message_id: None,
                },
            )
            .unwrap();

        // Save Bob's state to a temp file.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let state_path = tmp.path().to_str().unwrap().to_string();
        let bob_state_before = bob.export_state().unwrap();
        std::fs::write(&state_path, &bob_state_before).unwrap();

        // Decrypt via push path.
        let result = decrypt_push_payload(
            state_path.clone(),
            vec![group_id.clone()],
            encrypted.tag,
            encrypted.ciphertext,
        )
        .expect("decrypt_push_payload should succeed");

        assert_eq!(result.group_id, group_id);
        assert_eq!(result.sender_did, Some("did:plc:alice".to_string()));
        assert_eq!(result.plaintext_preview, Some("Hello, Bob!".to_string()));
        assert!(result.message_id.is_some());
        assert_eq!(result.message_id.as_ref().unwrap().len(), 16);

        // State file must have been updated (seen counter advanced).
        let bob_state_after = std::fs::read(&state_path).unwrap();
        assert_ne!(bob_state_after, bob_state_before);
    }

    #[test]
    fn test_decrypt_push_payload_tag_not_found() {
        let (group_id, _alice_kb, _alice, bob) = two_party_group();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let state_path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(&state_path, bob.export_state().unwrap()).unwrap();

        // Valid group ID but a tag that won't match any candidate.
        let err = decrypt_push_payload(
            state_path,
            vec![group_id],
            vec![0u8; 16], // wrong tag
            vec![0u8; 64],
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("tag not matched"));
    }

    #[test]
    fn test_decrypt_push_payload_wrong_ciphertext() {
        let (group_id, alice_kb, alice, bob) = two_party_group();

        // Alice encrypts a message to get a valid tag.
        let encrypted = alice
            .encrypt_event(
                group_id.clone(),
                alice_kb,
                EventDto {
                    kind: EventKindDto::Message,
                    group_id: group_id.clone(),
                    epoch: 0,
                    payload: b"test".to_vec(),
                    message_id: None,
                },
            )
            .unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let state_path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(&state_path, bob.export_state().unwrap()).unwrap();

        // Correct tag, corrupted ciphertext → decrypt error.
        let err = decrypt_push_payload(
            state_path,
            vec![group_id],
            encrypted.tag,
            vec![0u8; 64], // garbage
        );
        assert!(err.is_err());
    }

    #[test]
    fn test_push_media_label() {
        assert_eq!(push_media_label(None), "📷 Photo");
        assert_eq!(push_media_label(Some("image/jpeg")), "📷 Photo");
        assert_eq!(push_media_label(Some("image/png")), "📷 Photo");
        assert_eq!(push_media_label(Some("image/gif")), "🎞️ GIF");
        assert_eq!(push_media_label(Some("video/mp4")), "🎬 Video");
        assert_eq!(push_media_label(Some("video/webm")), "🎬 Video");
    }
}

#[cfg(test)]
mod pair_channel_ffi_tests {
    use super::*;

    const TOKEN_UNSET: &str = "the rendezvous token is set once pair_new has run";

    struct Device {
        session: MoatSessionHandle,
        ring: RingDriverHandle,
        identity: PairIdentityDto,
        driver: PairChannelHandle,
        token: std::cell::RefCell<Option<Vec<u8>>>,
    }

    impl Device {
        fn new(name: &str) -> Self {
            let session = MoatSessionHandle::new_session();
            let kp = session.generate_key_package("did:plc:alice".into(), name.into()).unwrap();
            let identity = PairIdentityDto {
                credential: CredentialDto {
                    did: "did:plc:alice".into(),
                    device_id: session.device_id(),
                    device_name: name.into(),
                },
                key_bundle: kp.key_bundle,
                stealth_pubkey: vec![name.len() as u8; 32],
            };
            Device {
                session,
                ring: RingDriverHandle::new_empty(),
                identity,
                driver: PairChannelHandle::new_driver(),
                token: Default::default(),
            }
        }

        fn identity(&self) -> PairIdentityDto {
            PairIdentityDto {
                credential: CredentialDto {
                    did: self.identity.credential.did.clone(),
                    device_id: self.identity.credential.device_id.clone(),
                    device_name: self.identity.credential.device_name.clone(),
                },
                key_bundle: self.identity.key_bundle.clone(),
                stealth_pubkey: self.identity.stealth_pubkey.clone(),
            }
        }

        fn token(&self) -> Vec<u8> {
            self.token.borrow().clone().expect(TOKEN_UNSET)
        }

        fn on_paired(&self) -> Vec<PairChannelCommandDto> {
            self.driver.on_paired(&self.session, &self.ring, 0, self.token())
        }

        fn on_frame(&self, data: Vec<u8>) -> Vec<PairChannelCommandDto> {
            self.driver.on_frame(&self.session, &self.ring, 0, self.token(), data)
        }

        /// Frames to hand to the peer, answering history requests with an
        /// empty history on the way.
        fn frames(&self, cmds: Vec<PairChannelCommandDto>) -> Vec<Vec<u8>> {
            let mut frames = Vec::new();
            for cmd in cmds {
                match cmd {
                    PairChannelCommandDto::SendFrame { data } => frames.push(data),
                    PairChannelCommandDto::LoadHistory { token } => {
                        let cmds = self
                            .driver
                            .provide_history(&self.session, &self.ring, 0, token, vec![])
                            .unwrap();
                        frames.extend(self.frames(cmds));
                    }
                    _ => {}
                }
            }
            frames
        }
    }

    /// Deliver frames back and forth until neither side has more to say.
    fn exchange(a: &Device, b: &Device, mut to_b: Vec<Vec<u8>>) {
        let mut to_a = Vec::new();
        while !to_a.is_empty() || !to_b.is_empty() {
            for frame in std::mem::take(&mut to_b) {
                to_a.extend(b.frames(b.on_frame(frame)));
            }
            for frame in std::mem::take(&mut to_a) {
                to_b.extend(a.frames(a.on_frame(frame)));
            }
        }
    }

    /// The whole pairing, and the transfer it hands on to, over the FFI.
    #[test]
    fn pairing_converges_via_ffi() {
        let phone = Device::new("Alice's Phone");
        let laptop = Device::new("Alice's Laptop");

        let started = phone.driver.pair_new(phone.identity(), "wss://drawbridge.example.com/ws".into()).unwrap();
        let token = started
            .commands
            .iter()
            .find_map(|c| match c {
                PairChannelCommandDto::SendPairOffer { token, .. } => Some(token.clone()),
                _ => None,
            })
            .expect("pair_new must send an offer");
        laptop
            .driver
            .pair_confirm(laptop.identity(), started.code, Some("wss://drawbridge.example.com/ws".into()))
            .unwrap();
        for device in [&phone, &laptop] {
            *device.token.borrow_mut() = Some(token.clone());
            let cmds = device.driver.on_pair_ready(
                "wss://drawbridge.example.com/ws".into(),
                token.clone(),
                "wss://drawbridge.example.com/pair".into(),
            );
            assert!(matches!(cmds.as_slice(), [PairChannelCommandDto::ConnectPair { .. }]));
        }

        let enroll = phone.frames(phone.on_paired());
        assert!(laptop.frames(laptop.on_paired()).is_empty());
        exchange(&phone, &laptop, enroll);
        assert!(matches!(
            laptop.driver.pairing_ui_state(),
            PairingUiStateDto::AwaitingApproval { .. }
        ));

        let approved = laptop
            .driver
            .pair_approve(&laptop.session, &laptop.ring, 0, vec![])
            .unwrap();
        exchange(&laptop, &phone, laptop.frames(approved));

        for device in [&phone, &laptop] {
            assert!(matches!(device.driver.pairing_ui_state(), PairingUiStateDto::Done { .. }));
            assert!(!device.driver.is_transferring());
        }
        assert!(phone.ring.ring_group_id().is_some());
        assert_eq!(phone.ring.ring_group_id(), laptop.ring.ring_group_id());
    }
}
