use flutter_rust_bridge::frb;
use moat_core::{
    self, ControlKind, EncryptResult, Event, EventKind, MoatCredential, MoatSession, ModifierKind,
    ReactionPayload as CoreReactionPayload, SenderInfo, WelcomeResult,
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

    /// Check if a DID already has a device in the group.
    #[frb(sync)]
    pub fn is_did_in_group(&self, group_id: Vec<u8>, did: String) -> Result<bool, String> {
        self.inner
            .lock()
            .unwrap()
            .is_did_in_group(&group_id, &did)
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
                Event::message_from_bytes(self.group_id, self.epoch, &self.payload)
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
                EventKind::Modifier(_) | EventKind::Control(_) | EventKind::Unknown(_) => {
                    EventKindDto::Unknown
                }
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

/// Sign a Drawbridge challenge with the Ed25519 identity key from a key bundle.
///
/// Returns (signature_bytes, public_key_bytes) as raw bytes (64 and 32 bytes).
/// The caller is responsible for base64-encoding for JSON transport.
///
/// `message` is typically `"{nonce}\n{relay_url}\n{timestamp}\n"`.
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

/// Result of signing a Drawbridge challenge.
pub struct DrawbridgeChallengeSignature {
    /// Ed25519 signature (64 bytes)
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes)
    pub public_key: Vec<u8>,
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

// --- Blob crypto and image processing ---

/// Encrypt a blob. Returns encrypted bytes and metadata for ExternalBlob.
pub fn blob_encrypt(plaintext: Vec<u8>) -> Result<BlobEncryptResult, String> {
    moat_core::blob_encrypt(&plaintext)
        .map(|(blob, key, ciphertext_hash, content_hash)| BlobEncryptResult {
            blob,
            key: key.to_vec(),
            ciphertext_hash,
            content_hash,
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

        assert_eq!(padded.len(), 512);
        let unpadded = unpad(padded);
        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_pad_bucket_sizes() {
        let small = pad_to_bucket(vec![0x42; 100]);
        assert_eq!(small.len(), 512);

        let standard = pad_to_bucket(vec![0x42; 600]);
        assert_eq!(standard.len(), 1024);

        let large = pad_to_bucket(vec![0x42; 2000]);
        assert_eq!(large.len(), 4096);
    }

    #[test]
    fn test_pad_empty() {
        let padded = pad_to_bucket(vec![]);
        assert_eq!(padded.len(), 512);
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
