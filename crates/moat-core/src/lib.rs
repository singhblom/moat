//! moat-core: Pure MLS logic for Moat encrypted messenger
//!
//! This crate provides MLS operations for the Moat encrypted messenger.
//!
//! # Main Types
//!
//! - [`MoatSession`] - Holds a persistent provider for MLS operations
//! - [`MoatCredential`] - Structured credential containing DID and device name
//!
//! # Example
//!
//! ```
//! use moat_core::{MoatSession, MoatCredential};
//!
//! let session = MoatSession::new();
//!
//! let credential = MoatCredential::new("did:plc:alice123", "My Laptop", [0u8; 16]);
//! let (key_package, key_bundle) = session.generate_key_package(&credential).unwrap();
//! let group_id = session.create_group(&credential, &key_bundle).unwrap();
//!
//! // Caller persists state however they choose
//! let state = session.export_state().unwrap();
//! ```

pub mod blob;
pub(crate) mod credential;
pub(crate) mod device_ring;
pub mod digest;
pub(crate) mod error;
pub(crate) mod event;
pub mod message;
pub(crate) mod padding;
pub(crate) mod stealth;
pub(crate) mod storage;
pub(crate) mod tag;

pub mod api;

use openmls::framing::MlsMessageBodyIn;
use openmls::prelude::tls_codec::{Deserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

// Disambiguate from openmls::prelude::* and make accessible as moat_core::X
pub use crate::credential::MoatCredential;
pub use crate::error::{Error, ErrorCode, Result};
pub use crate::device_ring::{
    classify_group_kind, decode_coord_msg, encode_coord_msg, reconcile_rings, CoordGroupResult,
    CoordMsg, GroupKind, ReconcileDecision,
};
pub use crate::event::{
    ControlKind, DecryptOutcome, Event, EventKind, MessageKind, ModifierKind, ReactionPayload,
    SenderInfo, TranscriptWarning,
};
pub use crate::message::{
    ExternalBlob, LongTextMessage, MediaMessage, MessageBodyKind, MessagePayload,
    ParsedMessagePayload, TextMessage, MEDIUM_TEXT_MAX_BYTES, SHORT_TEXT_MAX_BYTES,
};
pub use crate::blob::{blob_decrypt, blob_encrypt};
pub use crate::padding::{pad_to_bucket, unpad, Bucket};
pub use crate::stealth::{encrypt_for_stealth, generate_stealth_keypair, try_decrypt_stealth};
pub(crate) use crate::storage::MoatProvider;
pub use crate::tag::{
    derive_event_tag, generate_candidate_tags, prior_epoch_gap_limit, MAX_PRIOR_EPOCHS,
    TAG_EXPORT_SECRET_LABEL, TAG_EXPORT_SECRET_LEN, TAG_GAP_LIMIT,
};
pub use crate::digest::{diff_anchors, DigestAnchor, DiffRange};

/// The ciphersuite used by Moat
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Serialized key bundle containing both key package and private key
#[serde_as]
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
pub struct KeyBundle {
    #[serde_as(as = "Base64")]
    pub key_package: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub init_private_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub encryption_private_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signature_key: Vec<u8>,
    /// Raw Ed25519 private key seed (32 bytes). Used for Drawbridge challenge-response auth.
    #[serde_as(as = "Base64")]
    pub signature_private_key: Vec<u8>,
}

/// Result of creating a welcome message for a new member
#[derive(Debug)]
pub struct WelcomeResult {
    pub new_group_state: Vec<u8>,
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
    pub group_id: Vec<u8>,
}

/// Result of encrypting an event
pub struct EncryptResult {
    pub new_group_state: Vec<u8>,
    pub tag: [u8; 16],
    pub ciphertext: Vec<u8>,
    /// The message_id assigned to the event (16 bytes for Message/Reaction, None otherwise)
    pub message_id: Option<Vec<u8>>,
}

/// Result of decrypting an event
#[derive(Debug)]
pub struct DecryptResult {
    pub new_group_state: Vec<u8>,
    pub event: Event,
    /// Information about the sender (extracted from their MLS credential)
    pub sender: Option<SenderInfo>,
}

/// Result of removing a member from a group
pub struct RemoveResult {
    /// The commit message to broadcast to other members
    pub commit: Vec<u8>,
    /// The group ID
    pub group_id: Vec<u8>,
}


/// Magic bytes for versioned state format.
const STATE_MAGIC: &[u8; 4] = b"MOAT";

/// Current state format version.
const STATE_VERSION: u16 = 5;

/// Size of the state header: 4 (magic) + 2 (version) + 16 (device_id) = 22 bytes.
const STATE_HEADER_SIZE: usize = 4 + 2 + 16;

/// Label for epoch fingerprint derivation via MLS export_secret.
const EPOCH_FINGERPRINT_LABEL: &str = "moat-epoch-fingerprint-v1";

/// Length of epoch fingerprint in bytes.
const EPOCH_FINGERPRINT_LEN: usize = 16;

/// Key for the hash chain map: (group_id, device_id).
type HashChainKey = (Vec<u8>, [u8; 16]);

/// Key for the tag counter map: (group_id, epoch).
type TagCounterKey = (Vec<u8>, u64);

/// Key for the seen counter map: (group_id, sender_did, sender_device_id).
type SeenCounterKey = (Vec<u8>, String, [u8; 16]);

/// Maximum number of automatic conflict recovery retries.
const CONFLICT_RETRY_LIMIT: usize = 2;

/// A pending MLS operation that can be retried after conflict recovery.
/// In-memory only — not persisted in the state blob.
#[derive(Debug, Clone)]
pub enum PendingOperation {
    AddMember {
        key_bundle: Vec<u8>,
        new_member_key_package: Vec<u8>,
    },
    RemoveMember {
        key_bundle: Vec<u8>,
        leaf_index: u32,
    },
    KickUser {
        key_bundle: Vec<u8>,
        did: String,
    },
    LeaveGroup {
        key_bundle: Vec<u8>,
    },
}

/// A persistent MLS session.
///
/// MoatSession holds a [`MoatProvider`] for MLS operations and a unique device ID.
///
/// No built-in file I/O — callers manage persistence via `export_state()` /
/// `from_state()`. This ensures every caller (CLI, mobile, tests) exercises
/// the same API.
///
/// # Thread Safety
///
/// `MoatSession` is `Send + Sync`. The internal storage uses `std::sync::RwLock`
/// for safe concurrent access.
///
/// However, MLS operations that load-modify-save a group (e.g., `encrypt_event`,
/// `decrypt_event`, `add_member`) are **not atomic** at the session level. If
/// multiple threads call mutating operations on the same group concurrently,
/// results are undefined. Callers should ensure exclusive access to the session
/// during mutating operations — for example, by wrapping it in a `Mutex` on the
/// mobile side.
///
/// Read-only methods (`export_state`, `get_group_epoch`, `has_pending_changes`,
/// `device_id`) are safe to call concurrently.
///
/// # State format (v5)
///
/// The exported state has the following layout:
/// - `b"MOAT"` (4 bytes) — magic identifier
/// - Version (2 bytes, little-endian u16) — currently `5`
/// - Device ID (16 bytes) — random, generated once per device
/// - MLS state length (8 bytes, little-endian u64)
/// - MLS state (variable) — raw storage data
/// - Hash chain entry count (8 bytes, little-endian u64)
/// - Hash chain entries: for each entry:
///   - group_id length (4 bytes, little-endian u32)
///   - group_id (variable)
///   - device_id (16 bytes)
///   - last_event_hash (32 bytes)
/// - Tag counter entry count (8 bytes, little-endian u64)
/// - Tag counter entries: for each entry:
///   - group_id length (4 bytes, little-endian u32)
///   - group_id (variable)
///   - epoch (8 bytes, little-endian u64)
///   - counter (8 bytes, little-endian u64)
/// - Seen counter entry count (8 bytes, little-endian u64)
/// - Seen counter entries: for each entry:
///   - group_id length (4 bytes, little-endian u32)
///   - group_id (variable)
///   - sender_did length (4 bytes, little-endian u32)
///   - sender_did (variable, UTF-8)
///   - sender_device_id (16 bytes)
///   - counter (8 bytes, little-endian u64)
///
/// # Example
///
/// ```
/// use moat_core::{MoatSession, MoatCredential};
///
/// // Create a new session
/// let session = MoatSession::new();
/// let credential = MoatCredential::new("did:plc:alice123", "My Laptop", [0u8; 16]);
/// let (key_package, key_bundle) = session.generate_key_package(&credential).unwrap();
/// let group_id = session.create_group(&credential, &key_bundle).unwrap();
///
/// // Persist: caller chooses how (file, SQLite, etc.)
/// let state = session.export_state().unwrap();
/// // ... write state bytes somewhere ...
///
/// // Restore later
/// let session2 = MoatSession::from_state(&state).unwrap();
/// assert_eq!(session.device_id(), session2.device_id());
/// ```
pub struct MoatSession {
    provider: MoatProvider,
    device_id: [u8; 16],
    /// Per-device hash chain state: maps (group_id, device_id) → last event hash.
    /// Used for transcript integrity verification.
    hash_chains: RwLock<HashMap<HashChainKey, [u8; 32]>>,
    /// Outgoing tag counter: maps (group_id, epoch) → next counter value.
    /// Pre-incremented before publishing for crash safety.
    tag_counters: RwLock<HashMap<TagCounterKey, u64>>,
    /// Recipient-side seen counter: maps (group_id, sender_did, device_id) → highest counter seen.
    /// Used by populate_candidate_tags to scan the right window.
    seen_counters: RwLock<HashMap<SeenCounterKey, u64>>,
    /// In-memory tag → (group_id, sender_did, device_id, counter) reverse lookup.
    /// Populated by populate_candidate_tags, used by mark_tag_seen. Not persisted.
    tag_metadata: RwLock<HashMap<[u8; 16], (Vec<u8>, String, [u8; 16], u64)>>,
    /// In-memory pending operations for conflict recovery. Maps group_id → operation.
    /// Not persisted — if the app restarts mid-operation, the user retries manually.
    pending_ops: RwLock<HashMap<Vec<u8>, PendingOperation>>,
    /// Prior epoch export secrets for multi-epoch tag retention.
    /// Maps group_id → ring buffer of old export secrets (most recent first).
    /// Used by `populate_candidate_tags` to generate candidate tags with decaying
    /// gap limits for prior epochs, catching messages stranded across epoch boundaries.
    prior_export_secrets: RwLock<HashMap<Vec<u8>, VecDeque<Vec<u8>>>>,
    /// Running SHA-256 digest chain per conversation (keyed by group_id).
    conversation_digests: RwLock<HashMap<Vec<u8>, crate::digest::DigestState>>,
    /// Oldest synced rkey per conversation.  Persisted as the sync watermark.
    watermarks: RwLock<HashMap<Vec<u8>, String>>,
    /// (oldest_rkey, newest_rkey) held locally per conversation.
    inbox_ranges: RwLock<HashMap<Vec<u8>, (String, String)>>,
    /// Groups whose next `append_to_digest` call should force an anchor (epoch boundary).
    /// Transient — not persisted.
    digest_epoch_boundaries: RwLock<HashSet<Vec<u8>>>,
}

impl MoatSession {
    /// Create a new session with empty storage and a random device ID.
    pub fn new() -> Self {
        use rand::RngCore;
        let mut device_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut device_id);
        Self {
            provider: MoatProvider::new(),
            device_id,
            hash_chains: RwLock::new(HashMap::new()),
            tag_counters: RwLock::new(HashMap::new()),
            seen_counters: RwLock::new(HashMap::new()),
            tag_metadata: RwLock::new(HashMap::new()),
            pending_ops: RwLock::new(HashMap::new()),
            prior_export_secrets: RwLock::new(HashMap::new()),
            conversation_digests: RwLock::new(HashMap::new()),
            watermarks: RwLock::new(HashMap::new()),
            inbox_ranges: RwLock::new(HashMap::new()),
            digest_epoch_boundaries: RwLock::new(HashSet::new()),
        }
    }

    /// Create a session from previously exported state bytes.
    ///
    /// The state must start with a valid version header (`b"MOAT"` + version).
    /// The returned session contains all MLS state and device ID from the export.
    /// Use `export_state()` to persist again after operations.
    pub fn from_state(state: &[u8]) -> Result<Self> {
        if state.len() < STATE_HEADER_SIZE {
            return Err(Error::Deserialization("state too short".into()));
        }
        if &state[0..4] != STATE_MAGIC {
            return Err(Error::Deserialization("invalid state header".into()));
        }
        let version = u16::from_le_bytes([state[4], state[5]]);
        match version {
            1 | 2 => {
                return Err(Error::StateVersionMismatch(format!(
                    "v{version} state not supported; re-initialize session"
                )))
            }
            3 | 4 | 5 => {}
            _ => {
                return Err(Error::Deserialization(format!(
                    "unsupported state version: {version}"
                )))
            }
        }
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&state[6..22]);

        let rest = &state[STATE_HEADER_SIZE..];

        // MLS state with length prefix
        if rest.len() < 8 {
            return Err(Error::Deserialization(
                "state too short for MLS length".into(),
            ));
        }
        let mls_len = u64::from_le_bytes(rest[..8].try_into().unwrap()) as usize;
        let rest = &rest[8..];
        if rest.len() < mls_len {
            return Err(Error::Deserialization(
                "state too short for MLS data".into(),
            ));
        }
        let provider = MoatProvider::from_state(&rest[..mls_len])
            .map_err(|e| Error::Storage(e.to_string()))?;
        let rest = &rest[mls_len..];

        // Parse hash chain entries
        let (hash_chains, rest) = Self::deserialize_hash_chains(rest)?;

        // v3: Parse tag counter entries
        let (tag_counters, rest) = Self::deserialize_tag_counters(rest)?;

        // Parse seen counter entries (may be absent in older state files)
        let (seen_counters, rest) = Self::deserialize_seen_counters_rest(rest)?;

        // v4: Parse prior export secrets (absent in v3)
        let (prior_export_secrets, rest) = if version >= 4 && !rest.is_empty() {
            let (secrets, remaining) = Self::deserialize_prior_export_secrets_rest(rest)?;
            (secrets, remaining)
        } else {
            (HashMap::new(), rest)
        };

        // v5: Parse digest / watermark / inbox_range tables (absent in v3/v4)
        let (conversation_digests, rest) = if version >= 5 && !rest.is_empty() {
            Self::deserialize_conversation_digests(rest)?
        } else {
            (HashMap::new(), rest)
        };
        let (watermarks, rest) = if version >= 5 && !rest.is_empty() {
            Self::deserialize_watermarks(rest)?
        } else {
            (HashMap::new(), rest)
        };
        let inbox_ranges = if version >= 5 && !rest.is_empty() {
            Self::deserialize_inbox_ranges(rest)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            provider,
            device_id,
            hash_chains: RwLock::new(hash_chains),
            tag_counters: RwLock::new(tag_counters),
            seen_counters: RwLock::new(seen_counters),
            tag_metadata: RwLock::new(HashMap::new()),
            pending_ops: RwLock::new(HashMap::new()),
            prior_export_secrets: RwLock::new(prior_export_secrets),
            conversation_digests: RwLock::new(conversation_digests),
            watermarks: RwLock::new(watermarks),
            inbox_ranges: RwLock::new(inbox_ranges),
            digest_epoch_boundaries: RwLock::new(HashSet::new()),
        })
    }

    /// Export the full session state as bytes.
    ///
    /// The returned bytes include a version header and device ID, followed by
    /// raw MLS state. Pass to `from_state()` to restore the session.
    /// Also clears the dirty flag.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let raw_state = self
            .provider
            .export_state()
            .map_err(|e| Error::Storage(e.to_string()))?;
        self.provider.clear_pending_changes();

        let hash_chain_bytes = self.serialize_hash_chains();
        let tag_counter_bytes = self.serialize_tag_counters();
        let seen_counter_bytes = self.serialize_seen_counters();
        let prior_secrets_bytes = self.serialize_prior_export_secrets();
        let digest_bytes = self.serialize_conversation_digests();
        let watermark_bytes = self.serialize_watermarks();
        let inbox_range_bytes = self.serialize_inbox_ranges();

        let mut buf = Vec::with_capacity(
            STATE_HEADER_SIZE
                + 8
                + raw_state.len()
                + hash_chain_bytes.len()
                + tag_counter_bytes.len()
                + seen_counter_bytes.len()
                + prior_secrets_bytes.len()
                + digest_bytes.len()
                + watermark_bytes.len()
                + inbox_range_bytes.len(),
        );
        buf.extend_from_slice(STATE_MAGIC);
        buf.extend_from_slice(&STATE_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.device_id);
        // MLS state with length prefix
        buf.extend_from_slice(&(raw_state.len() as u64).to_le_bytes());
        buf.extend_from_slice(&raw_state);
        // Hash chain data
        buf.extend_from_slice(&hash_chain_bytes);
        // v3: Tag counter data
        buf.extend_from_slice(&tag_counter_bytes);
        // Seen counter data (recipient-side)
        buf.extend_from_slice(&seen_counter_bytes);
        // v4: Prior export secrets for multi-epoch tag retention
        buf.extend_from_slice(&prior_secrets_bytes);
        // v5: Conversation digests, watermarks, inbox ranges
        buf.extend_from_slice(&digest_bytes);
        buf.extend_from_slice(&watermark_bytes);
        buf.extend_from_slice(&inbox_range_bytes);
        Ok(buf)
    }

    /// Get the device ID for this session.
    ///
    /// The device ID is a random 16-byte identifier generated once when the
    /// session is first created, and persisted through `export_state()`/`from_state()`.
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// Create a new device ring MLS group with a random 32-byte group ID.
    ///
    /// The ring is created with only the caller as its initial member; siblings
    /// are added later via [`add_device`]. Returns the raw group ID bytes.
    pub fn create_device_ring(
        &self,
        credential: &MoatCredential,
        key_bundle: &[u8],
    ) -> Result<Vec<u8>> {
        self.create_group(credential, key_bundle)
    }

    /// Create a pairwise device coordination group between this device and a sibling.
    ///
    /// Creates an MLS group, immediately adds the sibling via their key package,
    /// and returns the group ID, commit, and welcome for the sibling.
    pub fn create_device_coord_group(
        &self,
        credential: &MoatCredential,
        key_bundle: &[u8],
        sibling_key_package: &[u8],
    ) -> Result<crate::device_ring::CoordGroupResult> {
        let group_id = self.create_group(credential, key_bundle)?;
        let welcome_result = self.add_member(&group_id, key_bundle, sibling_key_package)?;
        Ok(crate::device_ring::CoordGroupResult {
            group_id,
            commit: welcome_result.commit,
            welcome: welcome_result.welcome,
        })
    }

    /// Check if there are unsaved changes.
    pub fn has_pending_changes(&self) -> bool {
        self.provider.has_pending_changes()
    }

    /// Generate a new key package for the given credential.
    ///
    /// The key package and signature keys are persisted to storage.
    /// Returns (key_package_bytes, key_bundle_bytes).
    ///
    /// # Arguments
    ///
    /// * `credential` - The MoatCredential containing DID and device name
    pub fn generate_key_package(&self, credential: &MoatCredential) -> Result<(Vec<u8>, Vec<u8>)> {
        // Serialize the credential to bytes for embedding in BasicCredential
        let credential_bytes = credential
            .to_bytes()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Generate Ed25519 keypair directly so we can capture the raw private key seed.
        // We use ed25519_dalek to generate the key, then hand the raw bytes to OpenMLS
        // via SignatureKeyPair::from_raw. This avoids relying on the `test-utils` feature
        // gate on SignatureKeyPair::private().
        let ed25519_signing_key =
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed25519_private_seed = ed25519_signing_key.to_bytes(); // [u8; 32]
        let ed25519_public = ed25519_signing_key.verifying_key().to_bytes().to_vec();
        let signature_keys = SignatureKeyPair::from_raw(
            CIPHERSUITE.signature_algorithm(),
            ed25519_private_seed.to_vec(),
            ed25519_public,
        );

        // Store the signature keys (persisted to file)
        signature_keys
            .store(self.provider.storage())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        // Create basic credential with our structured format
        let basic_credential = BasicCredential::new(credential_bytes);
        let credential_with_key = CredentialWithKey {
            credential: basic_credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        // Generate key package
        let key_package_bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &signature_keys,
                credential_with_key,
            )
            .map_err(|e| Error::KeyPackageGeneration(e.to_string()))?;

        // Get the key package for publishing
        let key_package = key_package_bundle.key_package();

        // Serialize key package
        let key_package_bytes = key_package
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Serialize signature keys
        let signature_key_bytes = signature_keys
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Get the init private key
        let init_private_key_bytes = key_package_bundle
            .init_private_key()
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Create key bundle (for compatibility with existing code)
        let key_bundle = KeyBundle {
            key_package: key_package_bytes.clone(),
            init_private_key: init_private_key_bytes,
            encryption_private_key: Vec::new(), // Stored in provider
            signature_key: signature_key_bytes,
            signature_private_key: ed25519_private_seed.to_vec(),
        };

        let key_bundle_bytes =
            serde_json::to_vec(&key_bundle).map_err(|e| Error::Serialization(e.to_string()))?;

        Ok((key_package_bytes, key_bundle_bytes))
    }

    /// Generate a fresh key package using the **existing** signing key from `key_bundle`.
    ///
    /// Unlike `generate_key_package`, this does NOT create a new signing key.
    /// The existing leaf-node signing key (already embedded in any group the caller
    /// belongs to) is preserved so that group operations (`add_member`, `kick_user`,
    /// `encrypt_event`, …) continue to work after the new key package is uploaded.
    ///
    /// Use this to replenish the PDS key package after a Welcome has been consumed,
    /// so the member can be re-invited to a group.
    ///
    /// Returns the new key package bytes (suitable for publishing to the PDS).
    pub fn replenish_key_package(
        &self,
        credential: &MoatCredential,
        key_bundle: &[u8],
    ) -> Result<Vec<u8>> {
        let credential_bytes = credential
            .to_bytes()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Re-use the existing signing key pair so the leaf-node public key stays
        // the same (matching what is already stored in every group the member has
        // joined via a prior Welcome).
        let signature_keys =
            SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
                .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Re-store the signing keys so OpenMLS can find them when building the package.
        signature_keys
            .store(self.provider.storage())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        let basic_credential = BasicCredential::new(credential_bytes);
        let credential_with_key = CredentialWithKey {
            credential: basic_credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        let key_package_bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &signature_keys,
                credential_with_key,
            )
            .map_err(|e| Error::KeyPackageGeneration(e.to_string()))?;

        let key_package_bytes = key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(key_package_bytes)
    }

    /// Create a new MLS group.
    ///
    /// The group state is persisted to storage.
    /// Returns the group ID as bytes.
    ///
    /// # Arguments
    ///
    /// * `credential` - The MoatCredential for the group creator
    /// * `key_bundle` - The serialized key bundle from generate_key_package
    pub fn create_group(&self, credential: &MoatCredential, key_bundle: &[u8]) -> Result<Vec<u8>> {
        // Serialize the credential to bytes
        let credential_bytes = credential
            .to_bytes()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Deserialize key bundle
        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Deserialize signature keys
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Store the signature keys (may already exist from generate_key_package)
        signature_keys
            .store(self.provider.storage())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        // Create credential with our structured format
        let basic_credential = BasicCredential::new(credential_bytes);
        let credential_with_key = CredentialWithKey {
            credential: basic_credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        // Create group config
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(tag::MAX_PRIOR_EPOCHS)
            .build();

        // Create the group (persisted to storage via provider)
        let group = MlsGroup::new(
            &self.provider,
            &signature_keys,
            &group_config,
            credential_with_key,
        )
        .map_err(|e| Error::GroupCreation(e.to_string()))?;

        let group_id = group.group_id().as_slice().to_vec();
        Ok(group_id)
    }

    /// Get the current epoch of a group by ID.
    ///
    /// Returns `None` if the group doesn't exist in storage.
    pub fn get_group_epoch(&self, group_id: &[u8]) -> Result<Option<u64>> {
        self.load_group(group_id)
            .map(|opt| opt.map(|g| g.epoch().as_u64()))
    }

    /// Load an existing group by ID.
    ///
    /// Returns None if the group doesn't exist in storage.
    pub(crate) fn load_group(&self, group_id: &[u8]) -> Result<Option<MlsGroup>> {
        let group_id = GroupId::from_slice(group_id);

        // Try to load the group from storage
        match MlsGroup::load(self.provider.storage(), &group_id) {
            Ok(Some(group)) => Ok(Some(group)),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::GroupLoad(e.to_string())),
        }
    }

    /// Add a member to an existing group.
    ///
    /// Returns (commit_bytes, welcome_bytes) to send to the new member.
    pub fn add_member(
        &self,
        group_id: &[u8],
        key_bundle: &[u8],
        new_member_key_package: &[u8],
    ) -> Result<WelcomeResult> {
        // Load the group
        let mut group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Deserialize the new member's key package
        let new_key_package = KeyPackageIn::tls_deserialize_exact(new_member_key_package)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Validate the key package
        let validated_key_package = new_key_package
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| Error::KeyPackageValidation(e.to_string()))?;

        // Save current export secret before epoch advances
        self.save_prior_export_secret(&group, group_id);

        // Add the member
        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &signature_keys, &[validated_key_package])
            .map_err(|e| Error::AddMember(e.to_string()))?;

        // Track pending operation for conflict recovery
        {
            let mut ops = self.pending_ops.write().unwrap();
            ops.insert(
                group_id.to_vec(),
                PendingOperation::AddMember {
                    key_bundle: key_bundle.to_vec(),
                    new_member_key_package: new_member_key_package.to_vec(),
                },
            );
        }

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

        // Clear pending op on success
        self.pending_ops.write().unwrap().remove(group_id);

        // Serialize results
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        let welcome_bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(WelcomeResult {
            new_group_state: Vec::new(), // No longer needed - state is in provider
            welcome: welcome_bytes,
            commit: commit_bytes,
            group_id: group_id.to_vec(),
        })
    }

    /// Process a welcome message to join a group.
    ///
    /// Returns the group ID of the joined group.
    pub fn process_welcome(&self, welcome_bytes: &[u8]) -> Result<Vec<u8>> {
        // Deserialize the welcome
        let mls_message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Extract the welcome from the message body
        let welcome = match mls_message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(Error::Deserialization("Not a welcome message".to_string())),
        };

        // Join the group
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(tag::MAX_PRIOR_EPOCHS)
            .build();

        let group = StagedWelcome::new_from_welcome(&self.provider, &join_config, welcome, None)
            .map_err(|e| Error::ProcessWelcome(e.to_string()))?
            .into_group(&self.provider)
            .map_err(|e| Error::ProcessWelcome(e.to_string()))?;

        let group_id = group.group_id().as_slice().to_vec();

        // Clear any stale seen counters / tag metadata for this group
        {
            let mut seen = self.seen_counters.write().unwrap();
            seen.retain(|(gid, _, _), _| gid != &group_id);
        }
        {
            let mut metadata = self.tag_metadata.write().unwrap();
            metadata.retain(|_, (gid, _, _, _)| gid != &group_id);
        }

        Ok(group_id)
    }

    /// Encrypt an event for a group.
    ///
    /// The event is serialized, padded, and encrypted using MLS.
    /// Sets transcript integrity fields (prev_event_hash, epoch_fingerprint,
    /// sender_device_id) before encryption.
    /// Derives a unique per-event tag using the counter-based HD scheme.
    /// The tag counter is pre-incremented for crash safety.
    /// Returns (conversation_tag, ciphertext).
    pub fn encrypt_event(
        &self,
        group_id: &[u8],
        key_bundle: &[u8],
        event: &Event,
    ) -> Result<EncryptResult> {
        // Load the group
        let mut group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Get signature keys from key bundle
        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Extract our DID from the group's member list
        let our_pubkey = signature_keys.to_public_vec();
        let sender_did = self.extract_own_did(&group, &our_pubkey)?;

        // Build the event with transcript integrity fields
        let mut event = event.clone();
        event.sender_device_id = Some(self.device_id.to_vec());

        // Set prev_event_hash from our hash chain
        let chain_key = (group_id.to_vec(), self.device_id);
        {
            let chains = self.hash_chains.read().unwrap();
            event.prev_event_hash = chains.get(&chain_key).map(|h| h.to_vec());
        }

        // Derive epoch fingerprint
        event.epoch_fingerprint = Some(Self::derive_epoch_fingerprint(&group, &self.provider)?);

        // Serialize and pad the event
        let event_bytes = event
            .to_bytes()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Update hash chain with this event's hash
        let event_hash = Self::hash_event_bytes(&event_bytes);
        {
            let mut chains = self.hash_chains.write().unwrap();
            chains.insert(chain_key, event_hash);
        }

        let padded = pad_to_bucket(&event_bytes);

        // Encrypt the message
        let ciphertext = group
            .create_message(&self.provider, &signature_keys, &padded)
            .map_err(|e| Error::Encryption(e.to_string()))?;

        // Serialize the ciphertext
        let ciphertext_bytes = ciphertext
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Derive per-event tag using counter-based HD scheme
        let epoch = group.epoch().as_u64();
        let export_secret = self.derive_tag_export_secret(&group)?;
        let counter_key = (group_id.to_vec(), epoch);

        // Pre-increment counter for crash safety
        let counter = {
            let mut counters = self.tag_counters.write().unwrap();
            let counter = counters.entry(counter_key).or_insert(0);
            let current = *counter;
            *counter = current + 1;
            current
        };

        let tag = tag::derive_event_tag(
            &export_secret,
            group_id,
            &sender_did,
            &self.device_id,
            counter,
        )?;

        Ok(EncryptResult {
            new_group_state: Vec::new(), // State is managed by provider
            tag,
            ciphertext: ciphertext_bytes,
            message_id: event.message_id.clone(),
        })
    }

    /// Decrypt a ciphertext for a group.
    ///
    /// The ciphertext is decrypted, unpadded, and deserialized.
    /// Returns a `DecryptOutcome` containing the decrypted event, sender
    /// information, and any transcript integrity warnings.
    ///
    /// For commit messages (e.g., adding/removing members), this function
    /// merges the commit into the group state and returns an Event with
    /// kind=Commit. The caller should update their epoch tags accordingly.
    pub fn decrypt_event(&self, group_id: &[u8], ciphertext: &[u8]) -> Result<DecryptOutcome> {
        // Load the group
        let mut group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize the MLS message
        let mls_message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Convert to protocol message
        let protocol_message = mls_message
            .try_into_protocol_message()
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Process the message with structured error classification
        let processed = match group.process_message(&self.provider, protocol_message) {
            Ok(msg) => msg,
            Err(e) => {
                return Err(Self::classify_process_error(e, group_id));
            }
        };

        // Extract sender info from the credential
        let sender = self.extract_sender_info(&group, &processed);

        // Handle the message content based on type
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                // Regular application message - unpad and deserialize
                let padded_bytes = app_msg.into_bytes();
                let event_bytes = unpad(&padded_bytes);
                let event = Event::from_bytes(&event_bytes)
                    .map_err(|e| Error::Deserialization(e.to_string()))?;

                // Validate transcript integrity
                let mut warnings = Vec::new();
                self.validate_hash_chain(group_id, &event, &event_bytes, &mut warnings);
                self.validate_epoch_fingerprint(group_id, &event, &group, &mut warnings);

                let result = DecryptResult {
                    new_group_state: Vec::new(),
                    event,
                    sender,
                };
                Ok(DecryptOutcome::from_result_and_warnings(result, warnings))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                // Save current export secret before epoch advances
                self.save_prior_export_secret(&group, group_id);

                // Check if we have a pending local commit that conflicts with this remote commit
                let had_pending_op = {
                    let ops = self.pending_ops.read().unwrap();
                    ops.contains_key(group_id)
                };

                // Merge the remote commit
                group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .map_err(|e| Error::StateDiverged(e.to_string()))?;

                // Get the new epoch after merging
                let new_epoch = group.epoch().as_u64();

                // Clear seen counters and tag metadata for this group — the export
                // secret changes with the epoch, so old counter values are meaningless.
                // Senders also reset their counters per epoch, so recipients must
                // start scanning from 0 in the new epoch.
                {
                    let mut seen = self.seen_counters.write().unwrap();
                    seen.retain(|(gid, _, _), _| gid != group_id);
                }
                {
                    let mut metadata = self.tag_metadata.write().unwrap();
                    metadata.retain(|_, (gid, _, _, _)| gid != group_id);
                }

                // Return a commit event to signal the epoch has advanced
                let event = Event::commit(group_id.to_vec(), new_epoch, Vec::new());

                // For commits, validate epoch fingerprint after merge (both sides agree on post-commit state)
                // We skip hash chain validation for commit events since they're synthetic.
                let mut warnings = Vec::new();

                // Derive post-merge fingerprint (this is what all parties should agree on)
                let _ = Self::derive_epoch_fingerprint(&group, &self.provider);

                // Attempt conflict recovery if we had a pending operation
                if had_pending_op {
                    let recovered = self.attempt_conflict_recovery(group_id);
                    if recovered {
                        warnings.push(TranscriptWarning::ConflictRecovered {
                            group_id: group_id.to_vec(),
                        });
                    }
                    // If recovery failed, the pending op was already cleared — caller
                    // will get the warning so they know recovery happened (or didn't).
                }

                let result = DecryptResult {
                    new_group_state: Vec::new(),
                    event,
                    sender,
                };
                Ok(DecryptOutcome::from_result_and_warnings(result, warnings))
            }
            ProcessedMessageContent::ProposalMessage(_) => Err(Error::InvalidMessageType(
                "Unexpected proposal message".to_string(),
            )),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => Err(
                Error::InvalidMessageType("Unexpected external join".to_string()),
            ),
        }
    }

    /// Classify a `ProcessMessageError` into a structured moat-core `Error`.
    fn classify_process_error(e: ProcessMessageError, group_id: &[u8]) -> Error {
        let group_hex: String = group_id.iter().map(|b| format!("{:02x}", b)).collect();
        match &e {
            ProcessMessageError::GroupStateError(state_err) => match state_err {
                MlsGroupStateError::PendingCommit => Error::StaleCommit(format!(
                    "group {}: pending local commit conflicts with incoming message",
                    group_hex
                )),
                MlsGroupStateError::UseAfterEviction => {
                    Error::StateDiverged(format!("group {}: evicted from group", group_hex))
                }
                _ => Error::Decryption(e.to_string()),
            },
            ProcessMessageError::InvalidCommit(_) => {
                Error::StateDiverged(format!("group {}: invalid commit — {}", group_hex, e))
            }
            ProcessMessageError::ValidationError(_) => {
                // Validation errors can include unknown sender scenarios
                let msg = e.to_string();
                if msg.contains("unknown") || msg.contains("sender") {
                    Error::UnknownSender(format!("group {}: {}", group_hex, msg))
                } else {
                    Error::Decryption(e.to_string())
                }
            }
            _ => Error::Decryption(e.to_string()),
        }
    }

    /// Attempt to recover from a commit conflict by retrying the pending operation.
    ///
    /// When we receive a remote commit while we had a pending local operation,
    /// we discard our pending commit and retry the operation on the new epoch.
    /// Returns true if recovery succeeded, false otherwise.
    fn attempt_conflict_recovery(&self, group_id: &[u8]) -> bool {
        let pending_op = {
            let mut ops = self.pending_ops.write().unwrap();
            ops.remove(group_id)
        };

        let pending_op = match pending_op {
            Some(op) => op,
            None => return false,
        };

        for attempt in 0..CONFLICT_RETRY_LIMIT {
            let result = match &pending_op {
                PendingOperation::AddMember {
                    key_bundle,
                    new_member_key_package,
                } => self
                    .add_member(group_id, key_bundle, new_member_key_package)
                    .map(|_| ()),
                PendingOperation::RemoveMember {
                    key_bundle,
                    leaf_index,
                } => self
                    .remove_member(group_id, key_bundle, *leaf_index)
                    .map(|_| ()),
                PendingOperation::KickUser { key_bundle, did } => {
                    self.kick_user(group_id, key_bundle, did).map(|_| ())
                }
                PendingOperation::LeaveGroup { key_bundle } => {
                    self.leave_group(group_id, key_bundle).map(|_| ())
                }
            };

            match result {
                Ok(()) => return true,
                Err(e) => {
                    if attempt + 1 < CONFLICT_RETRY_LIMIT {
                        // Will retry
                        continue;
                    }
                    // Exhausted retries — log but don't error (caller gets no ConflictRecovered warning)
                    let _ = e; // suppress unused warning
                    return false;
                }
            }
        }

        false
    }

    /// Validate the hash chain for a received event.
    fn validate_hash_chain(
        &self,
        group_id: &[u8],
        event: &Event,
        event_bytes: &[u8],
        warnings: &mut Vec<TranscriptWarning>,
    ) {
        let sender_device_id = match &event.sender_device_id {
            Some(id) if id.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(id);
                arr
            }
            _ => return, // No sender_device_id — old event, skip validation
        };

        let chain_key = (group_id.to_vec(), sender_device_id);
        let event_hash = Self::hash_event_bytes(event_bytes);

        let mut chains = self.hash_chains.write().unwrap();

        // Check for replay: if prev_event_hash matches the current stored hash
        // AND the event hash is the same as stored, it's a replay
        if let Some(&stored_hash) = chains.get(&chain_key) {
            if event_hash == stored_hash {
                warnings.push(TranscriptWarning::ReplayDetected {
                    group_id: group_id.to_vec(),
                    sender_device_id: sender_device_id.to_vec(),
                });
                return; // Don't update chain on replay
            }
        }

        // Validate prev_event_hash
        let expected = chains.get(&chain_key).copied();
        let received = &event.prev_event_hash;

        match (expected, received) {
            (None, None) => {
                // First event from this sender — valid
            }
            (None, Some(_)) => {
                // We have no record but they claim a previous hash — we're new or missed events.
                // Accept silently since we may have just joined.
            }
            (Some(exp), Some(recv)) => {
                if recv.len() != 32 || recv.as_slice() != exp.as_slice() {
                    warnings.push(TranscriptWarning::HashChainMismatch {
                        group_id: group_id.to_vec(),
                        sender_device_id: sender_device_id.to_vec(),
                        expected: Some(exp),
                        received: Some(recv.clone()),
                    });
                }
            }
            (Some(exp), None) => {
                // We expected a hash but got None — gap or old client
                warnings.push(TranscriptWarning::HashChainMismatch {
                    group_id: group_id.to_vec(),
                    sender_device_id: sender_device_id.to_vec(),
                    expected: Some(exp),
                    received: None,
                });
            }
        }

        // Update stored hash
        chains.insert(chain_key, event_hash);
    }

    /// Validate epoch fingerprint for a received event.
    fn validate_epoch_fingerprint(
        &self,
        group_id: &[u8],
        event: &Event,
        group: &MlsGroup,
        warnings: &mut Vec<TranscriptWarning>,
    ) {
        let received = match &event.epoch_fingerprint {
            Some(fp) => fp,
            None => return, // Old event without fingerprint — skip
        };

        let local = match Self::derive_epoch_fingerprint(group, &self.provider) {
            Ok(fp) => fp,
            Err(_) => return, // Can't derive — skip (shouldn't happen)
        };

        if local != *received {
            warnings.push(TranscriptWarning::EpochFingerprintMismatch {
                group_id: group_id.to_vec(),
                epoch: event.epoch,
                local,
                received: received.clone(),
            });
        }
    }

    /// Serialize hash chain state to bytes.
    fn serialize_hash_chains(&self) -> Vec<u8> {
        let chains = self.hash_chains.read().unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(chains.len() as u64).to_le_bytes());
        for ((group_id, device_id), hash) in chains.iter() {
            buf.extend_from_slice(&(group_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(group_id);
            buf.extend_from_slice(device_id);
            buf.extend_from_slice(hash);
        }
        buf
    }

    /// Deserialize hash chain state from bytes. Returns (map, remaining_bytes).
    fn deserialize_hash_chains(data: &[u8]) -> Result<(HashMap<HashChainKey, [u8; 32]>, &[u8])> {
        if data.len() < 8 {
            return Err(Error::Deserialization("hash chain data too short".into()));
        }
        let count = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let mut offset = 8;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if offset + 4 > data.len() {
                return Err(Error::Deserialization("hash chain entry truncated".into()));
            }
            let gid_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + gid_len + 16 + 32 > data.len() {
                return Err(Error::Deserialization("hash chain entry truncated".into()));
            }
            let group_id = data[offset..offset + gid_len].to_vec();
            offset += gid_len;
            let mut device_id = [0u8; 16];
            device_id.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            map.insert((group_id, device_id), hash);
        }
        Ok((map, &data[offset..]))
    }

    /// Serialize tag counter state to bytes.
    ///
    /// Prunes stale epoch entries: for each group_id, only the entry with
    /// the highest epoch is serialized. Old epoch counters are also removed
    /// from the in-memory map to prevent unbounded growth.
    fn serialize_tag_counters(&self) -> Vec<u8> {
        let mut counters = self.tag_counters.write().unwrap();

        // Find the max epoch per group_id (owned keys to avoid borrow conflict)
        let mut max_epochs: HashMap<Vec<u8>, u64> = HashMap::new();
        for ((group_id, epoch), _) in counters.iter() {
            let entry = max_epochs.entry(group_id.clone()).or_insert(0);
            if *epoch > *entry {
                *entry = *epoch;
            }
        }

        // Remove stale entries
        counters.retain(|(group_id, epoch), _| {
            max_epochs.get(group_id).map_or(false, |&max| *epoch == max)
        });

        let mut buf = Vec::new();
        buf.extend_from_slice(&(counters.len() as u64).to_le_bytes());
        for ((group_id, epoch), counter) in counters.iter() {
            buf.extend_from_slice(&(group_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(group_id);
            buf.extend_from_slice(&epoch.to_le_bytes());
            buf.extend_from_slice(&counter.to_le_bytes());
        }
        buf
    }

    /// Deserialize tag counter state from bytes. Returns (map, remaining_bytes).
    fn deserialize_tag_counters(data: &[u8]) -> Result<(HashMap<TagCounterKey, u64>, &[u8])> {
        if data.len() < 8 {
            return Err(Error::Deserialization("tag counter data too short".into()));
        }
        let count = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let mut offset = 8;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if offset + 4 > data.len() {
                return Err(Error::Deserialization("tag counter entry truncated".into()));
            }
            let gid_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + gid_len + 8 + 8 > data.len() {
                return Err(Error::Deserialization("tag counter entry truncated".into()));
            }
            let group_id = data[offset..offset + gid_len].to_vec();
            offset += gid_len;
            let epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let counter = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            map.insert((group_id, epoch), counter);
        }
        Ok((map, &data[offset..]))
    }

    /// Serialize seen counter state to bytes.
    fn serialize_seen_counters(&self) -> Vec<u8> {
        let counters = self.seen_counters.read().unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(counters.len() as u64).to_le_bytes());
        for ((group_id, sender_did, device_id), counter) in counters.iter() {
            buf.extend_from_slice(&(group_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(group_id);
            let did_bytes = sender_did.as_bytes();
            buf.extend_from_slice(&(did_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(did_bytes);
            buf.extend_from_slice(device_id);
            buf.extend_from_slice(&counter.to_le_bytes());
        }
        buf
    }

    /// Deserialize seen counter state from bytes, returning remaining bytes.
    fn deserialize_seen_counters_rest(data: &[u8]) -> Result<(HashMap<SeenCounterKey, u64>, &[u8])> {
        if data.is_empty() {
            return Ok((HashMap::new(), data));
        }
        if data.len() < 8 {
            return Err(Error::Deserialization("seen counter data too short".into()));
        }
        let count = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let mut offset = 8;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if offset + 4 > data.len() {
                return Err(Error::Deserialization(
                    "seen counter entry truncated".into(),
                ));
            }
            let gid_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + gid_len > data.len() {
                return Err(Error::Deserialization(
                    "seen counter entry truncated".into(),
                ));
            }
            let group_id = data[offset..offset + gid_len].to_vec();
            offset += gid_len;
            if offset + 4 > data.len() {
                return Err(Error::Deserialization(
                    "seen counter entry truncated".into(),
                ));
            }
            let did_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + did_len + 16 + 8 > data.len() {
                return Err(Error::Deserialization(
                    "seen counter entry truncated".into(),
                ));
            }
            let sender_did = String::from_utf8(data[offset..offset + did_len].to_vec())
                .map_err(|_| Error::Deserialization("invalid UTF-8 in seen counter DID".into()))?;
            offset += did_len;
            let mut device_id = [0u8; 16];
            device_id.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            let counter = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            map.insert((group_id, sender_did, device_id), counter);
        }
        Ok((map, &data[offset..]))
    }

    /// Serialize prior export secrets to bytes.
    ///
    /// Format: [num_groups: u64] then per group:
    ///   [group_id_len: u32] [group_id] [num_secrets: u32] then per secret: [32 bytes]
    fn serialize_prior_export_secrets(&self) -> Vec<u8> {
        let secrets = self.prior_export_secrets.read().unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(secrets.len() as u64).to_le_bytes());
        for (group_id, deque) in secrets.iter() {
            buf.extend_from_slice(&(group_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(group_id);
            buf.extend_from_slice(&(deque.len() as u32).to_le_bytes());
            for secret in deque {
                buf.extend_from_slice(secret);
            }
        }
        buf
    }

    /// Deserialize prior export secrets from bytes, returning the remaining slice.
    fn deserialize_prior_export_secrets_rest(
        data: &[u8],
    ) -> Result<(HashMap<Vec<u8>, VecDeque<Vec<u8>>>, &[u8])> {
        if data.len() < 8 {
            return Ok((HashMap::new(), data));
        }
        let num_groups = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let mut offset = 8;
        let mut map = HashMap::with_capacity(num_groups);
        for _ in 0..num_groups {
            if offset + 4 > data.len() {
                return Err(Error::Deserialization(
                    "prior export secrets truncated".into(),
                ));
            }
            let gid_len =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + gid_len > data.len() {
                return Err(Error::Deserialization(
                    "prior export secrets truncated".into(),
                ));
            }
            let group_id = data[offset..offset + gid_len].to_vec();
            offset += gid_len;
            if offset + 4 > data.len() {
                return Err(Error::Deserialization(
                    "prior export secrets truncated".into(),
                ));
            }
            let num_secrets =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let mut deque = VecDeque::with_capacity(num_secrets);
            for _ in 0..num_secrets {
                if offset + 32 > data.len() {
                    return Err(Error::Deserialization(
                        "prior export secret truncated".into(),
                    ));
                }
                deque.push_back(data[offset..offset + 32].to_vec());
                offset += 32;
            }
            map.insert(group_id, deque);
        }
        Ok((map, &data[offset..]))
    }

    // ── v5 digest / watermark / inbox_range serialization ──────────────────

    fn serialize_conversation_digests(&self) -> Vec<u8> {
        let digests = self.conversation_digests.read().unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(digests.len() as u64).to_le_bytes());
        for (group_id, state) in digests.iter() {
            buf.extend_from_slice(&(group_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(group_id);
            buf.extend_from_slice(&state.tip);
            buf.extend_from_slice(&state.append_count.to_le_bytes());
            buf.extend_from_slice(&(state.anchors.len() as u32).to_le_bytes());
            for anchor in &state.anchors {
                let rkey_bytes = anchor.rkey.as_bytes();
                buf.extend_from_slice(&(rkey_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(rkey_bytes);
                buf.extend_from_slice(&anchor.digest);
            }
        }
        buf
    }

    fn deserialize_conversation_digests(
        data: &[u8],
    ) -> Result<(HashMap<Vec<u8>, crate::digest::DigestState>, &[u8])> {
        if data.len() < 8 {
            return Ok((HashMap::new(), data));
        }
        let count = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let mut offset = 8;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if offset + 4 > data.len() {
                return Err(Error::Deserialization("digest table truncated".into()));
            }
            let gid_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + gid_len + 32 + 8 + 4 > data.len() {
                return Err(Error::Deserialization("digest table truncated".into()));
            }
            let group_id = data[offset..offset + gid_len].to_vec();
            offset += gid_len;
            let mut tip = [0u8; 32];
            tip.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            let append_count = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let anchor_count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            let mut anchors = Vec::with_capacity(anchor_count);
            for _ in 0..anchor_count {
                if offset + 2 > data.len() {
                    return Err(Error::Deserialization("digest anchor truncated".into()));
                }
                let rkey_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
                offset += 2;
                if offset + rkey_len + 32 > data.len() {
                    return Err(Error::Deserialization("digest anchor truncated".into()));
                }
                let rkey = String::from_utf8(data[offset..offset + rkey_len].to_vec())
                    .map_err(|_| Error::Deserialization("invalid UTF-8 in digest anchor rkey".into()))?;
                offset += rkey_len;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                anchors.push(crate::digest::DigestAnchor { rkey, digest });
            }
            map.insert(group_id, crate::digest::DigestState {
                tip,
                anchors,
                append_count,
                epoch_boundary_pending: false,
            });
        }
        Ok((map, &data[offset..]))
    }

    fn serialize_watermarks(&self) -> Vec<u8> {
        let watermarks = self.watermarks.read().unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(watermarks.len() as u64).to_le_bytes());
        for (group_id, rkey) in watermarks.iter() {
            buf.extend_from_slice(&(group_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(group_id);
            let rkey_bytes = rkey.as_bytes();
            buf.extend_from_slice(&(rkey_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(rkey_bytes);
        }
        buf
    }

    fn deserialize_watermarks(data: &[u8]) -> Result<(HashMap<Vec<u8>, String>, &[u8])> {
        if data.len() < 8 {
            return Ok((HashMap::new(), data));
        }
        let count = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let mut offset = 8;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if offset + 4 > data.len() {
                return Err(Error::Deserialization("watermark table truncated".into()));
            }
            let gid_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + gid_len + 2 > data.len() {
                return Err(Error::Deserialization("watermark table truncated".into()));
            }
            let group_id = data[offset..offset + gid_len].to_vec();
            offset += gid_len;
            let rkey_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + rkey_len > data.len() {
                return Err(Error::Deserialization("watermark rkey truncated".into()));
            }
            let rkey = String::from_utf8(data[offset..offset + rkey_len].to_vec())
                .map_err(|_| Error::Deserialization("invalid UTF-8 in watermark rkey".into()))?;
            offset += rkey_len;
            map.insert(group_id, rkey);
        }
        Ok((map, &data[offset..]))
    }

    fn serialize_inbox_ranges(&self) -> Vec<u8> {
        let ranges = self.inbox_ranges.read().unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(ranges.len() as u64).to_le_bytes());
        for (group_id, (oldest, newest)) in ranges.iter() {
            buf.extend_from_slice(&(group_id.len() as u32).to_le_bytes());
            buf.extend_from_slice(group_id);
            let oldest_bytes = oldest.as_bytes();
            buf.extend_from_slice(&(oldest_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(oldest_bytes);
            let newest_bytes = newest.as_bytes();
            buf.extend_from_slice(&(newest_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(newest_bytes);
        }
        buf
    }

    fn deserialize_inbox_ranges(data: &[u8]) -> Result<HashMap<Vec<u8>, (String, String)>> {
        if data.len() < 8 {
            return Ok(HashMap::new());
        }
        let count = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let mut offset = 8;
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            if offset + 4 > data.len() {
                return Err(Error::Deserialization("inbox_range table truncated".into()));
            }
            let gid_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + gid_len + 2 > data.len() {
                return Err(Error::Deserialization("inbox_range table truncated".into()));
            }
            let group_id = data[offset..offset + gid_len].to_vec();
            offset += gid_len;

            let oldest_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + oldest_len + 2 > data.len() {
                return Err(Error::Deserialization("inbox_range oldest_rkey truncated".into()));
            }
            let oldest = String::from_utf8(data[offset..offset + oldest_len].to_vec())
                .map_err(|_| Error::Deserialization("invalid UTF-8 in inbox_range".into()))?;
            offset += oldest_len;

            let newest_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + newest_len > data.len() {
                return Err(Error::Deserialization("inbox_range newest_rkey truncated".into()));
            }
            let newest = String::from_utf8(data[offset..offset + newest_len].to_vec())
                .map_err(|_| Error::Deserialization("invalid UTF-8 in inbox_range".into()))?;
            offset += newest_len;

            map.insert(group_id, (oldest, newest));
        }
        Ok(map)
    }

    // ── v5 public API ────────────────────────────────────────────────────────

    /// Append a user-visible message to the running digest for a conversation.
    ///
    /// Only call for events whose kind starts with `message.` (user-visible content).
    /// Control and modifier events are excluded from the digest.
    ///
    /// `digest_n = SHA256(digest_{n-1} || rkey || message_id)`
    pub fn append_to_digest(&self, group_id: &[u8], rkey: &str, message_id: &[u8; 16]) -> Result<()> {
        let should_anchor = {
            let mut digests = self.conversation_digests.write().unwrap();
            let state = digests.entry(group_id.to_vec()).or_default();
            // Transfer any pending epoch boundary flag.
            if self.digest_epoch_boundaries.read().unwrap().contains(group_id) {
                state.epoch_boundary_pending = true;
                self.digest_epoch_boundaries.write().unwrap().remove(group_id);
            }
            state.append(rkey, message_id)
        };
        // Update inbox range.
        {
            let mut ranges = self.inbox_ranges.write().unwrap();
            let entry = ranges.entry(group_id.to_vec()).or_insert_with(|| (rkey.to_string(), rkey.to_string()));
            if rkey < entry.0.as_str() {
                entry.0 = rkey.to_string();
            }
            if rkey > entry.1.as_str() {
                entry.1 = rkey.to_string();
            }
        }
        let _ = should_anchor; // anchor is stored inside DigestState
        Ok(())
    }

    /// Return the current digest tip for a conversation, or `None` if no messages yet.
    pub fn digest_tip(&self, group_id: &[u8]) -> Option<[u8; 32]> {
        self.conversation_digests.read().unwrap().get(group_id).map(|s| s.tip)
    }

    /// Return all stored digest anchors for a conversation.
    pub fn digest_anchors(&self, group_id: &[u8]) -> Vec<DigestAnchor> {
        self.conversation_digests.read().unwrap()
            .get(group_id)
            .map(|s| s.anchors.clone())
            .unwrap_or_default()
    }

    /// Return the (oldest_rkey, newest_rkey) range held locally for a conversation.
    pub fn range(&self, group_id: &[u8]) -> Option<(String, String)> {
        self.inbox_ranges.read().unwrap().get(group_id).cloned()
    }

    /// Return the oldest synced rkey (watermark) for a conversation.
    pub fn watermark(&self, group_id: &[u8]) -> Option<String> {
        self.watermarks.read().unwrap().get(group_id).cloned()
    }

    /// Set the sync watermark (oldest synced rkey) for a conversation.
    pub fn set_watermark(&self, group_id: &[u8], rkey: &str) -> Result<()> {
        self.watermarks.write().unwrap().insert(group_id.to_vec(), rkey.to_string());
        Ok(())
    }

    /// Signal that an epoch boundary has occurred for `group_id`.
    ///
    /// The next call to `append_to_digest` for this group will unconditionally
    /// save a digest anchor, regardless of whether the stride threshold is met.
    pub fn mark_digest_epoch_boundary(&self, group_id: &[u8]) {
        self.digest_epoch_boundaries.write().unwrap().insert(group_id.to_vec());
    }

    /// Save the current epoch's export secret to the prior secrets ring buffer.
    ///
    /// Call this **before** an epoch-advancing operation (add_member, remove_member,
    /// merge_staged_commit) so that `populate_candidate_tags` can generate tags for
    /// messages stranded at the old epoch.
    fn save_prior_export_secret(&self, group: &MlsGroup, group_id: &[u8]) {
        if let Ok(secret) = self.derive_tag_export_secret(group) {
            let mut secrets = self.prior_export_secrets.write().unwrap();
            let deque = secrets
                .entry(group_id.to_vec())
                .or_insert_with(VecDeque::new);
            deque.push_front(secret);
            while deque.len() > tag::MAX_PRIOR_EPOCHS {
                deque.pop_back();
            }
        }
    }

    /// Derive the epoch fingerprint for a group's current state.
    fn derive_epoch_fingerprint(group: &MlsGroup, provider: &MoatProvider) -> Result<Vec<u8>> {
        group
            .export_secret(
                provider,
                EPOCH_FINGERPRINT_LABEL,
                &[],
                EPOCH_FINGERPRINT_LEN,
            )
            .map_err(|e| Error::Encryption(format!("epoch fingerprint derivation failed: {e}")))
    }

    /// Derive the export secret used for tag derivation.
    fn derive_tag_export_secret(&self, group: &MlsGroup) -> Result<Vec<u8>> {
        group
            .export_secret(
                &self.provider,
                tag::TAG_EXPORT_SECRET_LABEL,
                &[],
                tag::TAG_EXPORT_SECRET_LEN,
            )
            .map_err(|e| Error::Encryption(format!("tag export secret derivation failed: {e}")))
    }

    /// Extract our own DID from the group's member list by matching the signature key.
    fn extract_own_did(&self, group: &MlsGroup, our_pubkey: &[u8]) -> Result<String> {
        let members: Vec<_> = group.members().collect();
        let member = members
            .iter()
            .find(|m| m.signature_key == our_pubkey)
            .ok_or_else(|| Error::GroupLoad("Own member not found in group".to_string()))?;
        let credential_bytes = member.credential.serialized_content();
        let moat_credential = MoatCredential::try_from_bytes(credential_bytes)
            .ok_or_else(|| Error::GroupLoad("Could not parse own credential".to_string()))?;
        Ok(moat_credential.did().to_string())
    }

    /// Compute SHA-256 hash of event bytes.
    fn hash_event_bytes(event_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(event_bytes);
        hasher.finalize().into()
    }

    /// Extract sender information from a processed message.
    fn extract_sender_info(
        &self,
        group: &MlsGroup,
        processed: &ProcessedMessage,
    ) -> Option<SenderInfo> {
        // Get the sender's leaf index
        let sender = processed.sender();
        let leaf_index = match sender {
            Sender::Member(leaf) => leaf.u32(),
            _ => return None,
        };

        // Get the member at that leaf index
        let members: Vec<_> = group.members().collect();
        let member = members.iter().find(|m| m.index.u32() == leaf_index)?;

        // Extract the credential bytes from the member's credential
        // OpenMLS Credential stores serialized content that we can access directly
        let credential_bytes = member.credential.serialized_content();

        // Try to parse as MoatCredential
        let moat_credential = MoatCredential::try_from_bytes(credential_bytes)?;

        Some(SenderInfo::from_credential(&moat_credential).with_leaf_index(leaf_index))
    }

    /// Extract credential information from a key package.
    ///
    /// Returns the MoatCredential if the key package contains a valid structured credential.
    pub fn extract_credential_from_key_package(
        &self,
        key_package_bytes: &[u8],
    ) -> Result<Option<MoatCredential>> {
        let key_package = KeyPackageIn::tls_deserialize_exact(key_package_bytes)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        let validated = key_package
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| Error::KeyPackageValidation(e.to_string()))?;

        let credential = validated.leaf_node().credential();
        let credential_bytes = credential.serialized_content();

        Ok(MoatCredential::try_from_bytes(credential_bytes))
    }

    /// Get all members of a group with their credentials.
    ///
    /// Returns a list of (leaf_index, credential) pairs for all group members.
    pub fn get_group_members(&self, group_id: &[u8]) -> Result<Vec<(u32, Option<MoatCredential>)>> {
        let group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        let members: Vec<_> = group
            .members()
            .map(|m| {
                let leaf_index = m.index.u32();
                let credential_bytes = m.credential.serialized_content();
                let moat_credential = MoatCredential::try_from_bytes(credential_bytes);
                (leaf_index, moat_credential)
            })
            .collect();

        Ok(members)
    }

    /// Get all DIDs currently in a group.
    ///
    /// Returns a deduplicated list of DIDs (a single DID may have multiple devices).
    pub fn get_group_dids(&self, group_id: &[u8]) -> Result<Vec<String>> {
        let members = self.get_group_members(group_id)?;
        let mut dids: Vec<String> = members
            .into_iter()
            .filter_map(|(_, cred)| cred.map(|c| c.did().to_string()))
            .collect();
        dids.sort();
        dids.dedup();
        Ok(dids)
    }

    /// Check if a DID already has a device in a group.
    ///
    /// Returns true if any member of the group has the same DID.
    pub fn is_did_in_group(&self, group_id: &[u8], did: &str) -> Result<bool> {
        let members = self.get_group_members(group_id)?;
        Ok(members
            .iter()
            .any(|(_, cred)| cred.as_ref().map_or(false, |c| c.did() == did)))
    }

    /// Derive the next tag for a group event and advance the counter.
    ///
    /// Use this for events that bypass `encrypt_event` (e.g., raw commits from
    /// `add_member`/`add_device`/`remove_member`). The tag is derived using the
    /// pre-advance epoch (the commit is the last event of the old epoch).
    ///
    /// Returns the derived tag.
    pub fn derive_next_tag(&self, group_id: &[u8], key_bundle: &[u8]) -> Result<[u8; 16]> {
        let group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let our_pubkey = signature_keys.to_public_vec();
        let sender_did = self.extract_own_did(&group, &our_pubkey)?;

        let epoch = group.epoch().as_u64();
        let export_secret = self.derive_tag_export_secret(&group)?;
        let counter_key = (group_id.to_vec(), epoch);

        let counter = {
            let mut counters = self.tag_counters.write().unwrap();
            let counter = counters.entry(counter_key).or_insert(0);
            let current = *counter;
            *counter = current + 1;
            current
        };

        tag::derive_event_tag(
            &export_secret,
            group_id,
            &sender_did,
            &self.device_id,
            counter,
        )
    }

    /// Generate candidate tags for recipient scanning.
    ///
    /// Returns a vector of (tag, counter) pairs that a specific sender device
    /// might have used for events in the given group at the given epoch.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The MLS group identifier
    /// * `sender_did` - The sender's ATProto DID
    /// * `sender_device_id` - The sender's 16-byte device ID
    /// * `from_counter` - Start of the scanning window (inclusive)
    /// * `count` - Number of candidate tags to generate
    pub fn generate_candidate_tags(
        &self,
        group_id: &[u8],
        sender_did: &str,
        sender_device_id: &[u8; 16],
        from_counter: u64,
        count: u64,
    ) -> Result<Vec<([u8; 16], u64)>> {
        let group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;
        let export_secret = self.derive_tag_export_secret(&group)?;
        tag::generate_candidate_tags(
            &export_secret,
            group_id,
            sender_did,
            sender_device_id,
            from_counter,
            count,
        )
    }

    /// Generate all candidate tags for every member in a group.
    ///
    /// Iterates all group members, and for each member with a device_id,
    /// generates `TAG_GAP_LIMIT` candidate tags starting from the last seen
    /// counter for that sender (or 0 if never seen). Also populates the
    /// internal `tag_metadata` reverse lookup so that `mark_tag_seen` can
    /// advance the seen counter when a tag is matched.
    ///
    /// Returns a flat list of all candidate tags.
    pub fn populate_candidate_tags(&self, group_id: &[u8]) -> Result<Vec<[u8; 16]>> {
        let group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;
        let export_secret = self.derive_tag_export_secret(&group)?;
        let members = self.get_group_members(group_id)?;
        let seen = self.seen_counters.read().unwrap();

        let mut all_tags = Vec::new();
        let mut metadata = self.tag_metadata.write().unwrap();

        // Current epoch: use seen_counters for the scanning window
        for (_leaf_idx, cred) in &members {
            let cred = match cred {
                Some(c) => c,
                None => continue,
            };
            let device_id = cred.device_id();
            let key = (group_id.to_vec(), cred.did().to_string(), *device_id);
            let from_counter = seen.get(&key).map_or(0, |&c| c + 1);
            let tags = tag::generate_candidate_tags(
                &export_secret,
                group_id,
                cred.did(),
                device_id,
                from_counter,
                tag::TAG_GAP_LIMIT,
            )?;
            for (t, counter) in tags {
                metadata.insert(
                    t,
                    (
                        group_id.to_vec(),
                        cred.did().to_string(),
                        *device_id,
                        counter,
                    ),
                );
                all_tags.push(t);
            }
        }

        // Prior epochs: decaying gap limits, always from counter 0
        let prior_secrets = self.prior_export_secrets.read().unwrap();
        if let Some(deque) = prior_secrets.get(group_id) {
            for (age_minus_1, prior_secret) in deque.iter().enumerate() {
                let age = age_minus_1 + 1; // age 1 = most recent prior epoch
                let gap = tag::prior_epoch_gap_limit(age);
                if gap == 0 {
                    break;
                }
                for (_leaf_idx, cred) in &members {
                    let cred = match cred {
                        Some(c) => c,
                        None => continue,
                    };
                    let device_id = cred.device_id();
                    let tags = tag::generate_candidate_tags(
                        prior_secret,
                        group_id,
                        cred.did(),
                        device_id,
                        0, // always scan from counter 0 for old epochs
                        gap,
                    )?;
                    for (t, counter) in tags {
                        metadata.insert(
                            t,
                            (
                                group_id.to_vec(),
                                cred.did().to_string(),
                                *device_id,
                                counter,
                            ),
                        );
                        all_tags.push(t);
                    }
                }
            }
        }

        Ok(all_tags)
    }

    /// Mark a tag as seen, advancing the seen counter for the corresponding sender.
    ///
    /// Call this after matching a tag from `populate_candidate_tags` to ensure
    /// the scanning window advances. Returns true if the tag was found in metadata
    /// and the counter was updated.
    pub fn mark_tag_seen(&self, tag: &[u8; 16]) -> bool {
        let meta = self.tag_metadata.read().unwrap();
        let entry = match meta.get(tag) {
            Some(e) => e.clone(),
            None => return false,
        };
        drop(meta);

        let (group_id, sender_did, device_id, counter) = entry;
        let key = (group_id, sender_did, device_id);
        let mut seen = self.seen_counters.write().unwrap();
        let current = seen.entry(key).or_insert(0);
        if counter >= *current {
            *current = counter;
        }
        true
    }

    /// Scan ahead with a wider window to try matching an unknown tag.
    ///
    /// When `populate_candidate_tags` misses because the sender's counter advanced
    /// beyond the gap limit, this method scans a much larger range (up to `scan_limit`)
    /// for all devices in the given group. Returns the matching tag metadata if found,
    /// and updates `tag_metadata` and `seen_counters` accordingly.
    pub fn try_scan_ahead_tag(
        &self,
        group_id: &[u8],
        target_tag: &[u8; 16],
        scan_limit: u64,
    ) -> Result<bool> {
        let group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;
        let export_secret = self.derive_tag_export_secret(&group)?;
        let members = self.get_group_members(group_id)?;
        let seen = self.seen_counters.read().unwrap();

        // Try current epoch first
        for (_leaf_idx, cred) in &members {
            let cred = match cred {
                Some(c) => c,
                None => continue,
            };
            let device_id = cred.device_id();
            let key = (group_id.to_vec(), cred.did().to_string(), *device_id);
            let from_counter = seen.get(&key).map_or(0, |&c| c + 1);

            let tags = tag::generate_candidate_tags(
                &export_secret,
                group_id,
                cred.did(),
                device_id,
                from_counter,
                scan_limit,
            )?;
            for (t, counter) in tags {
                if &t == target_tag {
                    let mut metadata = self.tag_metadata.write().unwrap();
                    metadata.insert(
                        t,
                        (
                            group_id.to_vec(),
                            cred.did().to_string(),
                            *device_id,
                            counter,
                        ),
                    );
                    drop(metadata);
                    drop(seen);
                    let mut seen_w = self.seen_counters.write().unwrap();
                    let current = seen_w.entry(key).or_insert(0);
                    if counter >= *current {
                        *current = counter;
                    }
                    return Ok(true);
                }
            }
        }

        // Try prior epoch secrets
        let prior_secrets = self.prior_export_secrets.read().unwrap();
        if let Some(deque) = prior_secrets.get(group_id) {
            for prior_secret in deque.iter() {
                for (_leaf_idx, cred) in &members {
                    let cred = match cred {
                        Some(c) => c,
                        None => continue,
                    };
                    let device_id = cred.device_id();
                    let tags = tag::generate_candidate_tags(
                        prior_secret,
                        group_id,
                        cred.did(),
                        device_id,
                        0,
                        scan_limit,
                    )?;
                    for (t, counter) in tags {
                        if &t == target_tag {
                            let mut metadata = self.tag_metadata.write().unwrap();
                            metadata.insert(
                                t,
                                (
                                    group_id.to_vec(),
                                    cred.did().to_string(),
                                    *device_id,
                                    counter,
                                ),
                            );
                            drop(metadata);
                            drop(seen);
                            // Don't advance seen_counters for old-epoch matches
                            // (they use epoch-specific counters, not the current epoch's)
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Add a new device (key package) to a group for an existing member's DID.
    ///
    /// This is used when a user adds a new device. The new device must have the same
    /// DID as an existing group member. Returns (commit_bytes, welcome_bytes).
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group to add the device to
    /// * `key_bundle` - The caller's key bundle (must be a group member)
    /// * `new_device_key_package` - The new device's key package
    ///
    /// # Returns
    ///
    /// A `WelcomeResult` containing the commit and welcome messages.
    pub fn add_device(
        &self,
        group_id: &[u8],
        key_bundle: &[u8],
        new_device_key_package: &[u8],
    ) -> Result<WelcomeResult> {
        // Extract credential from new device's key package
        let new_device_credential = self
            .extract_credential_from_key_package(new_device_key_package)?
            .ok_or_else(|| {
                Error::KeyPackageValidation(
                    "Cannot extract credential from key package".to_string(),
                )
            })?;

        // Verify the DID is already in the group (this is an add-device, not add-member)
        if !self.is_did_in_group(group_id, new_device_credential.did())? {
            return Err(Error::AddMember(format!(
                "DID {} is not a member of this group; use add_member instead",
                new_device_credential.did()
            )));
        }

        // Use the existing add_member method - MLS treats all members equally
        self.add_member(group_id, key_bundle, new_device_key_package)
    }

    /// Remove a member from a group by their leaf index.
    ///
    /// Returns the commit message to broadcast to other members.
    pub fn remove_member(
        &self,
        group_id: &[u8],
        key_bundle: &[u8],
        leaf_index: u32,
    ) -> Result<RemoveResult> {
        // Load the group
        let mut group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Save current export secret before epoch advances
        self.save_prior_export_secret(&group, group_id);

        // Create the remove proposal
        let leaf_node_index = LeafNodeIndex::new(leaf_index);
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &signature_keys, &[leaf_node_index])
            .map_err(|e| Error::RemoveMember(e.to_string()))?;

        // Track pending operation
        {
            let mut ops = self.pending_ops.write().unwrap();
            ops.insert(
                group_id.to_vec(),
                PendingOperation::RemoveMember {
                    key_bundle: key_bundle.to_vec(),
                    leaf_index,
                },
            );
        }

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

        self.pending_ops.write().unwrap().remove(group_id);

        // Serialize the commit
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(RemoveResult {
            commit: commit_bytes,
            group_id: group_id.to_vec(),
        })
    }

    /// Remove all devices for a specific DID from a group (kick user).
    ///
    /// Returns the commit message. This removes all members whose credential
    /// matches the specified DID.
    pub fn kick_user(
        &self,
        group_id: &[u8],
        key_bundle: &[u8],
        did_to_kick: &str,
    ) -> Result<RemoveResult> {
        // Find all leaf indices for this DID
        let members = self.get_group_members(group_id)?;
        let leaf_indices: Vec<u32> = members
            .into_iter()
            .filter_map(|(idx, cred)| cred.filter(|c| c.did() == did_to_kick).map(|_| idx))
            .collect();

        if leaf_indices.is_empty() {
            return Err(Error::RemoveMember(format!(
                "DID {} is not a member of this group",
                did_to_kick
            )));
        }

        // Load the group
        let mut group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Create leaf node indices
        let leaf_node_indices: Vec<LeafNodeIndex> = leaf_indices
            .iter()
            .map(|&idx| LeafNodeIndex::new(idx))
            .collect();

        // Save current export secret before epoch advances
        self.save_prior_export_secret(&group, group_id);

        // Remove all members with this DID
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &signature_keys, &leaf_node_indices)
            .map_err(|e| Error::RemoveMember(e.to_string()))?;

        // Track pending operation
        {
            let mut ops = self.pending_ops.write().unwrap();
            ops.insert(
                group_id.to_vec(),
                PendingOperation::KickUser {
                    key_bundle: key_bundle.to_vec(),
                    did: did_to_kick.to_string(),
                },
            );
        }

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

        self.pending_ops.write().unwrap().remove(group_id);

        // Serialize the commit
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(RemoveResult {
            commit: commit_bytes,
            group_id: group_id.to_vec(),
        })
    }

    /// Get our own leaf index in a group.
    ///
    /// Returns the leaf index of the current device in the group, or None if not found.
    pub fn get_own_leaf_index(&self, group_id: &[u8], key_bundle: &[u8]) -> Result<Option<u32>> {
        let group = match self.load_group(group_id)? {
            Some(g) => g,
            None => return Ok(None),
        };

        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        let our_pubkey = signature_keys.to_public_vec();
        let members: Vec<_> = group.members().collect();

        Ok(members
            .iter()
            .find(|m| m.signature_key == our_pubkey)
            .map(|m| m.index.u32()))
    }

    /// Sign a Drawbridge challenge message with the Ed25519 identity key from a key bundle.
    ///
    /// Returns `(signature_bytes, public_key_bytes)` as raw bytes (64 and 32 bytes respectively).
    /// The caller is responsible for encoding these as needed (e.g., base64 for JSON transport).
    ///
    /// The `message` is typically `"{nonce}\n{relay_url}\n{timestamp}\n"`.
    pub fn sign_drawbridge_challenge(
        key_bundle: &[u8],
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use ed25519_dalek::Signer;

        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        let seed: [u8; 32] = bundle
            .signature_private_key
            .try_into()
            .map_err(|_| Error::KeyGeneration(
                "signature_private_key must be 32 bytes; re-generate your key package".to_string(),
            ))?;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(message);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        Ok((signature.to_bytes().to_vec(), public_key))
    }

    /// Leave a group (remove self).
    ///
    /// Returns the commit message to broadcast. After calling this, the caller
    /// will no longer be able to decrypt messages in this group.
    pub fn leave_group(&self, group_id: &[u8], key_bundle: &[u8]) -> Result<RemoveResult> {
        // Load the group
        let mut group = self
            .load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle = serde_json::from_slice(key_bundle)
            .map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Find our own leaf index
        let our_pubkey = signature_keys.to_public_vec();
        let members: Vec<_> = group.members().collect();
        let our_leaf = members
            .iter()
            .find(|m| m.signature_key == our_pubkey)
            .ok_or_else(|| Error::RemoveMember("Cannot find self in group".to_string()))?;

        // Create remove proposal for ourselves
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &signature_keys, &[our_leaf.index])
            .map_err(|e| Error::RemoveMember(e.to_string()))?;

        // Track pending operation
        {
            let mut ops = self.pending_ops.write().unwrap();
            ops.insert(
                group_id.to_vec(),
                PendingOperation::LeaveGroup {
                    key_bundle: key_bundle.to_vec(),
                },
            );
        }

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

        self.pending_ops.write().unwrap().remove(group_id);

        // Serialize the commit
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(RemoveResult {
            commit: commit_bytes,
            group_id: group_id.to_vec(),
        })
    }
}

// Compile-time assertions: MoatSession must be Send + Sync for safe FFI usage.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<MoatSession>();
    }
};

#[cfg(test)]
mod tests;
