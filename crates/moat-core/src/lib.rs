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
//! let credential = MoatCredential::new("did:plc:alice123", "My Laptop");
//! let (key_package, key_bundle) = session.generate_key_package(&credential).unwrap();
//! let group_id = session.create_group(&credential, &key_bundle).unwrap();
//!
//! // Caller persists state however they choose
//! let state = session.export_state().unwrap();
//! ```

pub(crate) mod credential;
pub(crate) mod error;
pub(crate) mod event;
pub(crate) mod padding;
pub(crate) mod stealth;
pub(crate) mod storage;
pub(crate) mod tag;

pub mod api;

use openmls::prelude::tls_codec::{Deserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls::framing::MlsMessageBodyIn;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

// Disambiguate from openmls::prelude::* and make accessible as moat_core::X
pub use crate::credential::MoatCredential;
pub use crate::error::{Error, ErrorCode, Result};
pub use crate::event::{Event, EventKind, SenderInfo};
pub use crate::padding::{pad_to_bucket, unpad, Bucket};
pub use crate::stealth::{encrypt_for_stealth, generate_stealth_keypair, try_decrypt_stealth};
pub(crate) use crate::storage::MoatProvider;
pub use crate::tag::derive_tag_from_group_id;

/// The ciphersuite used by Moat
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Serialized key bundle containing both key package and private key
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
pub struct KeyBundle {
    pub key_package: Vec<u8>,
    pub init_private_key: Vec<u8>,
    pub encryption_private_key: Vec<u8>,
    pub signature_key: Vec<u8>,
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
}

/// Result of decrypting an event
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
const STATE_VERSION: u16 = 1;

/// Size of the state header: 4 (magic) + 2 (version) + 16 (device_id) = 22 bytes.
const STATE_HEADER_SIZE: usize = 4 + 2 + 16;

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
/// `MoatSession` is `Send + Sync`. The internal storage uses `parking_lot::RwLock`
/// for lock-free reads and safe concurrent access.
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
/// # State format
///
/// The exported state has the following layout:
/// - `b"MOAT"` (4 bytes) — magic identifier
/// - Version (2 bytes, little-endian u16) — currently `1`
/// - Device ID (16 bytes) — random, generated once per device
/// - MLS state (remaining bytes) — raw storage data
///
/// # Example
///
/// ```
/// use moat_core::{MoatSession, MoatCredential};
///
/// // Create a new session
/// let session = MoatSession::new();
/// let credential = MoatCredential::new("did:plc:alice123", "My Laptop");
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
            1 => {}
            _ => return Err(Error::Deserialization(format!("unsupported state version: {version}"))),
        }
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&state[6..22]);
        let provider = MoatProvider::from_state(&state[STATE_HEADER_SIZE..])
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(Self { provider, device_id })
    }

    /// Export the full session state as bytes.
    ///
    /// The returned bytes include a version header and device ID, followed by
    /// raw MLS state. Pass to `from_state()` to restore the session.
    /// Also clears the dirty flag.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let raw_state = self.provider.export_state()
            .map_err(|e| Error::Storage(e.to_string()))?;
        self.provider.clear_pending_changes();
        let mut buf = Vec::with_capacity(STATE_HEADER_SIZE + raw_state.len());
        buf.extend_from_slice(STATE_MAGIC);
        buf.extend_from_slice(&STATE_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.device_id);
        buf.extend_from_slice(&raw_state);
        Ok(buf)
    }

    /// Get the device ID for this session.
    ///
    /// The device ID is a random 16-byte identifier generated once when the
    /// session is first created, and persisted through `export_state()`/`from_state()`.
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
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

        // Generate signature keypair
        let signature_keys = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

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
            .build(CIPHERSUITE, &self.provider, &signature_keys, credential_with_key)
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
        };

        let key_bundle_bytes =
            serde_json::to_vec(&key_bundle).map_err(|e| Error::Serialization(e.to_string()))?;

        Ok((key_package_bytes, key_bundle_bytes))
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
        let bundle: KeyBundle =
            serde_json::from_slice(key_bundle).map_err(|e| Error::Deserialization(e.to_string()))?;

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
            .build();

        // Create the group (persisted to storage via provider)
        let group = MlsGroup::new(&self.provider, &signature_keys, &group_config, credential_with_key)
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
        let mut group = self.load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle =
            serde_json::from_slice(key_bundle).map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Deserialize the new member's key package
        let new_key_package = KeyPackageIn::tls_deserialize_exact(new_member_key_package)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Validate the key package
        let validated_key_package = new_key_package
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| Error::KeyPackageValidation(e.to_string()))?;

        // Add the member
        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &signature_keys, &[validated_key_package])
            .map_err(|e| Error::AddMember(e.to_string()))?;

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

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
    pub fn process_welcome(
        &self,
        welcome_bytes: &[u8],
    ) -> Result<Vec<u8>> {
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
            .build();

        let group = StagedWelcome::new_from_welcome(&self.provider, &join_config, welcome, None)
            .map_err(|e| Error::ProcessWelcome(e.to_string()))?
            .into_group(&self.provider)
            .map_err(|e| Error::ProcessWelcome(e.to_string()))?;

        let group_id = group.group_id().as_slice().to_vec();
        Ok(group_id)
    }

    /// Encrypt an event for a group.
    ///
    /// The event is serialized, padded, and encrypted using MLS.
    /// Returns (conversation_tag, ciphertext).
    pub fn encrypt_event(
        &self,
        group_id: &[u8],
        key_bundle: &[u8],
        event: &Event,
    ) -> Result<EncryptResult> {
        // Load the group
        let mut group = self.load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Get signature keys from key bundle
        let bundle: KeyBundle =
            serde_json::from_slice(key_bundle).map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Serialize and pad the event
        let event_bytes = event.to_bytes()
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let padded = pad_to_bucket(&event_bytes);

        // Encrypt the message
        let ciphertext = group
            .create_message(&self.provider, &signature_keys, &padded)
            .map_err(|e| Error::Encryption(e.to_string()))?;

        // Serialize the ciphertext
        let ciphertext_bytes = ciphertext
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Derive conversation tag for current epoch
        let tag = derive_tag_from_group_id(group_id, group.epoch().as_u64())?;

        Ok(EncryptResult {
            new_group_state: Vec::new(), // State is managed by provider
            tag,
            ciphertext: ciphertext_bytes,
        })
    }

    /// Decrypt a ciphertext for a group.
    ///
    /// The ciphertext is decrypted, unpadded, and deserialized.
    /// Returns the decrypted event along with sender information.
    pub fn decrypt_event(
        &self,
        group_id: &[u8],
        ciphertext: &[u8],
    ) -> Result<DecryptResult> {
        // Load the group
        let mut group = self.load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize the MLS message
        let mls_message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Convert to protocol message
        let protocol_message = mls_message
            .try_into_protocol_message()
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Process the message
        let processed = group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| Error::Decryption(e.to_string()))?;

        // Extract sender info from the credential
        let sender = self.extract_sender_info(&group, &processed);

        // Extract the application message
        let padded_bytes = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => app_msg.into_bytes(),
            ProcessedMessageContent::ProposalMessage(_) => {
                return Err(Error::InvalidMessageType("Unexpected proposal message".to_string()));
            }
            ProcessedMessageContent::StagedCommitMessage(_) => {
                return Err(Error::InvalidMessageType("Unexpected commit message".to_string()));
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                return Err(Error::InvalidMessageType("Unexpected external join".to_string()));
            }
        };

        // Unpad and deserialize
        let event_bytes = unpad(&padded_bytes);
        let event = Event::from_bytes(&event_bytes)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        Ok(DecryptResult {
            new_group_state: Vec::new(), // State is managed by provider
            event,
            sender,
        })
    }

    /// Extract sender information from a processed message.
    fn extract_sender_info(&self, group: &MlsGroup, processed: &ProcessedMessage) -> Option<SenderInfo> {
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
    pub fn extract_credential_from_key_package(&self, key_package_bytes: &[u8]) -> Result<Option<MoatCredential>> {
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
        let group = self.load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        let members: Vec<_> = group.members().map(|m| {
            let leaf_index = m.index.u32();
            let credential_bytes = m.credential.serialized_content();
            let moat_credential = MoatCredential::try_from_bytes(credential_bytes);
            (leaf_index, moat_credential)
        }).collect();

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
        Ok(members.iter().any(|(_, cred)| {
            cred.as_ref().map_or(false, |c| c.did() == did)
        }))
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
        let new_device_credential = self.extract_credential_from_key_package(new_device_key_package)?
            .ok_or_else(|| Error::KeyPackageValidation(
                "Cannot extract credential from key package".to_string()
            ))?;

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
        let mut group = self.load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle =
            serde_json::from_slice(key_bundle).map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Create the remove proposal
        let leaf_node_index = LeafNodeIndex::new(leaf_index);
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &signature_keys, &[leaf_node_index])
            .map_err(|e| Error::RemoveMember(e.to_string()))?;

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

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
            .filter_map(|(idx, cred)| {
                cred.filter(|c| c.did() == did_to_kick).map(|_| idx)
            })
            .collect();

        if leaf_indices.is_empty() {
            return Err(Error::RemoveMember(format!(
                "DID {} is not a member of this group",
                did_to_kick
            )));
        }

        // Load the group
        let mut group = self.load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle =
            serde_json::from_slice(key_bundle).map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Create leaf node indices
        let leaf_node_indices: Vec<LeafNodeIndex> = leaf_indices
            .iter()
            .map(|&idx| LeafNodeIndex::new(idx))
            .collect();

        // Remove all members with this DID
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &signature_keys, &leaf_node_indices)
            .map_err(|e| Error::RemoveMember(e.to_string()))?;

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

        // Serialize the commit
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(RemoveResult {
            commit: commit_bytes,
            group_id: group_id.to_vec(),
        })
    }

    /// Leave a group (remove self).
    ///
    /// Returns the commit message to broadcast. After calling this, the caller
    /// will no longer be able to decrypt messages in this group.
    pub fn leave_group(
        &self,
        group_id: &[u8],
        key_bundle: &[u8],
    ) -> Result<RemoveResult> {
        // Load the group
        let mut group = self.load_group(group_id)?
            .ok_or_else(|| Error::GroupLoad("Group not found".to_string()))?;

        // Deserialize our key bundle to get signature keys
        let bundle: KeyBundle =
            serde_json::from_slice(key_bundle).map_err(|e| Error::Deserialization(e.to_string()))?;
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Find our own leaf index
        let our_pubkey = signature_keys.to_public_vec();
        let members: Vec<_> = group.members().collect();
        let our_leaf = members.iter().find(|m| m.signature_key == our_pubkey)
            .ok_or_else(|| Error::RemoveMember("Cannot find self in group".to_string()))?;

        // Create remove proposal for ourselves
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &signature_keys, &[our_leaf.index])
            .map_err(|e| Error::RemoveMember(e.to_string()))?;

        // Merge the pending commit
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| Error::MergeCommit(e.to_string()))?;

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
