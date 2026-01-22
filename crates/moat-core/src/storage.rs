//! File-backed storage provider for OpenMLS
//!
//! This module provides a persistent storage implementation that saves
//! MLS state to disk, allowing sessions to survive application restarts.
//!
//! The main entry point is `MoatProvider`, which combines:
//! - `FileStorage` for persistent key/group state storage
//! - `RustCrypto` from openmls_rust_crypto for cryptographic operations

use openmls_rust_crypto::RustCrypto;
use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};
use openmls_traits::OpenMlsProvider;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::RwLock;

/// File-backed storage for OpenMLS state.
///
/// This wraps an in-memory HashMap but persists to disk on every write
/// and can be loaded from disk on startup.
pub struct FileStorage {
    /// The path to the storage file
    path: PathBuf,
    /// In-memory cache of the storage
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl FileStorage {
    /// Create a new FileStorage at the given path.
    ///
    /// If the file exists, it will be loaded. Otherwise, an empty storage is created.
    pub fn new(path: PathBuf) -> Result<Self, FileStorageError> {
        let values = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            // Ensure parent directory exists
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| FileStorageError::Io(e.to_string()))?;
            }
            HashMap::new()
        };

        Ok(Self {
            path,
            values: RwLock::new(values),
        })
    }

    /// Create an in-memory only storage (for testing)
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Load storage from a file
    fn load_from_file(path: &PathBuf) -> Result<HashMap<Vec<u8>, Vec<u8>>, FileStorageError> {
        let file = File::open(path).map_err(|e| FileStorageError::Io(e.to_string()))?;
        let mut reader = BufReader::new(file);

        let read_u64 = |r: &mut BufReader<File>| -> Result<u64, FileStorageError> {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf)
                .map_err(|e| FileStorageError::Io(e.to_string()))?;
            Ok(u64::from_be_bytes(buf))
        };

        let read_bytes =
            |r: &mut BufReader<File>, len: usize| -> Result<Vec<u8>, FileStorageError> {
                let mut buf = vec![0u8; len];
                r.read_exact(&mut buf)
                    .map_err(|e| FileStorageError::Io(e.to_string()))?;
                Ok(buf)
            };

        let count = read_u64(&mut reader)? as usize;
        let mut map = HashMap::with_capacity(count);

        for _ in 0..count {
            let k_len = read_u64(&mut reader)? as usize;
            let v_len = read_u64(&mut reader)? as usize;
            let k = read_bytes(&mut reader, k_len)?;
            let v = read_bytes(&mut reader, v_len)?;
            map.insert(k, v);
        }

        Ok(map)
    }

    /// Save storage to file
    fn save_to_file(&self) -> Result<(), FileStorageError> {
        // Skip saving for in-memory storage
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }

        let values = self.values.read().unwrap();

        // Write to a temp file first, then rename for atomicity
        let temp_path = self.path.with_extension("tmp");
        let file = File::create(&temp_path).map_err(|e| FileStorageError::Io(e.to_string()))?;
        let mut writer = BufWriter::new(file);

        // Write count
        writer
            .write_all(&(values.len() as u64).to_be_bytes())
            .map_err(|e| FileStorageError::Io(e.to_string()))?;

        // Write each key-value pair
        for (k, v) in values.iter() {
            writer
                .write_all(&(k.len() as u64).to_be_bytes())
                .map_err(|e| FileStorageError::Io(e.to_string()))?;
            writer
                .write_all(&(v.len() as u64).to_be_bytes())
                .map_err(|e| FileStorageError::Io(e.to_string()))?;
            writer
                .write_all(k)
                .map_err(|e| FileStorageError::Io(e.to_string()))?;
            writer
                .write_all(v)
                .map_err(|e| FileStorageError::Io(e.to_string()))?;
        }

        writer
            .flush()
            .map_err(|e| FileStorageError::Io(e.to_string()))?;
        drop(writer);

        // Atomic rename
        fs::rename(&temp_path, &self.path).map_err(|e| FileStorageError::Io(e.to_string()))?;

        Ok(())
    }

    /// Internal helper to write a value
    fn write_value(&self, label: &[u8], key: &[u8], value: Vec<u8>) -> Result<(), FileStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        {
            let mut values = self.values.write().unwrap();
            values.insert(storage_key, value);
        }
        self.save_to_file()
    }

    /// Internal helper to append to a list value
    fn append_value(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), FileStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        {
            let mut values = self.values.write().unwrap();
            let list_bytes = values.entry(storage_key).or_insert(b"[]".to_vec());
            let mut list: Vec<Vec<u8>> =
                serde_json::from_slice(list_bytes).map_err(|_| FileStorageError::Serialization)?;
            list.push(value);
            *list_bytes =
                serde_json::to_vec(&list).map_err(|_| FileStorageError::Serialization)?;
        }
        self.save_to_file()
    }

    /// Internal helper to remove an item from a list value
    fn remove_item_value(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), FileStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        {
            let mut values = self.values.write().unwrap();
            let list_bytes = values.entry(storage_key).or_insert(b"[]".to_vec());
            let mut list: Vec<Vec<u8>> =
                serde_json::from_slice(list_bytes).map_err(|_| FileStorageError::Serialization)?;
            if let Some(pos) = list.iter().position(|stored| stored == &value) {
                list.remove(pos);
            }
            *list_bytes =
                serde_json::to_vec(&list).map_err(|_| FileStorageError::Serialization)?;
        }
        self.save_to_file()
    }

    /// Internal helper to read a value
    fn read_value<V: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, FileStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        let values = self.values.read().unwrap();

        match values.get(&storage_key) {
            Some(value) => serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| FileStorageError::Serialization),
            None => Ok(None),
        }
    }

    /// Internal helper to read a list value
    fn read_list_value<V: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<V>, FileStorageError> {
        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&CURRENT_VERSION.to_be_bytes());

        let values = self.values.read().unwrap();

        let list_bytes: Vec<Vec<u8>> = match values.get(&storage_key) {
            Some(bytes) => {
                serde_json::from_slice(bytes).map_err(|_| FileStorageError::Serialization)?
            }
            None => vec![],
        };

        list_bytes
            .iter()
            .map(|bytes| {
                serde_json::from_slice(bytes).map_err(|_| FileStorageError::Serialization)
            })
            .collect()
    }

    /// Internal helper to delete a value
    fn delete_value(&self, label: &[u8], key: &[u8]) -> Result<(), FileStorageError> {
        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&CURRENT_VERSION.to_be_bytes());

        {
            let mut values = self.values.write().unwrap();
            values.remove(&storage_key);
        }
        self.save_to_file()
    }
}

/// Errors from the file storage
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum FileStorageError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Serialization error")]
    Serialization,
    #[error("Value not found")]
    NotFound,
}

/// OpenMLS provider with persistent file-backed storage.
///
/// This combines:
/// - `RustCrypto` for cryptographic operations (HPKE, signatures, AEAD, etc.)
/// - `FileStorage` for persistent state storage
///
/// Use this instead of `OpenMlsRustCrypto` when you need MLS state to survive
/// application restarts.
///
/// # Example
///
/// ```no_run
/// use moat_core::MoatProvider;
/// use std::path::PathBuf;
///
/// let provider = MoatProvider::new(PathBuf::from("~/.moat/mls_state.bin")).unwrap();
/// // Use with OpenMLS operations...
/// ```
pub struct MoatProvider {
    crypto: RustCrypto,
    storage: FileStorage,
}

impl MoatProvider {
    /// Create a new MoatProvider with file-backed storage at the given path.
    ///
    /// If the file exists, existing state will be loaded.
    /// If it doesn't exist, a new storage file will be created.
    pub fn new(storage_path: PathBuf) -> Result<Self, FileStorageError> {
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: FileStorage::new(storage_path)?,
        })
    }

    /// Create an in-memory only provider (for testing).
    ///
    /// State will not be persisted to disk.
    pub fn in_memory() -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: FileStorage::in_memory(),
        }
    }
}

impl OpenMlsProvider for MoatProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = FileStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// Storage labels (same as MemoryStorage)
const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";
const TREE_LABEL: &[u8] = b"Tree";
const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";
const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";

/// Build a storage key with version
fn build_key_from_vec<const V: u16>(label: &[u8], key: Vec<u8>) -> Vec<u8> {
    let mut out = label.to_vec();
    out.extend_from_slice(&key);
    out.extend_from_slice(&V.to_be_bytes());
    out
}

/// Build a storage key from a serializable value
fn build_key<const V: u16, K: Serialize>(label: &[u8], key: K) -> Vec<u8> {
    build_key_from_vec::<V>(label, serde_json::to_vec(&key).unwrap())
}

/// Build epoch key pairs ID
fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, FileStorageError> {
    let mut key =
        serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?;
    key.extend_from_slice(
        &serde_json::to_vec(epoch).map_err(|_| FileStorageError::Serialization)?,
    );
    key.extend_from_slice(
        &serde_json::to_vec(&leaf_index).map_err(|_| FileStorageError::Serialization)?,
    );
    Ok(key)
}

impl StorageProvider<CURRENT_VERSION> for FileStorage {
    type Error = FileStorageError;

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let key =
            serde_json::to_vec(&(group_id, proposal_ref)).map_err(|_| FileStorageError::Serialization)?;
        let value = serde_json::to_vec(proposal).map_err(|_| FileStorageError::Serialization)?;
        self.write_value(QUEUED_PROPOSAL_LABEL, &key, value)?;

        let key = serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?;
        let value =
            serde_json::to_vec(proposal_ref).map_err(|_| FileStorageError::Serialization)?;
        self.append_value(PROPOSAL_QUEUE_REFS_LABEL, &key, value)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write_value(
            TREE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(tree).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(INTERIM_TRANSCRIPT_HASH_LABEL, group_id);
        let value = serde_json::to_vec(interim_transcript_hash)
            .map_err(|_| FileStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.save_to_file()
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(GROUP_CONTEXT_LABEL, group_id);
        let value =
            serde_json::to_vec(group_context).map_err(|_| FileStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.save_to_file()
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(CONFIRMATION_TAG_LABEL, group_id);
        let value =
            serde_json::to_vec(confirmation_tag).map_err(|_| FileStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.save_to_file()
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(SIGNATURE_KEY_PAIR_LABEL, public_key);
        let value =
            serde_json::to_vec(signature_key_pair).map_err(|_| FileStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.save_to_file()
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list_value(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> = self.read_list_value(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )?;

        refs.into_iter()
            .map(|proposal_ref| {
                let key = serde_json::to_vec(&(group_id, &proposal_ref))
                    .map_err(|_| FileStorageError::Serialization)?;
                let proposal: QueuedProposal = self
                    .read_value(QUEUED_PROPOSAL_LABEL, &key)?
                    .ok_or(FileStorageError::NotFound)?;
                Ok((proposal_ref, proposal))
            })
            .collect()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(TREE_LABEL, group_id);
        let values = self.values.read().unwrap();
        match values.get(&key) {
            Some(value) => serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| FileStorageError::Serialization),
            None => Ok(None),
        }
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(GROUP_CONTEXT_LABEL, group_id);
        let values = self.values.read().unwrap();
        match values.get(&key) {
            Some(value) => serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| FileStorageError::Serialization),
            None => Ok(None),
        }
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(INTERIM_TRANSCRIPT_HASH_LABEL, group_id);
        let values = self.values.read().unwrap();
        match values.get(&key) {
            Some(value) => serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| FileStorageError::Serialization),
            None => Ok(None),
        }
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(CONFIRMATION_TAG_LABEL, group_id);
        let values = self.values.read().unwrap();
        match values.get(&key) {
            Some(value) => serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| FileStorageError::Serialization),
            None => Ok(None),
        }
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let key = build_key::<CURRENT_VERSION, _>(SIGNATURE_KEY_PAIR_LABEL, public_key);
        let values = self.values.read().unwrap();
        match values.get(&key) {
            Some(value) => serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| FileStorageError::Serialization),
            None => Ok(None),
        }
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(hash_ref).map_err(|_| FileStorageError::Serialization)?;
        let value =
            serde_json::to_vec(key_package).map_err(|_| FileStorageError::Serialization)?;
        self.write_value(KEY_PACKAGE_LABEL, &key, value)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write_value(
            PSK_LABEL,
            &serde_json::to_vec(psk_id).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(psk).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_value(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(key_pair).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let key = serde_json::to_vec(hash_ref).map_err(|_| FileStorageError::Serialization)?;
        self.read_value(KEY_PACKAGE_LABEL, &key)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_value(
            PSK_LABEL,
            &serde_json::to_vec(psk_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read_value(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            KEY_PACKAGE_LABEL,
            &serde_json::to_vec(hash_ref).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            PSK_LABEL,
            &serde_json::to_vec(psk_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read_value(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write_value(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(group_state).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read_value(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write_value(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(message_secrets).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read_value(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write_value(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(resumption_psk_store)
                .map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read_value(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write_value(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(own_leaf_index).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read_value(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write_value(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
            serde_json::to_vec(group_epoch_secrets)
                .map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let value = serde_json::to_vec(key_pairs).map_err(|_| FileStorageError::Serialization)?;
        self.write_value(EPOCH_KEY_PAIRS_LABEL, &key, value)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, key);
        let values = self.values.read().unwrap();

        match values.get(&storage_key) {
            Some(value) => {
                serde_json::from_slice(value).map_err(|_| FileStorageError::Serialization)
            }
            None => Err(FileStorageError::NotFound),
        }
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.delete_value(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let proposal_refs: Vec<ProposalRef> = self.read_list_value(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )?;

        {
            let mut values = self.values.write().unwrap();
            for proposal_ref in proposal_refs {
                let key = serde_json::to_vec(&(group_id, proposal_ref))
                    .map_err(|_| FileStorageError::Serialization)?;
                values.remove(&key);
            }

            let key = build_key::<CURRENT_VERSION, _>(PROPOSAL_QUEUE_REFS_LABEL, group_id);
            values.remove(&key);
        }

        self.save_to_file()
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read_value(
            JOIN_CONFIG_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?;
        let value = serde_json::to_vec(config).map_err(|_| FileStorageError::Serialization)?;
        self.write_value(JOIN_CONFIG_LABEL, &key, value)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list_value(
            OWN_LEAF_NODES_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?;
        let value = serde_json::to_vec(leaf_node).map_err(|_| FileStorageError::Serialization)?;
        self.append_value(OWN_LEAF_NODES_LABEL, &key, value)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            OWN_LEAF_NODES_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            JOIN_CONFIG_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            TREE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            GROUP_CONTEXT_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?,
        )
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id).map_err(|_| FileStorageError::Serialization)?;
        let value =
            serde_json::to_vec(proposal_ref).map_err(|_| FileStorageError::Serialization)?;
        self.remove_item_value(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        let key =
            serde_json::to_vec(&(group_id, proposal_ref)).map_err(|_| FileStorageError::Serialization)?;
        self.delete_value(QUEUED_PROPOSAL_LABEL, &key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_storage() {
        let storage = FileStorage::in_memory();

        // Test basic write and read
        storage.write_value(b"test", b"key1", b"value1".to_vec()).unwrap();

        let values = storage.values.read().unwrap();
        assert!(!values.is_empty());
    }

    #[test]
    fn test_file_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_storage.bin");

        // Write some data
        {
            let storage = FileStorage::new(path.clone()).unwrap();
            storage.write_value(b"test", b"key1", b"value1".to_vec()).unwrap();
        }

        // Read it back in a new instance
        {
            let storage = FileStorage::new(path.clone()).unwrap();
            let values = storage.values.read().unwrap();
            assert!(!values.is_empty());
        }
    }
}
