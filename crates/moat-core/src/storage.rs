//! MLS storage provider for OpenMLS
//!
//! This module provides an in-memory storage implementation for MLS state.
//! `MlsStorage` is a HashMap that implements OpenMLS's `StorageProvider` trait.
//! It has no file I/O — callers are responsible for persistence via
//! `export_state()` / `from_state()`.
//!
//! The main entry point is `MoatProvider`, which combines:
//! - `MlsStorage` for MLS key/group state storage
//! - `RustCrypto` from openmls_rust_crypto for cryptographic operations

use openmls_rust_crypto::RustCrypto;
use openmls_traits::storage::{traits, Entity, StorageProvider, CURRENT_VERSION};
use openmls_traits::OpenMlsProvider;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory storage for OpenMLS state.
///
/// This wraps a HashMap behind an `RwLock`, implementing OpenMLS's
/// `StorageProvider` trait.
///
/// There is no built-in persistence — callers control when and how state
/// is persisted using `export_state()` and `from_state()`.
///
/// # Thread Safety
///
/// `MlsStorage` is `Send + Sync`. All reads and writes are protected by the
/// internal `RwLock`. However, `MoatSession` operations that load-modify-save
/// a group are not atomic — callers must ensure only one thread operates on a
/// given session at a time (e.g., behind a `Mutex` on the mobile side).
pub struct MlsStorage {
    /// In-memory storage
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    /// Whether there are unsaved changes
    dirty: RwLock<bool>,
}

impl MlsStorage {
    /// Create a new empty storage.
    pub fn new() -> Self {
        Self {
            values: RwLock::new(HashMap::new()),
            dirty: RwLock::new(false),
        }
    }

    /// Check if there are unsaved changes.
    pub fn has_pending_changes(&self) -> bool {
        *self.dirty.read().unwrap()
    }

    /// Clear the dirty flag (call after persisting state).
    pub fn clear_pending_changes(&self) {
        *self.dirty.write().unwrap() = false;
    }

    /// Export the entire storage state as bytes.
    ///
    /// Callers are responsible for persisting this data however they choose
    /// (file, SQLite, platform storage, etc.).
    pub fn export_state(&self) -> Result<Vec<u8>, MlsStorageError> {
        let values = self.values.read().unwrap();

        // Use the same binary format as save_to_file
        let mut buf = Vec::new();

        // Write count
        buf.extend_from_slice(&(values.len() as u64).to_be_bytes());

        // Write each key-value pair
        for (k, v) in values.iter() {
            buf.extend_from_slice(&(k.len() as u64).to_be_bytes());
            buf.extend_from_slice(&(v.len() as u64).to_be_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(v);
        }

        Ok(buf)
    }

    /// Create a MlsStorage from exported state bytes.
    ///
    /// This creates an in-memory storage initialized with the given state.
    /// Use this for native-managed storage where the caller provides
    /// previously exported state.
    pub fn from_state(state: &[u8]) -> Result<Self, MlsStorageError> {
        let values = Self::parse_state(state)?;
        Ok(Self {
            values: RwLock::new(values),
            dirty: RwLock::new(false),
        })
    }

    /// Parse state bytes into a HashMap.
    fn parse_state(state: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, MlsStorageError> {
        use std::io::{Cursor, Read as IoRead};

        let mut cursor = Cursor::new(state);

        let read_u64 = |c: &mut Cursor<&[u8]>| -> Result<u64, MlsStorageError> {
            let mut buf = [0u8; 8];
            c.read_exact(&mut buf)
                .map_err(|e| MlsStorageError::Io(e.to_string()))?;
            Ok(u64::from_be_bytes(buf))
        };

        let read_bytes = |c: &mut Cursor<&[u8]>, len: usize| -> Result<Vec<u8>, MlsStorageError> {
            let mut buf = vec![0u8; len];
            c.read_exact(&mut buf)
                .map_err(|e| MlsStorageError::Io(e.to_string()))?;
            Ok(buf)
        };

        let count = read_u64(&mut cursor)? as usize;
        let mut map = HashMap::with_capacity(count);

        for _ in 0..count {
            let k_len = read_u64(&mut cursor)? as usize;
            let v_len = read_u64(&mut cursor)? as usize;
            let k = read_bytes(&mut cursor, k_len)?;
            let v = read_bytes(&mut cursor, v_len)?;
            map.insert(k, v);
        }

        Ok(map)
    }

    /// Mark storage as dirty (has unsaved changes).
    fn mark_dirty(&self) {
        *self.dirty.write().unwrap() = true;
    }

    /// Internal helper to write a value
    fn write_value(&self, label: &[u8], key: &[u8], value: Vec<u8>) -> Result<(), MlsStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        {
            let mut values = self.values.write().unwrap();
            values.insert(storage_key, value);
        }
        self.mark_dirty();
        Ok(())
    }

    /// Internal helper to append to a list value
    fn append_value(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), MlsStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        {
            let mut values = self.values.write().unwrap();
            let list_bytes = values.entry(storage_key).or_insert(b"[]".to_vec());
            let mut list: Vec<Vec<u8>> =
                serde_json::from_slice(list_bytes).map_err(|_| MlsStorageError::Serialization)?;
            list.push(value);
            *list_bytes = serde_json::to_vec(&list).map_err(|_| MlsStorageError::Serialization)?;
        }
        self.mark_dirty();
        Ok(())
    }

    /// Internal helper to remove an item from a list value
    fn remove_item_value(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), MlsStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        {
            let mut values = self.values.write().unwrap();
            let list_bytes = values.entry(storage_key).or_insert(b"[]".to_vec());
            let mut list: Vec<Vec<u8>> =
                serde_json::from_slice(list_bytes).map_err(|_| MlsStorageError::Serialization)?;
            if let Some(pos) = list.iter().position(|stored| stored == &value) {
                list.remove(pos);
            }
            *list_bytes = serde_json::to_vec(&list).map_err(|_| MlsStorageError::Serialization)?;
        }
        self.mark_dirty();
        Ok(())
    }

    /// Internal helper to read a value
    fn read_value<V: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, MlsStorageError> {
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(label, key.to_vec());
        let values = self.values.read().unwrap();

        match values.get(&storage_key) {
            Some(value) => serde_json::from_slice(value)
                .map(Some)
                .map_err(|_| MlsStorageError::Serialization),
            None => Ok(None),
        }
    }

    /// Internal helper to read a list value
    fn read_list_value<V: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<V>, MlsStorageError> {
        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&CURRENT_VERSION.to_be_bytes());

        let values = self.values.read().unwrap();

        let list_bytes: Vec<Vec<u8>> = match values.get(&storage_key) {
            Some(bytes) => {
                serde_json::from_slice(bytes).map_err(|_| MlsStorageError::Serialization)?
            }
            None => vec![],
        };

        list_bytes
            .iter()
            .map(|bytes| serde_json::from_slice(bytes).map_err(|_| MlsStorageError::Serialization))
            .collect()
    }

    /// Internal helper to delete a value
    fn delete_value(&self, label: &[u8], key: &[u8]) -> Result<(), MlsStorageError> {
        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&CURRENT_VERSION.to_be_bytes());

        {
            let mut values = self.values.write().unwrap();
            values.remove(&storage_key);
        }
        self.mark_dirty();
        Ok(())
    }
}

/// Errors from the file storage
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MlsStorageError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Serialization error")]
    Serialization,
    #[error("Value not found")]
    NotFound,
}

/// OpenMLS provider with MLS state storage.
///
/// This combines:
/// - `RustCrypto` for cryptographic operations (HPKE, signatures, AEAD, etc.)
/// - `MlsStorage` for MLS state storage
///
/// No file I/O — callers manage persistence via `export_state()` / `from_state()`.
///
/// # Example
///
/// ```ignore
/// use moat_core::MoatProvider;
///
/// let provider = MoatProvider::new();
/// // Use with OpenMLS operations...
/// ```
pub struct MoatProvider {
    crypto: RustCrypto,
    storage: MlsStorage,
}

impl MoatProvider {
    /// Create a new provider with empty storage.
    pub fn new() -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: MlsStorage::new(),
        }
    }

    /// Create a provider from previously exported state bytes.
    pub fn from_state(state: &[u8]) -> Result<Self, MlsStorageError> {
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: MlsStorage::from_state(state)?,
        })
    }

    /// Export the full storage state as bytes.
    pub fn export_state(&self) -> Result<Vec<u8>, MlsStorageError> {
        self.storage.export_state()
    }

    /// Check if there are unsaved changes.
    pub fn has_pending_changes(&self) -> bool {
        self.storage.has_pending_changes()
    }

    /// Clear the dirty flag (call after persisting state).
    pub fn clear_pending_changes(&self) {
        self.storage.clear_pending_changes()
    }
}

impl OpenMlsProvider for MoatProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MlsStorage;

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
) -> Result<Vec<u8>, MlsStorageError> {
    let mut key = serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?;
    key.extend_from_slice(&serde_json::to_vec(epoch).map_err(|_| MlsStorageError::Serialization)?);
    key.extend_from_slice(
        &serde_json::to_vec(&leaf_index).map_err(|_| MlsStorageError::Serialization)?,
    );
    Ok(key)
}

impl StorageProvider<CURRENT_VERSION> for MlsStorage {
    type Error = MlsStorageError;

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
        let key = serde_json::to_vec(&(group_id, proposal_ref))
            .map_err(|_| MlsStorageError::Serialization)?;
        let value = serde_json::to_vec(proposal).map_err(|_| MlsStorageError::Serialization)?;
        self.write_value(QUEUED_PROPOSAL_LABEL, &key, value)?;

        let key = serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?;
        let value = serde_json::to_vec(proposal_ref).map_err(|_| MlsStorageError::Serialization)?;
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(tree).map_err(|_| MlsStorageError::Serialization)?,
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
            .map_err(|_| MlsStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.mark_dirty();
        Ok(())
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
            serde_json::to_vec(group_context).map_err(|_| MlsStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.mark_dirty();
        Ok(())
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
            serde_json::to_vec(confirmation_tag).map_err(|_| MlsStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.mark_dirty();
        Ok(())
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
            serde_json::to_vec(signature_key_pair).map_err(|_| MlsStorageError::Serialization)?;
        let mut values = self.values.write().unwrap();
        values.insert(key, value);
        drop(values);
        self.mark_dirty();
        Ok(())
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
        )?;

        refs.into_iter()
            .map(|proposal_ref| {
                let key = serde_json::to_vec(&(group_id, &proposal_ref))
                    .map_err(|_| MlsStorageError::Serialization)?;
                let proposal: QueuedProposal = self
                    .read_value(QUEUED_PROPOSAL_LABEL, &key)?
                    .ok_or(MlsStorageError::NotFound)?;
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
                .map_err(|_| MlsStorageError::Serialization),
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
                .map_err(|_| MlsStorageError::Serialization),
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
                .map_err(|_| MlsStorageError::Serialization),
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
                .map_err(|_| MlsStorageError::Serialization),
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
                .map_err(|_| MlsStorageError::Serialization),
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
        let key = serde_json::to_vec(hash_ref).map_err(|_| MlsStorageError::Serialization)?;
        let value = serde_json::to_vec(key_package).map_err(|_| MlsStorageError::Serialization)?;
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
            &serde_json::to_vec(psk_id).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(psk).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(public_key).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(key_pair).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let key = serde_json::to_vec(hash_ref).map_err(|_| MlsStorageError::Serialization)?;
        self.read_value(KEY_PACKAGE_LABEL, &key)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_value(
            PSK_LABEL,
            &serde_json::to_vec(psk_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(public_key).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(public_key).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            KEY_PACKAGE_LABEL,
            &serde_json::to_vec(hash_ref).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            PSK_LABEL,
            &serde_json::to_vec(psk_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(group_state).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(message_secrets).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(resumption_psk_store).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(own_leaf_index).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
            serde_json::to_vec(group_epoch_secrets).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
        let value = serde_json::to_vec(key_pairs).map_err(|_| MlsStorageError::Serialization)?;
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
                serde_json::from_slice(value).map_err(|_| MlsStorageError::Serialization)
            }
            None => Err(MlsStorageError::NotFound),
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
        )?;

        {
            let mut values = self.values.write().unwrap();
            for proposal_ref in proposal_refs {
                let key = serde_json::to_vec(&(group_id, proposal_ref))
                    .map_err(|_| MlsStorageError::Serialization)?;
                values.remove(&key);
            }

            let key = build_key::<CURRENT_VERSION, _>(PROPOSAL_QUEUE_REFS_LABEL, group_id);
            values.remove(&key);
        }

        self.mark_dirty();
        Ok(())
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
        let key = serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?;
        let value = serde_json::to_vec(config).map_err(|_| MlsStorageError::Serialization)?;
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
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
        let key = serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?;
        let value = serde_json::to_vec(leaf_node).map_err(|_| MlsStorageError::Serialization)?;
        self.append_value(OWN_LEAF_NODES_LABEL, &key, value)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            OWN_LEAF_NODES_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            JOIN_CONFIG_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            TREE_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            GROUP_CONTEXT_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
        )
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_value(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?,
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
        let key = serde_json::to_vec(group_id).map_err(|_| MlsStorageError::Serialization)?;
        let value = serde_json::to_vec(proposal_ref).map_err(|_| MlsStorageError::Serialization)?;
        self.remove_item_value(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        let key = serde_json::to_vec(&(group_id, proposal_ref))
            .map_err(|_| MlsStorageError::Serialization)?;
        self.delete_value(QUEUED_PROPOSAL_LABEL, &key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage() {
        let storage = MlsStorage::new();

        // Test basic write and read
        storage
            .write_value(b"test", b"key1", b"value1".to_vec())
            .unwrap();

        let values = storage.values.read().unwrap();
        assert!(!values.is_empty());
    }

    #[test]
    fn test_dirty_flag() {
        let storage = MlsStorage::new();
        assert!(!storage.has_pending_changes());

        storage
            .write_value(b"test", b"key1", b"value1".to_vec())
            .unwrap();
        assert!(storage.has_pending_changes());

        storage.clear_pending_changes();
        assert!(!storage.has_pending_changes());
    }

    #[test]
    fn test_export_import_state() {
        let storage = MlsStorage::new();
        storage
            .write_value(b"test", b"key1", b"value1".to_vec())
            .unwrap();
        storage
            .write_value(b"test", b"key2", b"value2".to_vec())
            .unwrap();

        // Export
        let state = storage.export_state().unwrap();

        // Import into new storage
        let storage2 = MlsStorage::from_state(&state).unwrap();
        let values2 = storage2.values.read().unwrap();
        assert_eq!(values2.len(), 2);
    }

    #[test]
    fn test_export_empty_state() {
        let storage = MlsStorage::new();
        let state = storage.export_state().unwrap();

        let storage2 = MlsStorage::from_state(&state).unwrap();
        let values2 = storage2.values.read().unwrap();
        assert!(values2.is_empty());
    }
}
