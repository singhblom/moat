//! moat-core: Pure MLS logic for Moat encrypted messenger
//!
//! This crate provides stateless, bytes-in/bytes-out MLS operations.
//! No IO operations are performed - all state is passed in and out as byte slices.

mod error;
mod padding;
mod tag;

pub use error::{Error, Result};
pub use padding::{pad_to_bucket, unpad, Bucket};
pub use tag::{derive_conversation_tag, derive_tag_from_group_id};

use openmls::prelude::*;
use openmls::prelude::tls_codec::{Deserialize, Serialize as TlsSerialize};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

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

/// Serialized group state for storage
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
pub struct GroupState {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub serialized: Vec<u8>,
}

/// Result of creating a welcome message for a new member
pub struct WelcomeResult {
    pub new_group_state: Vec<u8>,
    pub welcome: Vec<u8>,
    pub commit: Vec<u8>,
}

/// Result of encrypting a message
pub struct EncryptResult {
    pub new_group_state: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Result of decrypting a message
pub struct DecryptResult {
    pub new_group_state: Vec<u8>,
    pub plaintext: Vec<u8>,
}

/// Pure MLS operations with no IO
pub struct MoatCore;

impl MoatCore {
    /// Generate a new key package for the given identity.
    ///
    /// Returns the serialized key package (to publish) and the serialized key bundle (to store locally).
    pub fn generate_key_package(identity: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let provider = &OpenMlsRustCrypto::default();

        // Generate signature keypair
        let signature_keys = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        // Store the signature keys so the provider can use them
        signature_keys
            .store(provider.storage())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        // Create basic credential
        let credential = BasicCredential::new(identity.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        // Generate key package
        let key_package_bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                provider,
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

        // Get the private keys from the key package bundle
        let init_private_key_bytes = key_package_bundle
            .init_private_key()
            .tls_serialize_detached()
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // For the encryption private key, we need to get it differently
        // Note: In OpenMLS 0.6.0, the encryption_key_pair() method is pub(crate)
        // so we'll store a placeholder for now - this will be handled by the storage provider
        let encryption_private_key_bytes = Vec::new();

        // Create key bundle
        let key_bundle = KeyBundle {
            key_package: key_package_bytes.clone(),
            init_private_key: init_private_key_bytes,
            encryption_private_key: encryption_private_key_bytes,
            signature_key: signature_key_bytes,
        };

        let key_bundle_bytes =
            serde_json::to_vec(&key_bundle).map_err(|e| Error::Serialization(e.to_string()))?;

        Ok((key_package_bytes, key_bundle_bytes))
    }

    /// Create a new MLS group.
    ///
    /// Returns the serialized group state.
    pub fn create_group(identity: &[u8], key_bundle: &[u8]) -> Result<Vec<u8>> {
        let provider = &OpenMlsRustCrypto::default();

        // Deserialize key bundle
        let bundle: KeyBundle =
            serde_json::from_slice(key_bundle).map_err(|e| Error::Deserialization(e.to_string()))?;

        // Deserialize signature keys
        let signature_keys = SignatureKeyPair::tls_deserialize_exact(&bundle.signature_key)
            .map_err(|e| Error::Deserialization(e.to_string()))?;

        // Store the signature keys
        signature_keys
            .store(provider.storage())
            .map_err(|e| Error::KeyGeneration(e.to_string()))?;

        // Create credential
        let credential = BasicCredential::new(identity.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        // Create group config
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        // Create the group
        let group = MlsGroup::new(
            provider,
            &signature_keys,
            &group_config,
            credential_with_key,
        )
        .map_err(|e| Error::GroupCreation(e.to_string()))?;

        // Serialize group state
        Self::serialize_group(&group, provider)
    }

    /// Get the current epoch of the group from serialized state.
    pub fn get_epoch(group_state: &[u8]) -> Result<u64> {
        let state: GroupState =
            serde_json::from_slice(group_state).map_err(|e| Error::Deserialization(e.to_string()))?;
        Ok(state.epoch)
    }

    /// Get the group ID from serialized state.
    pub fn get_group_id(group_state: &[u8]) -> Result<Vec<u8>> {
        let state: GroupState =
            serde_json::from_slice(group_state).map_err(|e| Error::Deserialization(e.to_string()))?;
        Ok(state.group_id)
    }

    // Internal helpers

    fn serialize_group(group: &MlsGroup, provider: &OpenMlsRustCrypto) -> Result<Vec<u8>> {
        // Export a secret for verification that the group is valid
        let exported = group
            .export_secret(provider, "moat-export", &[], 32)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Create a simplified state representation
        let state = GroupState {
            group_id: group.group_id().as_slice().to_vec(),
            epoch: group.epoch().as_u64(),
            serialized: exported,
        };

        serde_json::to_vec(&state).map_err(|e| Error::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
