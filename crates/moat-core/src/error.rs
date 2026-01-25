//! Error types for moat-core

use thiserror::Error;

/// Result type for moat-core operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during MLS operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("key package generation failed: {0}")]
    KeyPackageGeneration(String),

    #[error("key package validation failed: {0}")]
    KeyPackageValidation(String),

    #[error("group creation failed: {0}")]
    GroupCreation(String),

    #[error("group load failed: {0}")]
    GroupLoad(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("deserialization failed: {0}")]
    Deserialization(String),

    #[error("invalid message type: {0}")]
    InvalidMessageType(String),

    #[error("failed to add member: {0}")]
    AddMember(String),

    #[error("failed to merge commit: {0}")]
    MergeCommit(String),

    #[error("failed to process welcome: {0}")]
    ProcessWelcome(String),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("failed to process commit: {0}")]
    ProcessCommit(String),

    #[error("tag derivation failed: {0}")]
    TagDerivation(String),

    #[error("stealth encryption failed: {0}")]
    StealthEncryption(String),
}
