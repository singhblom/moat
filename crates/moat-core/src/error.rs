//! Error types for moat-core

use thiserror::Error;

/// Result type for moat-core operations
pub type Result<T> = std::result::Result<T, Error>;

/// Numeric error codes for FFI consumers.
///
/// Each variant maps to a specific failure category. FFI bindings (e.g. UniFFI)
/// can expose these as integers for pattern matching in Swift/Kotlin/Dart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    KeyGeneration = 1,
    KeyPackageGeneration = 2,
    KeyPackageValidation = 3,
    GroupCreation = 4,
    GroupLoad = 5,
    Storage = 6,
    Serialization = 7,
    Deserialization = 8,
    InvalidMessageType = 9,
    AddMember = 10,
    MergeCommit = 11,
    ProcessWelcome = 12,
    Encryption = 13,
    Decryption = 14,
    ProcessCommit = 15,
    TagDerivation = 16,
    StealthEncryption = 17,
}

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

impl Error {
    /// Return the numeric error code for this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::KeyGeneration(_) => ErrorCode::KeyGeneration,
            Error::KeyPackageGeneration(_) => ErrorCode::KeyPackageGeneration,
            Error::KeyPackageValidation(_) => ErrorCode::KeyPackageValidation,
            Error::GroupCreation(_) => ErrorCode::GroupCreation,
            Error::GroupLoad(_) => ErrorCode::GroupLoad,
            Error::Storage(_) => ErrorCode::Storage,
            Error::Serialization(_) => ErrorCode::Serialization,
            Error::Deserialization(_) => ErrorCode::Deserialization,
            Error::InvalidMessageType(_) => ErrorCode::InvalidMessageType,
            Error::AddMember(_) => ErrorCode::AddMember,
            Error::MergeCommit(_) => ErrorCode::MergeCommit,
            Error::ProcessWelcome(_) => ErrorCode::ProcessWelcome,
            Error::Encryption(_) => ErrorCode::Encryption,
            Error::Decryption(_) => ErrorCode::Decryption,
            Error::ProcessCommit(_) => ErrorCode::ProcessCommit,
            Error::TagDerivation(_) => ErrorCode::TagDerivation,
            Error::StealthEncryption(_) => ErrorCode::StealthEncryption,
        }
    }

    /// Return the human-readable error message.
    pub fn message(&self) -> &str {
        match self {
            Error::KeyGeneration(msg)
            | Error::KeyPackageGeneration(msg)
            | Error::KeyPackageValidation(msg)
            | Error::GroupCreation(msg)
            | Error::GroupLoad(msg)
            | Error::Storage(msg)
            | Error::Serialization(msg)
            | Error::Deserialization(msg)
            | Error::InvalidMessageType(msg)
            | Error::AddMember(msg)
            | Error::MergeCommit(msg)
            | Error::ProcessWelcome(msg)
            | Error::Encryption(msg)
            | Error::Decryption(msg)
            | Error::ProcessCommit(msg)
            | Error::TagDerivation(msg)
            | Error::StealthEncryption(msg) => msg,
        }
    }
}
