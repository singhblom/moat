//! Error types for moat-core

use thiserror::Error;

/// Result type for moat-core operations
pub type Result<T> = std::result::Result<T, Error>;

/// Numeric error codes for FFI consumers.
///
/// Each variant maps to a specific failure category. FFI bindings (e.g. UniFFI)
/// can expose these as integers for pattern matching in Swift/Kotlin/Dart.
///
/// Note: These codes were renumbered in the transcript integrity update.
/// FFI consumers must be updated to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    KeyGeneration = 100,
    KeyPackageGeneration = 101,
    KeyPackageValidation = 102,
    GroupCreation = 103,
    GroupLoad = 104,
    Storage = 105,
    Serialization = 106,
    Deserialization = 107,
    InvalidMessageType = 108,
    AddMember = 109,
    MergeCommit = 110,
    ProcessWelcome = 111,
    Encryption = 112,
    Decryption = 113,
    ProcessCommit = 114,
    TagDerivation = 115,
    StealthEncryption = 116,
    RemoveMember = 117,
    InvalidBlobUri = 118,
    CiphertextHashMismatch = 119,
    BlobDecryptionFailed = 120,
    ContentHashMismatch = 121,
    // Transcript integrity error codes
    StateVersionMismatch = 200,
    StaleCommit = 201,
    StateDiverged = 202,
    UnknownSender = 203,
    ConflictUnresolved = 204,
    // Pairing error codes
    PairingCodec = 300,
    PairingCrypto = 301,
    PairingProtocol = 302,
    // Sync-request error codes
    SyncRequestProtocol = 400,
    SyncProtocol = 401,
    PayloadTooLarge = 402,
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

    #[error("failed to remove member: {0}")]
    RemoveMember(String),

    #[error("state version mismatch: {0}")]
    StateVersionMismatch(String),

    #[error("stale commit: {0}")]
    StaleCommit(String),

    #[error("MLS state diverged: {0}")]
    StateDiverged(String),

    #[error("unknown sender: {0}")]
    UnknownSender(String),

    #[error("commit conflict unresolved after retries: {0}")]
    ConflictUnresolved(String),

    #[error("invalid blob URI (must start with at://): {0}")]
    InvalidBlobUri(String),

    #[error("blob ciphertext hash mismatch: {0}")]
    CiphertextHashMismatch(String),

    #[error("blob decryption failed: {0}")]
    BlobDecryptionFailed(String),

    #[error("blob content hash mismatch: {0}")]
    ContentHashMismatch(String),

    #[error("pairing code invalid: {0}")]
    PairingCodec(String),

    #[error("pairing channel error: {0}")]
    PairingCrypto(String),

    #[error("pairing protocol error: {0}")]
    PairingProtocol(String),

    #[error("sync request protocol error: {0}")]
    SyncRequestProtocol(String),

    #[error("sync protocol error: {0}")]
    SyncProtocol(String),

    /// An event's serialized form exceeds the largest padding bucket.
    ///
    /// Bucket padding rounds *up* to a fixed size, so there is no bucket
    /// for a payload larger than the biggest one. Oversized content
    /// belongs in an external blob with only the reference in the event
    /// (as `message.long_text` and `message.image` already do).
    #[error("{0}")]
    PayloadTooLarge(String),
}

impl Error {
    /// An event whose serialized form has outgrown the largest bucket.
    pub fn payload_too_large(len: usize, max: usize) -> Self {
        Error::PayloadTooLarge(format!(
            "payload of {len} bytes exceeds the largest padding bucket ({max} bytes); \
             oversized content belongs in an external blob"
        ))
    }

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
            Error::RemoveMember(_) => ErrorCode::RemoveMember,
            Error::StateVersionMismatch(_) => ErrorCode::StateVersionMismatch,
            Error::StaleCommit(_) => ErrorCode::StaleCommit,
            Error::StateDiverged(_) => ErrorCode::StateDiverged,
            Error::UnknownSender(_) => ErrorCode::UnknownSender,
            Error::ConflictUnresolved(_) => ErrorCode::ConflictUnresolved,
            Error::InvalidBlobUri(_) => ErrorCode::InvalidBlobUri,
            Error::CiphertextHashMismatch(_) => ErrorCode::CiphertextHashMismatch,
            Error::BlobDecryptionFailed(_) => ErrorCode::BlobDecryptionFailed,
            Error::ContentHashMismatch(_) => ErrorCode::ContentHashMismatch,
            Error::PairingCodec(_) => ErrorCode::PairingCodec,
            Error::PairingCrypto(_) => ErrorCode::PairingCrypto,
            Error::PairingProtocol(_) => ErrorCode::PairingProtocol,
            Error::SyncRequestProtocol(_) => ErrorCode::SyncRequestProtocol,
            Error::SyncProtocol(_) => ErrorCode::SyncProtocol,
            Error::PayloadTooLarge(_) => ErrorCode::PayloadTooLarge,
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
            | Error::StealthEncryption(msg)
            | Error::RemoveMember(msg)
            | Error::StateVersionMismatch(msg)
            | Error::StaleCommit(msg)
            | Error::StateDiverged(msg)
            | Error::UnknownSender(msg)
            | Error::ConflictUnresolved(msg)
            | Error::InvalidBlobUri(msg)
            | Error::CiphertextHashMismatch(msg)
            | Error::BlobDecryptionFailed(msg)
            | Error::ContentHashMismatch(msg)
            | Error::PairingCodec(msg)
            | Error::PairingCrypto(msg)
            | Error::PairingProtocol(msg)
            | Error::SyncRequestProtocol(msg)
            | Error::SyncProtocol(msg)
            | Error::PayloadTooLarge(msg) => msg,
        }
    }
}
