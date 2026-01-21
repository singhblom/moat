//! Error types for moat-atproto

use thiserror::Error;

/// Result type for moat-atproto operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during ATProto operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("authentication failed: {0}")]
    Authentication(String),

    #[error("session expired")]
    SessionExpired,

    #[error("network error: {0}")]
    Network(String),

    #[error("PDS error: {0}")]
    Pds(String),

    #[error("record not found: {0}")]
    NotFound(String),

    #[error("invalid record: {0}")]
    InvalidRecord(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("invalid handle: {0}")]
    InvalidHandle(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}
