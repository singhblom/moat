//! Public API surface for FFI
//!
//! This module defines what gets exposed via FFI.
//! All types here must be FFI-friendly.
//! UniFFI proc macro annotations will be added here when we start mobile.

// Core session and error types
pub use crate::error::{Error, ErrorCode, Result};
pub use crate::event::{Event, EventKind};
pub use crate::{DecryptResult, EncryptResult, KeyBundle, MoatSession, WelcomeResult, CIPHERSUITE};

// Stealth address functions
pub use crate::stealth::{encrypt_for_stealth, generate_stealth_keypair, try_decrypt_stealth};

// Tag derivation
pub use crate::tag::{derive_event_tag, generate_candidate_tags, TAG_EXPORT_SECRET_LABEL, TAG_EXPORT_SECRET_LEN, TAG_GAP_LIMIT};

// Padding utilities
pub use crate::padding::{pad_to_bucket, unpad, Bucket};
