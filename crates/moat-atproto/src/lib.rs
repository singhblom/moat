//! moat-atproto: ATProto PDS interaction for Moat encrypted messenger
//!
//! This crate handles all interaction with the ATProto Personal Data Server (PDS),
//! including authentication, publishing records, and fetching data.

mod client;
mod error;
mod records;

pub use client::MoatAtprotoClient;
pub use error::{Error, Result};
pub use records::{BlobRef, DrawbridgeConfigRecord, EventRecord, KeyPackageRecord, StealthAddressRecord};

pub const DEFAULT_PDS_URL: &str = "https://bsky.social";

/// Drawbridge relay this binary was built for, from `MOAT_DRAWBRIDGE_URL`.
/// `None` means no relay: the host polls only.
pub const BUILD_DRAWBRIDGE_URL: Option<&str> = option_env!("MOAT_DRAWBRIDGE_URL");

#[cfg(not(debug_assertions))]
const _: () = assert!(
    BUILD_DRAWBRIDGE_URL.is_some(),
    "release builds need MOAT_DRAWBRIDGE_URL (see config/release.env)"
);
