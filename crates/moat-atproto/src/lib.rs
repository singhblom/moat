//! moat-atproto: ATProto PDS interaction for Moat encrypted messenger
//!
//! This crate handles all interaction with the ATProto Personal Data Server (PDS),
//! including authentication, publishing records, and fetching data.

mod client;
mod error;
mod records;

pub use client::MoatAtprotoClient;
pub use error::{Error, Result};
pub use records::{EventRecord, KeyPackageRecord, StealthAddressRecord};
