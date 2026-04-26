//! Host-side adapter between the `moat_core::sync` state machine and
//! `crate::keystore::StoredMessage`.
//!
//! The state machine itself lives in `moat_core::sync`. This module re-exports
//! its public API for `crate::sync::*` paths in `app.rs`, and provides the
//! `StoredMessage <-> SyncMessage` conversions which depend on
//! `crate::keystore` and therefore can't live in moat-core.

pub use moat_core::sync::{
    decode_sync_msg, encode_sync_msg, AnchorDto, ConvState, SyncMessage, SyncOutput, SyncSession,
};

use crate::keystore::StoredMessage;

/// Convert a moat-cli `StoredMessage` into a wire-form `SyncMessage`.
pub fn sync_message_from_stored(m: &StoredMessage) -> SyncMessage {
    SyncMessage {
        rkey: m.rkey.clone(),
        message_id: m.message_id.clone(),
        sender_did: m.sender_did.clone().unwrap_or_default(),
        sender_device_name: m.sender_device.clone().unwrap_or_default(),
        timestamp_ms: m.timestamp.timestamp_millis(),
        content: m.content.clone(),
        is_own: m.is_own,
        blob_uri: m.blob_uri.clone(),
        blob_key: m.blob_key.clone(),
        blob_ciphertext_hash: m.blob_ciphertext_hash.clone(),
        blob_ciphertext_size: m.blob_ciphertext_size,
        blob_content_hash: m.blob_content_hash.clone(),
        blob_mime: m.blob_mime.clone(),
        blob_width: m.blob_width,
        blob_height: m.blob_height,
    }
}

/// Convert a wire-form `SyncMessage` into a moat-cli `StoredMessage`.
pub fn stored_from_sync_message(s: &SyncMessage) -> StoredMessage {
    StoredMessage {
        rkey: s.rkey.clone(),
        content: s.content.clone(),
        timestamp: chrono::DateTime::from_timestamp_millis(s.timestamp_ms)
            .unwrap_or_else(chrono::Utc::now),
        is_own: s.is_own,
        message_id: s.message_id.clone(),
        sender_did: if s.sender_did.is_empty() { None } else { Some(s.sender_did.clone()) },
        sender_device: if s.sender_device_name.is_empty() {
            None
        } else {
            Some(s.sender_device_name.clone())
        },
        blob_uri: s.blob_uri.clone(),
        blob_key: s.blob_key.clone(),
        blob_ciphertext_hash: s.blob_ciphertext_hash.clone(),
        blob_ciphertext_size: s.blob_ciphertext_size,
        blob_content_hash: s.blob_content_hash.clone(),
        blob_mime: s.blob_mime.clone(),
        blob_width: s.blob_width,
        blob_height: s.blob_height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_sync_message_roundtrip() {
        let stored = StoredMessage {
            rkey: "rkey001".to_string(),
            content: "test message".to_string(),
            timestamp: chrono::Utc::now(),
            is_own: false,
            message_id: Some(vec![1u8; 16]),
            sender_did: Some("did:plc:bob".to_string()),
            sender_device: Some("phone".to_string()),
            blob_uri: None,
            blob_key: None,
            blob_ciphertext_hash: None,
            blob_ciphertext_size: None,
            blob_content_hash: None,
            blob_mime: None,
            blob_width: None,
            blob_height: None,
        };
        let sync = sync_message_from_stored(&stored);
        let back = stored_from_sync_message(&sync);
        assert_eq!(back.rkey, stored.rkey);
        assert_eq!(back.content, stored.content);
        assert_eq!(back.sender_did, stored.sender_did);
        assert_eq!(back.message_id, stored.message_id);
    }

    #[test]
    fn empty_sender_round_trips_to_none() {
        let sync = SyncMessage {
            rkey: "r".into(),
            message_id: None,
            sender_did: String::new(),
            sender_device_name: String::new(),
            timestamp_ms: 0,
            content: "x".into(),
            is_own: false,
            blob_uri: None,
            blob_key: None,
            blob_ciphertext_hash: None,
            blob_ciphertext_size: None,
            blob_content_hash: None,
            blob_mime: None,
            blob_width: None,
            blob_height: None,
        };
        let stored = stored_from_sync_message(&sync);
        assert_eq!(stored.sender_did, None);
        assert_eq!(stored.sender_device, None);
    }
}
