//! Host-side adapter between the `moat_core::sync` state machine and
//! `crate::keystore::StoredMessage`.
//!
//! The state machine itself lives in `moat_core::sync`. This module re-exports
//! its public API for `crate::sync::*` paths in `app.rs`, and provides the
//! `StoredMessage <-> SyncMessage` conversions which depend on
//! `crate::keystore` and therefore can't live in moat-core.

pub use moat_core::sync::{
    decode_sync_msg, encode_sync_msg, ConvState, SyncMessage, SyncMsg, SyncOutput, SyncReaction,
    SyncSession,
};

use crate::keystore::{StoredMessage, StoredReaction};

/// How a transfer's frames are sealed and opened on the pair WS.
pub enum SyncChannel {
    /// Ring MLS, between established devices.
    Ring { ring_id: Vec<u8>, key_bundle: Vec<u8> },
    /// The pairing AEAD the pairing exchange ran on, so the new device
    /// needs no ring-MLS history for its first transfer.
    Pairing(moat_core::PairingFrameChannel),
}

/// The history transfer running on the pair WS.
pub struct SyncTransfer {
    pub session: SyncSession,
    pub channel: SyncChannel,
    /// The peer, as MLS named it on the frames it sent — from the leaf
    /// credential, not the payload. Ring channel only.
    pub peer_name: Option<String>,
}

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
        blob_thumbhash: m.blob_thumbhash.clone(),
        reactions: m
            .reactions
            .iter()
            .map(|r| SyncReaction {
                emoji: r.emoji.clone(),
                sender_did: r.sender_did.clone(),
            })
            .collect(),
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
        blob_thumbhash: s.blob_thumbhash.clone(),
        reactions: s
            .reactions
            .iter()
            .map(|r| StoredReaction {
                emoji: r.emoji.clone(),
                sender_did: r.sender_did.clone(),
            })
            .collect(),
        // Unsent rows are never synced.
        send_failed: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field a `StoredMessage` holds, each with a distinct
    /// non-default value.
    fn fully_populated() -> StoredMessage {
        StoredMessage {
            rkey: "rkey001".to_string(),
            content: "test message".to_string(),
            timestamp: chrono::DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
            is_own: false,
            message_id: Some(vec![1u8; 16]),
            sender_did: Some("did:plc:bob".to_string()),
            sender_device: Some("phone".to_string()),
            blob_uri: Some("at://did:plc:bob/bafyimage".to_string()),
            blob_key: Some(vec![2u8; 32]),
            blob_ciphertext_hash: Some(vec![3u8; 32]),
            blob_ciphertext_size: Some(4_096),
            blob_content_hash: Some(vec![4u8; 32]),
            blob_mime: Some("image/webp".to_string()),
            blob_width: Some(1024),
            blob_height: Some(768),
            blob_thumbhash: Some(vec![5u8; 24]),
            reactions: vec![
                StoredReaction { emoji: "👍".into(), sender_did: "did:plc:bob".into() },
                StoredReaction { emoji: "🎉".into(), sender_did: "did:plc:carol".into() },
            ],
            // Local to unsent rows, which are never synced.
            send_failed: None,
        }
    }

    /// A sync that drops a field loses it for good on the receiving side:
    /// history predating that device's membership cannot be re-read from
    /// the PDS, because those events are not decryptable to it. So the
    /// contract is total — *everything* a host persists has to survive the
    /// round trip, and this asserts field by field rather than spot-
    /// checking, which is how `thumbhash` and `reactions` were lost.
    #[test]
    fn every_stored_field_survives_the_round_trip() {
        let stored = fully_populated();
        let back = stored_from_sync_message(&sync_message_from_stored(&stored));

        assert_eq!(back.rkey, stored.rkey);
        assert_eq!(back.content, stored.content);
        assert_eq!(back.timestamp, stored.timestamp);
        assert_eq!(back.is_own, stored.is_own);
        assert_eq!(back.message_id, stored.message_id);
        assert_eq!(back.sender_did, stored.sender_did);
        assert_eq!(back.sender_device, stored.sender_device);
        assert_eq!(back.blob_uri, stored.blob_uri);
        assert_eq!(back.blob_key, stored.blob_key);
        assert_eq!(back.blob_ciphertext_hash, stored.blob_ciphertext_hash);
        assert_eq!(back.blob_ciphertext_size, stored.blob_ciphertext_size);
        assert_eq!(back.blob_content_hash, stored.blob_content_hash);
        assert_eq!(back.blob_mime, stored.blob_mime);
        assert_eq!(back.blob_width, stored.blob_width);
        assert_eq!(back.blob_height, stored.blob_height);
        assert_eq!(
            back.blob_thumbhash, stored.blob_thumbhash,
            "the blurry placeholder is stored here and nowhere else the \
             receiver can reach"
        );
        assert_eq!(
            back.reactions, stored.reactions,
            "reactions arrive as separate PDS events the receiver cannot \
             decrypt, so sync is their only route"
        );
    }

    /// The same contract stated structurally: the JSON a `SyncMessage`
    /// encodes to must mention every field, so adding one to
    /// `StoredMessage` without carrying it here fails loudly.
    #[test]
    fn the_wire_form_mentions_every_stored_field() {
        let wire = serde_json::to_value(sync_message_from_stored(&fully_populated()))
            .expect("SyncMessage serializes");
        let obj = wire.as_object().expect("an object");
        for field in [
            "rkey",
            "message_id",
            "sender_did",
            "sender_device_name",
            "timestamp_ms",
            "content",
            "is_own",
            "blob_uri",
            "blob_key",
            "blob_ciphertext_hash",
            "blob_ciphertext_size",
            "blob_content_hash",
            "blob_mime",
            "blob_width",
            "blob_height",
            "blob_thumbhash",
            "reactions",
        ] {
            assert!(
                obj.get(field).is_some_and(|v| !v.is_null()),
                "the wire form must carry {field}; a field held on one \
                 side and not sent is silently lost on the other"
            );
        }
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
            blob_thumbhash: None,
            reactions: Vec::new(),
        };
        let stored = stored_from_sync_message(&sync);
        assert_eq!(stored.sender_did, None);
        assert_eq!(stored.sender_device, None);
    }
}
