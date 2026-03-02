//! ATProto record types for Moat

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// MLS key package record stored on PDS
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageRecord {
    /// Schema version
    pub v: u32,

    /// MLS ciphersuite identifier
    pub ciphersuite: String,

    /// TLS-serialized MLS KeyPackage (base64 encoded in JSON)
    #[serde(with = "base64_bytes")]
    pub key_package: Vec<u8>,

    /// Expiration time
    pub expires_at: DateTime<Utc>,

    /// Creation time
    pub created_at: DateTime<Utc>,
}

/// Unified encrypted event record stored on PDS
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRecord {
    /// Record AT-URI (populated after fetch, not in record itself)
    #[serde(skip)]
    pub uri: String,

    /// Record rkey (populated after fetch, not in record itself)
    /// Used for cursor-based pagination
    #[serde(skip)]
    pub rkey: String,

    /// Author DID (populated after fetch, not in record itself)
    #[serde(skip)]
    pub author_did: String,

    /// Schema version
    pub v: u32,

    /// Rotating 16-byte conversation tag
    #[serde(with = "base64_tag")]
    pub tag: [u8; 16],

    /// Padded encrypted payload
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,

    /// Creation time
    pub created_at: DateTime<Utc>,
}

/// Record data for creating a new key package
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageData {
    pub v: u32,
    pub ciphersuite: String,
    #[serde(with = "base64_bytes")]
    pub key_package: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Record data for creating a new event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventData {
    pub v: u32,
    #[serde(with = "base64_tag")]
    pub tag: [u8; 16],
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// Stealth address record stored on PDS (v2: multi-device)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StealthAddressRecord {
    /// Record rkey (TID, populated after fetch)
    #[serde(skip)]
    pub rkey: String,

    /// Schema version (must be 2)
    pub v: u32,

    /// X25519 public key for stealth address derivation (32 bytes)
    #[serde(with = "base64_pubkey")]
    pub scan_pubkey: [u8; 32],

    /// Human-readable device name
    pub device_name: String,

    /// Creation time
    pub created_at: DateTime<Utc>,
}

/// Record data for creating a new stealth address (v2: multi-device)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StealthAddressData {
    pub v: u32,
    #[serde(with = "base64_pubkey")]
    pub scan_pubkey: [u8; 32],
    pub device_name: String,
    pub created_at: DateTime<Utc>,
}

/// Helper module for ATProto IPLD bytes encoding of byte vectors.
/// Serializes as `{"$bytes": "<base64>"}` per the ATProto data model spec.
mod base64_bytes {
    use base64::{engine::general_purpose::{STANDARD, STANDARD_NO_PAD}, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$bytes", &STANDARD.encode(bytes))?;
        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BytesWrapper {
            #[serde(rename = "$bytes")]
            bytes: String,
        }
        let wrapper = BytesWrapper::deserialize(deserializer)?;
        // Use STANDARD_NO_PAD to handle both padded and unpadded base64.
        // ATProto PDSes (e.g. bsky.social) strip padding when re-encoding
        // bytes through their IPLD/CBOR layer.
        STANDARD_NO_PAD.decode(wrapper.bytes.trim_end_matches('=')).map_err(serde::de::Error::custom)
    }
}

/// Helper module for ATProto IPLD bytes encoding of 16-byte tags.
/// Serializes as `{"$bytes": "<base64>"}` per the ATProto data model spec.
mod base64_tag {
    use base64::{engine::general_purpose::{STANDARD, STANDARD_NO_PAD}, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$bytes", &STANDARD.encode(bytes))?;
        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BytesWrapper {
            #[serde(rename = "$bytes")]
            bytes: String,
        }
        let wrapper = BytesWrapper::deserialize(deserializer)?;
        let bytes = STANDARD_NO_PAD.decode(wrapper.bytes.trim_end_matches('=')).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom("tag must be exactly 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Helper module for ATProto IPLD bytes encoding of 32-byte public keys.
/// Serializes as `{"$bytes": "<base64>"}` per the ATProto data model spec.
mod base64_pubkey {
    use base64::{engine::general_purpose::{STANDARD, STANDARD_NO_PAD}, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$bytes", &STANDARD.encode(bytes))?;
        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BytesWrapper {
            #[serde(rename = "$bytes")]
            bytes: String,
        }
        let wrapper = BytesWrapper::deserialize(deserializer)?;
        let bytes = STANDARD_NO_PAD.decode(wrapper.bytes.trim_end_matches('=')).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("pubkey must be exactly 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_data_serialization() {
        let data = EventData {
            v: 1,
            tag: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: EventData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.v, data.v);
        assert_eq!(parsed.tag, data.tag);
        assert_eq!(parsed.ciphertext, data.ciphertext);

        // Verify ATProto IPLD bytes format: {"$bytes": "<base64>"}
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value["tag"]["$bytes"].is_string(),
            "tag must serialize as {{\"$bytes\": \"...\"}} per ATProto spec"
        );
        assert!(
            value["ciphertext"]["$bytes"].is_string(),
            "ciphertext must serialize as {{\"$bytes\": \"...\"}} per ATProto spec"
        );
    }

    #[test]
    fn test_key_package_data_serialization() {
        let data = KeyPackageData {
            v: 1,
            ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            key_package: vec![1, 2, 3, 4, 5],
            expires_at: Utc::now(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: KeyPackageData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.v, data.v);
        assert_eq!(parsed.ciphersuite, data.ciphersuite);
        assert_eq!(parsed.key_package, data.key_package);

        // Verify ATProto IPLD bytes format: {"$bytes": "<base64>"}
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value["keyPackage"]["$bytes"].is_string(),
            "keyPackage must serialize as {{\"$bytes\": \"...\"}} per ATProto spec"
        );
    }

    /// Ensure that base64 fields without padding (as returned by bsky.social after
    /// IPLD/CBOR round-trip) are accepted by the deserializers.
    #[test]
    fn test_stealth_address_unpadded_base64() {
        // 32 bytes encodes to 43 base64 chars without padding (bsky.social strips the '=')
        let json = r#"{"v":2,"scanPubkey":{"$bytes":"FtKnvfUoIJCdfrcKbtFL9JHrUdQbnt0X7euvw0fZUTs"},"deviceName":"CLI (Mac)","createdAt":"2026-03-01T21:31:58Z"}"#;
        let record: StealthAddressData = serde_json::from_str(json)
            .expect("should deserialize unpadded base64 from bsky.social");
        assert_eq!(record.device_name, "CLI (Mac)");
        assert_eq!(record.scan_pubkey.len(), 32);
    }

    #[test]
    fn test_stealth_address_data_serialization() {
        let data = StealthAddressData {
            v: 2,
            scan_pubkey: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            device_name: "Test Device".to_string(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: StealthAddressData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.v, data.v);
        assert_eq!(parsed.scan_pubkey, data.scan_pubkey);
        assert_eq!(parsed.device_name, data.device_name);

        // Verify ATProto IPLD bytes format: {"$bytes": "<base64>"}
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value["scanPubkey"]["$bytes"].is_string(),
            "scanPubkey must serialize as {{\"$bytes\": \"...\"}} per ATProto spec"
        );
    }
}
