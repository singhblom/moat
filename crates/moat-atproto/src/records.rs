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

/// Stealth address record stored on PDS
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StealthAddressRecord {
    /// Schema version
    pub v: u32,

    /// X25519 public key for stealth address derivation (32 bytes)
    #[serde(with = "base64_pubkey")]
    pub scan_pubkey: [u8; 32],

    /// Creation time
    pub created_at: DateTime<Utc>,
}

/// Record data for creating a new stealth address
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StealthAddressData {
    pub v: u32,
    #[serde(with = "base64_pubkey")]
    pub scan_pubkey: [u8; 32],
    pub created_at: DateTime<Utc>,
}

/// Helper module for base64 encoding/decoding of byte vectors
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Helper module for base64 encoding/decoding of 16-byte tags
mod base64_tag {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom("tag must be exactly 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Helper module for base64 encoding/decoding of 32-byte public keys
mod base64_pubkey {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
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
    }

    #[test]
    fn test_stealth_address_data_serialization() {
        let data = StealthAddressData {
            v: 1,
            scan_pubkey: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let parsed: StealthAddressData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.v, data.v);
        assert_eq!(parsed.scan_pubkey, data.scan_pubkey);
    }
}
