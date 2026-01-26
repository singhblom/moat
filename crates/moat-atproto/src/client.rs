//! ATProto client for Moat

use crate::error::{Error, Result};
use crate::records::{
    EventData, EventRecord, KeyPackageData, KeyPackageRecord, StealthAddressData,
    StealthAddressRecord,
};
use atrium_api::agent::{store::MemorySessionStore, AtpAgent};
use atrium_api::com::atproto::repo::{create_record, list_records};
use atrium_api::types::string::{AtIdentifier, Nsid};
use atrium_xrpc_client::reqwest::{ReqwestClient, ReqwestClientBuilder};
use chrono::{Duration, Utc};

/// Default timeout for HTTP requests (30 seconds)
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
use ipld_core::ipld::Ipld;
use std::collections::BTreeMap;

/// Lexicon NSID for key packages
const KEY_PACKAGE_NSID: &str = "social.moat.keyPackage";

/// Lexicon NSID for events
const EVENT_NSID: &str = "social.moat.event";

/// Lexicon NSID for stealth addresses
const STEALTH_ADDRESS_NSID: &str = "social.moat.stealthAddress";

/// Default PDS URL (Bluesky)
const DEFAULT_PDS_URL: &str = "https://bsky.social";

/// PLC Directory URL for DID resolution
const PLC_DIRECTORY_URL: &str = "https://plc.directory";

/// ATProto client for Moat operations
pub struct MoatAtprotoClient {
    /// Authenticated agent for the user's PDS (used for writes)
    agent: AtpAgent<MemorySessionStore, ReqwestClient>,
    /// HTTP client for PLC directory lookups
    http_client: reqwest::Client,
    did: String,
}

impl MoatAtprotoClient {
    /// Create a new client and authenticate with the PDS.
    pub async fn login(handle: &str, password: &str) -> Result<Self> {
        Self::login_with_pds(handle, password, DEFAULT_PDS_URL).await
    }

    /// Create a new client with a custom PDS URL.
    pub async fn login_with_pds(handle: &str, password: &str, pds_url: &str) -> Result<Self> {
        // Create HTTP client with timeout
        let http_client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| Error::Pds(format!("Failed to create HTTP client: {}", e)))?;

        // Use the same client for the ATProto agent
        let xrpc_client = ReqwestClientBuilder::new(pds_url).client(http_client.clone()).build();
        let agent = AtpAgent::new(xrpc_client, MemorySessionStore::default());

        agent
            .login(handle, password)
            .await
            .map_err(|e| Error::Authentication(e.to_string()))?;

        let session = agent
            .get_session()
            .await
            .ok_or(Error::Authentication("no session after login".to_string()))?;

        Ok(Self {
            agent,
            http_client,
            did: session.did.to_string(),
        })
    }

    /// Resolve a DID's PDS endpoint from the PLC directory.
    async fn resolve_pds_endpoint(&self, did: &str) -> Result<String> {
        let url = format!("{}/{}", PLC_DIRECTORY_URL, did);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Pds(format!("Failed to fetch DID document: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Pds(format!(
                "PLC directory returned {}: {}",
                response.status(),
                did
            )));
        }

        let doc: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Pds(format!("Failed to parse DID document: {}", e)))?;

        // Extract the PDS endpoint from the service array
        let services = doc["service"]
            .as_array()
            .ok_or_else(|| Error::Pds("DID document has no services".to_string()))?;

        for service in services {
            if service["type"].as_str() == Some("AtprotoPersonalDataServer") {
                if let Some(endpoint) = service["serviceEndpoint"].as_str() {
                    return Ok(endpoint.to_string());
                }
            }
        }

        Err(Error::Pds(format!("No PDS endpoint found for {}", did)))
    }

    /// Create an unauthenticated agent for a specific PDS (reuses the timeout client).
    fn agent_for_pds(&self, pds_url: &str) -> AtpAgent<MemorySessionStore, ReqwestClient> {
        let xrpc_client =
            ReqwestClientBuilder::new(pds_url).client(self.http_client.clone()).build();
        AtpAgent::new(xrpc_client, MemorySessionStore::default())
    }

    /// Get the authenticated user's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Publish a key package to the PDS.
    ///
    /// Returns the AT-URI of the created record.
    pub async fn publish_key_package(
        &self,
        key_package: &[u8],
        ciphersuite: &str,
    ) -> Result<String> {
        let now = Utc::now();
        let expires_at = now + Duration::days(30);

        let data = KeyPackageData {
            v: 1,
            ciphersuite: ciphersuite.to_string(),
            key_package: key_package.to_vec(),
            expires_at,
            created_at: now,
        };

        let record_value = serde_json::to_value(&data)?;
        let ipld_record = json_to_ipld(record_value)?;

        let record = match ipld_record {
            Ipld::Map(map) => atrium_api::types::Unknown::Object(
                map.into_iter()
                    .map(|(k, v)| (k, v.try_into().expect("valid ipld")))
                    .collect(),
            ),
            _ => return Err(Error::Serialization("expected object".to_string())),
        };

        let input = create_record::InputData {
            collection: Nsid::new(KEY_PACKAGE_NSID.to_string())
                .map_err(|e| Error::InvalidRecord(e.to_string()))?,
            record,
            repo: AtIdentifier::Did(
                self.did.parse().map_err(|_| Error::InvalidDid(self.did.clone()))?,
            ),
            rkey: None,
            swap_commit: None,
            validate: None,
        };

        let output = self
            .agent
            .api
            .com
            .atproto
            .repo
            .create_record(input.into())
            .await
            .map_err(|e| Error::Pds(e.to_string()))?;

        Ok(output.uri.to_string())
    }

    /// Fetch key packages for a given DID.
    ///
    /// Resolves the DID's PDS and queries it directly.
    pub async fn fetch_key_packages(&self, did: &str) -> Result<Vec<KeyPackageRecord>> {
        // Resolve the target user's PDS
        let pds_url = self.resolve_pds_endpoint(did).await?;
        let pds_agent = self.agent_for_pds(&pds_url);

        let input = list_records::ParametersData {
            collection: Nsid::new(KEY_PACKAGE_NSID.to_string())
                .map_err(|e| Error::InvalidRecord(e.to_string()))?,
            cursor: None,
            limit: Some(100.try_into().unwrap()),
            repo: AtIdentifier::Did(
                did.parse().map_err(|_| Error::InvalidDid(did.to_string()))?,
            ),
            reverse: None,
            rkey_start: None,
            rkey_end: None,
        };

        let output = pds_agent
            .api
            .com
            .atproto
            .repo
            .list_records(input.into())
            .await
            .map_err(|e| Error::Pds(e.to_string()))?;

        let mut records = Vec::new();
        for item in &output.records {
            let value = serde_json::to_value(&item.value)
                .map_err(|e| Error::Serialization(e.to_string()))?;

            if let Ok(record) = serde_json::from_value::<KeyPackageRecord>(value) {
                // Skip expired key packages
                if record.expires_at > Utc::now() {
                    records.push(record);
                }
            }
        }

        Ok(records)
    }

    /// Publish an encrypted event to the PDS.
    ///
    /// Returns the AT-URI of the created record.
    pub async fn publish_event(&self, tag: &[u8; 16], ciphertext: &[u8]) -> Result<String> {
        let data = EventData {
            v: 1,
            tag: *tag,
            ciphertext: ciphertext.to_vec(),
            created_at: Utc::now(),
        };

        let record_value = serde_json::to_value(&data)?;
        let ipld_record = json_to_ipld(record_value)?;

        let record = match ipld_record {
            Ipld::Map(map) => atrium_api::types::Unknown::Object(
                map.into_iter()
                    .map(|(k, v)| (k, v.try_into().expect("valid ipld")))
                    .collect(),
            ),
            _ => return Err(Error::Serialization("expected object".to_string())),
        };

        let input = create_record::InputData {
            collection: Nsid::new(EVENT_NSID.to_string())
                .map_err(|e| Error::InvalidRecord(e.to_string()))?,
            record,
            repo: AtIdentifier::Did(
                self.did.parse().map_err(|_| Error::InvalidDid(self.did.clone()))?,
            ),
            rkey: None,
            swap_commit: None,
            validate: None,
        };

        let output = self
            .agent
            .api
            .com
            .atproto
            .repo
            .create_record(input.into())
            .await
            .map_err(|e| Error::Pds(e.to_string()))?;

        Ok(output.uri.to_string())
    }

    /// Fetch events from a specific DID.
    ///
    /// Resolves the DID's PDS and queries it directly.
    ///
    /// If `rkey_start` is provided, only fetches records with rkey > rkey_start.
    /// This enables efficient incremental polling without needing to track all seen URIs.
    ///
    /// Automatically paginates through all results using the cursor.
    pub async fn fetch_events_from_did(
        &self,
        did: &str,
        rkey_start: Option<&str>,
    ) -> Result<Vec<EventRecord>> {
        // Resolve the target user's PDS
        let pds_url = self.resolve_pds_endpoint(did).await?;
        let pds_agent = self.agent_for_pds(&pds_url);

        let mut all_records = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let input = list_records::ParametersData {
                collection: Nsid::new(EVENT_NSID.to_string())
                    .map_err(|e| Error::InvalidRecord(e.to_string()))?,
                cursor: cursor.clone(),
                limit: Some(100.try_into().unwrap()),
                repo: AtIdentifier::Did(
                    did.parse().map_err(|_| Error::InvalidDid(did.to_string()))?,
                ),
                reverse: None,
                rkey_start: rkey_start.map(|s| s.to_string()),
                rkey_end: None,
            };

            let output = pds_agent
                .api
                .com
                .atproto
                .repo
                .list_records(input.into())
                .await
                .map_err(|e| Error::Pds(e.to_string()))?;

            for item in &output.records {
                let value = serde_json::to_value(&item.value)
                    .map_err(|e| Error::Serialization(e.to_string()))?;

                if let Ok(mut record) = serde_json::from_value::<EventRecord>(value) {
                    record.uri = item.uri.to_string();
                    record.author_did = did.to_string();
                    // Extract rkey from URI: at://did:plc:xxx/social.moat.event/rkey
                    if let Some(rkey) = item.uri.split('/').last() {
                        record.rkey = rkey.to_string();
                    }
                    all_records.push(record);
                }
            }

            // Continue pagination if there's more data
            match &output.cursor {
                Some(next_cursor) if !output.records.is_empty() => {
                    cursor = Some(next_cursor.clone());
                }
                _ => break,
            }
        }

        Ok(all_records)
    }

    /// Fetch events matching a specific tag from a DID.
    pub async fn fetch_events_by_tag(
        &self,
        did: &str,
        tag: &[u8; 16],
    ) -> Result<Vec<EventRecord>> {
        let all_events = self.fetch_events_from_did(did, None).await?;

        // Filter by tag
        let matching: Vec<_> = all_events.into_iter().filter(|e| &e.tag == tag).collect();

        Ok(matching)
    }

    /// Resolve a handle to a DID.
    pub async fn resolve_did(&self, handle: &str) -> Result<String> {
        let input = atrium_api::com::atproto::identity::resolve_handle::ParametersData {
            handle: handle.parse().map_err(|_| Error::InvalidHandle(handle.to_string()))?,
        };

        let output = self
            .agent
            .api
            .com
            .atproto
            .identity
            .resolve_handle(input.into())
            .await
            .map_err(|e| Error::Pds(e.to_string()))?;

        Ok(output.did.to_string())
    }

    /// Resolve a DID to a handle.
    ///
    /// Fetches the DID document from PLC directory and extracts the handle
    /// from the `alsoKnownAs` field.
    pub async fn resolve_handle(&self, did: &str) -> Result<String> {
        let url = format!("{}/{}", PLC_DIRECTORY_URL, did);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Pds(format!("Failed to fetch DID document: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Pds(format!(
                "PLC directory returned {}: {}",
                response.status(),
                did
            )));
        }

        let doc: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Pds(format!("Failed to parse DID document: {}", e)))?;

        // Extract handle from alsoKnownAs array (format: "at://handle")
        if let Some(aliases) = doc["alsoKnownAs"].as_array() {
            for alias in aliases {
                if let Some(s) = alias.as_str() {
                    if let Some(handle) = s.strip_prefix("at://") {
                        return Ok(handle.to_string());
                    }
                }
            }
        }

        // Fallback to DID if no handle found
        Ok(did.to_string())
    }

    /// Publish a stealth address to the PDS.
    ///
    /// This is a singleton record (key: "self"), so calling this will
    /// replace any existing stealth address.
    ///
    /// Returns the AT-URI of the created record.
    pub async fn publish_stealth_address(&self, scan_pubkey: &[u8; 32]) -> Result<String> {
        let data = StealthAddressData {
            v: 1,
            scan_pubkey: *scan_pubkey,
            created_at: Utc::now(),
        };

        let record_value = serde_json::to_value(&data)?;
        let ipld_record = json_to_ipld(record_value)?;

        let record = match ipld_record {
            Ipld::Map(map) => atrium_api::types::Unknown::Object(
                map.into_iter()
                    .map(|(k, v)| (k, v.try_into().expect("valid ipld")))
                    .collect(),
            ),
            _ => return Err(Error::Serialization("expected object".to_string())),
        };

        let input = create_record::InputData {
            collection: Nsid::new(STEALTH_ADDRESS_NSID.to_string())
                .map_err(|e| Error::InvalidRecord(e.to_string()))?,
            record,
            repo: AtIdentifier::Did(
                self.did.parse().map_err(|_| Error::InvalidDid(self.did.clone()))?,
            ),
            rkey: Some("self".to_string()), // Singleton record
            swap_commit: None,
            validate: None,
        };

        let output = self
            .agent
            .api
            .com
            .atproto
            .repo
            .create_record(input.into())
            .await
            .map_err(|e| Error::Pds(e.to_string()))?;

        Ok(output.uri.to_string())
    }

    /// Fetch a user's stealth address.
    ///
    /// Resolves the DID's PDS and queries it directly.
    /// Returns `None` if the user hasn't published a stealth address.
    pub async fn fetch_stealth_address(&self, did: &str) -> Result<Option<[u8; 32]>> {
        // Resolve the target user's PDS
        let pds_url = self.resolve_pds_endpoint(did).await?;
        let pds_agent = self.agent_for_pds(&pds_url);

        let input = list_records::ParametersData {
            collection: Nsid::new(STEALTH_ADDRESS_NSID.to_string())
                .map_err(|e| Error::InvalidRecord(e.to_string()))?,
            cursor: None,
            limit: Some(1.try_into().unwrap()),
            repo: AtIdentifier::Did(
                did.parse().map_err(|_| Error::InvalidDid(did.to_string()))?,
            ),
            reverse: None,
            rkey_start: None,
            rkey_end: None,
        };

        let output = pds_agent
            .api
            .com
            .atproto
            .repo
            .list_records(input.into())
            .await
            .map_err(|e| Error::Pds(e.to_string()))?;

        // Look for the stealth address record
        for item in &output.records {
            let value = serde_json::to_value(&item.value)
                .map_err(|e| Error::Serialization(e.to_string()))?;

            if let Ok(record) = serde_json::from_value::<StealthAddressRecord>(value) {
                return Ok(Some(record.scan_pubkey));
            }
        }

        Ok(None)
    }
}

/// Convert serde_json::Value to IPLD
fn json_to_ipld(value: serde_json::Value) -> Result<Ipld> {
    match value {
        serde_json::Value::Null => Ok(Ipld::Null),
        serde_json::Value::Bool(b) => Ok(Ipld::Bool(b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Ipld::Integer(i.into()))
            } else if let Some(f) = n.as_f64() {
                // ATProto doesn't support floats, convert to string
                Ok(Ipld::String(f.to_string()))
            } else {
                Ok(Ipld::Null)
            }
        }
        serde_json::Value::String(s) => Ok(Ipld::String(s)),
        serde_json::Value::Array(arr) => {
            let ipld_arr: Result<Vec<Ipld>> = arr.into_iter().map(json_to_ipld).collect();
            Ok(Ipld::List(ipld_arr?))
        }
        serde_json::Value::Object(obj) => {
            let ipld_map: Result<BTreeMap<String, Ipld>> = obj
                .into_iter()
                .map(|(k, v)| Ok((k, json_to_ipld(v)?)))
                .collect();
            Ok(Ipld::Map(ipld_map?))
        }
    }
}
