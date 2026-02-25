//! ATProto client for Moat

use crate::error::{Error, Result};
use crate::records::{
    EventData, EventRecord, KeyPackageData, KeyPackageRecord, StealthAddressData,
    StealthAddressRecord,
};
use atrium_api::agent::{store::MemorySessionStore, AtpAgent};
use atrium_api::com::atproto::repo::{create_record, delete_record, list_records};
use atrium_api::com::atproto::server::create_session::OutputData as SessionData;
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
///
/// This type is cheaply cloneable (all fields are `Arc`-wrapped or inherently
/// clone-friendly) so it can be shared with background `tokio::spawn` tasks.
#[derive(Clone)]
pub struct MoatAtprotoClient {
    /// Authenticated agent for the user's PDS (used for writes)
    agent: std::sync::Arc<AtpAgent<MemorySessionStore, ReqwestClient>>,
    /// HTTP client for PLC directory lookups and raw blob operations
    http_client: reqwest::Client,
    did: String,
    /// Base URL of the user's own PDS (e.g. "https://bsky.social")
    pds_url: String,
    /// When set, `resolve_pds_endpoint` returns this URL for every DID
    /// instead of performing real DID resolution. Used in integration tests
    /// where all participants are on a single local PDS.
    pds_override: Option<String>,
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
        let xrpc_client = ReqwestClientBuilder::new(pds_url)
            .client(http_client.clone())
            .build();
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
            agent: std::sync::Arc::new(agent),
            http_client,
            did: session.did.to_string(),
            pds_url: pds_url.to_string(),
            pds_override: None,
        })
    }

    /// Override PDS resolution: every `resolve_pds_endpoint` call returns this
    /// URL regardless of the DID. Useful for integration tests where all
    /// participants share a single local Postern instance.
    pub fn with_pds_override(mut self, url: String) -> Self {
        self.pds_override = Some(url);
        self
    }

    /// Resume a session from stored tokens.
    ///
    /// This avoids counting against the login rate limit by reusing existing tokens.
    /// If the access token is expired, the agent will automatically refresh it.
    pub async fn resume_session(did: &str, access_jwt: &str, refresh_jwt: &str) -> Result<Self> {
        Self::resume_session_with_pds(did, access_jwt, refresh_jwt, DEFAULT_PDS_URL).await
    }

    /// Resume a session from stored tokens with a custom PDS URL.
    pub async fn resume_session_with_pds(
        did: &str,
        access_jwt: &str,
        refresh_jwt: &str,
        pds_url: &str,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| Error::Pds(format!("Failed to create HTTP client: {}", e)))?;

        let xrpc_client = ReqwestClientBuilder::new(pds_url)
            .client(http_client.clone())
            .build();
        let agent = AtpAgent::new(xrpc_client, MemorySessionStore::default());

        // Create a minimal session with the stored tokens
        let session_data = SessionData {
            access_jwt: access_jwt.to_string(),
            refresh_jwt: refresh_jwt.to_string(),
            did: did
                .parse()
                .map_err(|_| Error::InvalidDid(did.to_string()))?,
            handle: "unknown.invalid".parse().expect("valid handle"), // Will be updated by resume_session
            active: None,
            did_doc: None,
            email: None,
            email_auth_factor: None,
            email_confirmed: None,
            status: None,
        };

        agent
            .resume_session(session_data.into())
            .await
            .map_err(|_| Error::SessionExpired)?;

        Ok(Self {
            agent: std::sync::Arc::new(agent),
            http_client,
            did: did.to_string(),
            pds_url: pds_url.to_string(),
            pds_override: None,
        })
    }

    /// Get the current session tokens for persistence.
    ///
    /// Returns (access_jwt, refresh_jwt) if a session is active.
    pub async fn get_session_tokens(&self) -> Option<(String, String)> {
        let session = self.agent.get_session().await?;
        Some((session.access_jwt.clone(), session.refresh_jwt.clone()))
    }

    /// Resolve a DID's PDS endpoint.
    ///
    /// Resolution order:
    /// 1. `pds_override` — returns it immediately (for integration tests).
    /// 2. `did:web:` — fetches `/.well-known/did.json` from the encoded host.
    /// 3. PLC directory — the default for `did:plc:` DIDs.
    async fn resolve_pds_endpoint(&self, did: &str) -> Result<String> {
        // 1. Override: used in integration tests where all peers share one PDS.
        if let Some(ref url) = self.pds_override {
            return Ok(url.clone());
        }

        // 2. did:web: resolution.
        if did.starts_with("did:web:") {
            return self.resolve_did_web(did).await;
        }

        // 3. PLC directory (default for did:plc:).
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

        self.extract_pds_from_doc(&doc, did)
    }

    /// Resolve a `did:web:` DID by fetching `/.well-known/did.json`.
    ///
    /// `did:web:host%3Aport` maps to `http://host:port/.well-known/did.json`.
    /// Path segments (`did:web:host:path:to`) map to `/path/to/did.json`.
    async fn resolve_did_web(&self, did: &str) -> Result<String> {
        let authority = did
            .strip_prefix("did:web:")
            .unwrap()
            .replace("%3A", ":")
            .replace("%3a", ":");

        // Split off any path segments (did:web:host:a:b → host, ["a","b"])
        let mut parts = authority.splitn(2, ':');
        let host = parts.next().unwrap_or("");
        let path = parts
            .next()
            .map(|p| format!("/{}", p.replace(':', "/")))
            .unwrap_or_default();

        // Use http for localhost, https otherwise.
        let scheme = if host.starts_with("localhost") || host.starts_with("127.") {
            "http"
        } else {
            "https"
        };
        let doc_url = format!("{scheme}://{host}{path}/.well-known/did.json");

        let response = self
            .http_client
            .get(&doc_url)
            .send()
            .await
            .map_err(|e| Error::Pds(format!("Failed to fetch did:web document: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Pds(format!(
                "did:web resolution returned {}: {}",
                response.status(),
                did
            )));
        }

        let doc: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Pds(format!("Failed to parse did:web document: {}", e)))?;

        self.extract_pds_from_doc(&doc, did)
    }

    /// Extract the `AtprotoPersonalDataServer` endpoint from a DID document.
    fn extract_pds_from_doc(&self, doc: &serde_json::Value, did: &str) -> Result<String> {
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
        let xrpc_client = ReqwestClientBuilder::new(pds_url)
            .client(self.http_client.clone())
            .build();
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
                self.did
                    .parse()
                    .map_err(|_| Error::InvalidDid(self.did.clone()))?,
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
                did.parse()
                    .map_err(|_| Error::InvalidDid(did.to_string()))?,
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
                self.did
                    .parse()
                    .map_err(|_| Error::InvalidDid(self.did.clone()))?,
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
                    did.parse()
                        .map_err(|_| Error::InvalidDid(did.to_string()))?,
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
    pub async fn fetch_events_by_tag(&self, did: &str, tag: &[u8; 16]) -> Result<Vec<EventRecord>> {
        let all_events = self.fetch_events_from_did(did, None).await?;

        // Filter by tag
        let matching: Vec<_> = all_events.into_iter().filter(|e| &e.tag == tag).collect();

        Ok(matching)
    }

    /// Resolve a handle to a DID.
    pub async fn resolve_did(&self, handle: &str) -> Result<String> {
        let input = atrium_api::com::atproto::identity::resolve_handle::ParametersData {
            handle: handle
                .parse()
                .map_err(|_| Error::InvalidHandle(handle.to_string()))?,
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

    /// Publish a stealth address to the PDS for this device.
    ///
    /// Each device publishes its own stealth address with a unique TID.
    /// Multiple devices can coexist under the same DID.
    ///
    /// Returns the AT-URI of the created record.
    pub async fn publish_stealth_address(
        &self,
        scan_pubkey: &[u8; 32],
        device_name: &str,
    ) -> Result<String> {
        let data = StealthAddressData {
            v: 2,
            scan_pubkey: *scan_pubkey,
            device_name: device_name.to_string(),
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
                self.did
                    .parse()
                    .map_err(|_| Error::InvalidDid(self.did.clone()))?,
            ),
            rkey: None, // Let PDS generate TID
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

    /// Fetch all stealth addresses for a user (one per device).
    ///
    /// Resolves the DID's PDS and queries it directly.
    /// Returns a list of (public_key, device_name) tuples, one for each device.
    /// Returns an empty Vec if the user hasn't published any stealth addresses.
    pub async fn fetch_stealth_addresses(&self, did: &str) -> Result<Vec<StealthAddressRecord>> {
        // Resolve the target user's PDS
        let pds_url = self.resolve_pds_endpoint(did).await?;
        let pds_agent = self.agent_for_pds(&pds_url);

        let input = list_records::ParametersData {
            collection: Nsid::new(STEALTH_ADDRESS_NSID.to_string())
                .map_err(|e| Error::InvalidRecord(e.to_string()))?,
            cursor: None,
            limit: Some(100.try_into().unwrap()), // Get all devices
            repo: AtIdentifier::Did(
                did.parse()
                    .map_err(|_| Error::InvalidDid(did.to_string()))?,
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

            if let Ok(mut record) = serde_json::from_value::<StealthAddressRecord>(value) {
                // Only accept v2 records (multi-device)
                if record.v == 2 {
                    // Extract rkey from URI
                    if let Some(rkey) = item.uri.split('/').last() {
                        record.rkey = rkey.to_string();
                    }
                    records.push(record);
                }
            }
        }

        Ok(records)
    }

    /// Delete all Moat records from the user's PDS.
    ///
    /// This deletes all events, key packages, and stealth addresses.
    /// Use with caution - this cannot be undone!
    ///
    /// Returns the number of records deleted.
    pub async fn delete_all_records(&self) -> Result<usize> {
        let collections = [EVENT_NSID, KEY_PACKAGE_NSID, STEALTH_ADDRESS_NSID];
        let mut total_deleted = 0;

        for collection in &collections {
            let deleted = self.delete_all_records_in_collection(collection).await?;
            total_deleted += deleted;
        }

        Ok(total_deleted)
    }

    /// Delete all records in a specific collection.
    async fn delete_all_records_in_collection(&self, collection: &str) -> Result<usize> {
        let mut deleted = 0;
        let mut cursor: Option<String> = None;

        loop {
            // List records
            let input = list_records::ParametersData {
                collection: Nsid::new(collection.to_string())
                    .map_err(|e| Error::InvalidRecord(e.to_string()))?,
                cursor: cursor.clone(),
                limit: Some(100.try_into().unwrap()),
                repo: AtIdentifier::Did(
                    self.did
                        .parse()
                        .map_err(|_| Error::InvalidDid(self.did.clone()))?,
                ),
                reverse: None,
                rkey_start: None,
                rkey_end: None,
            };

            let output = self
                .agent
                .api
                .com
                .atproto
                .repo
                .list_records(input.into())
                .await
                .map_err(|e| Error::Pds(e.to_string()))?;

            if output.records.is_empty() {
                break;
            }

            // Delete each record
            for item in &output.records {
                // Extract rkey from URI
                if let Some(rkey) = item.uri.split('/').last() {
                    let delete_input = delete_record::InputData {
                        collection: Nsid::new(collection.to_string())
                            .map_err(|e| Error::InvalidRecord(e.to_string()))?,
                        repo: AtIdentifier::Did(
                            self.did
                                .parse()
                                .map_err(|_| Error::InvalidDid(self.did.clone()))?,
                        ),
                        rkey: rkey.to_string(),
                        swap_commit: None,
                        swap_record: None,
                    };

                    self.agent
                        .api
                        .com
                        .atproto
                        .repo
                        .delete_record(delete_input.into())
                        .await
                        .map_err(|e| Error::Pds(e.to_string()))?;

                    deleted += 1;
                }
            }

            // Continue pagination if there's more
            match &output.cursor {
                Some(next_cursor) if !output.records.is_empty() => {
                    cursor = Some(next_cursor.clone());
                }
                _ => break,
            }
        }

        Ok(deleted)
    }

    /// Upload an encrypted blob to the user's own PDS.
    ///
    /// The caller is responsible for encrypting the blob before calling this.
    /// Uses `com.atproto.repo.uploadBlob` with `application/octet-stream`.
    ///
    /// **Important**: the blob is garbage-collected by the PDS until it is
    /// referenced by a record. Create the event record referencing this blob
    /// immediately after upload.
    ///
    /// # Returns
    ///
    /// The CID string (e.g. `bafkreixxxxxxxx`). Callers typically construct
    /// the `ExternalBlob.uri` as `at://{own_did}/{cid}`.
    pub async fn upload_blob(&self, data: &[u8]) -> Result<String> {
        let session = self
            .agent
            .get_session()
            .await
            .ok_or_else(|| Error::Authentication("no active session".to_string()))?;

        let url = format!("{}/xrpc/com.atproto.repo.uploadBlob", self.pds_url);
        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", session.access_jwt))
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| Error::Pds(format!("blob upload request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Pds(format!("uploadBlob returned {status}: {body}")));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Serialization(format!("failed to parse uploadBlob response: {e}")))?;

        // Extract CID from: {"blob": {"$type": "blob", "ref": {"$link": "<cid>"}, ...}}
        let cid = json
            .get("blob")
            .and_then(|b| b.get("ref"))
            .and_then(|r| r.get("$link"))
            .and_then(|l| l.as_str())
            .ok_or_else(|| Error::Serialization("uploadBlob response missing blob.ref.$link".to_string()))?;

        Ok(cid.to_string())
    }

    /// Download a blob from a remote DID's PDS.
    ///
    /// Resolves the sender's PDS endpoint from their DID, then fetches the blob
    /// via `com.atproto.sync.getBlob`. The returned bytes are the raw encrypted
    /// blob (`nonce || ciphertext`) — callers must decrypt with `blob_decrypt`.
    pub async fn fetch_blob(&self, did: &str, cid: &str) -> Result<Vec<u8>> {
        let pds_url = self.resolve_pds_endpoint(did).await?;
        let url = format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            pds_url, did, cid
        );

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Pds(format!("blob fetch request failed: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::NotFound(format!("blob not found: did={did} cid={cid}")));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Pds(format!("getBlob returned {status}: {body}")));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Pds(format!("failed to read blob response body: {e}")))?;

        Ok(bytes.to_vec())
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
