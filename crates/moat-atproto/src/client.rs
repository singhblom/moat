//! ATProto client for Moat

use crate::error::{Error, Result};
use crate::records::{EventData, EventRecord, KeyPackageData, KeyPackageRecord};
use atrium_api::agent::{store::MemorySessionStore, AtpAgent};
use atrium_api::com::atproto::repo::{create_record, list_records};
use atrium_api::types::string::{AtIdentifier, Nsid};
use atrium_xrpc_client::reqwest::ReqwestClient;
use chrono::{Duration, Utc};
use ipld_core::ipld::Ipld;
use std::collections::BTreeMap;

/// Lexicon NSID for key packages
const KEY_PACKAGE_NSID: &str = "social.moat.keyPackage";

/// Lexicon NSID for events
const EVENT_NSID: &str = "social.moat.event";

/// Default PDS URL (Bluesky)
const DEFAULT_PDS_URL: &str = "https://bsky.social";

/// ATProto client for Moat operations
pub struct MoatAtprotoClient {
    agent: AtpAgent<MemorySessionStore, ReqwestClient>,
    did: String,
}

impl MoatAtprotoClient {
    /// Create a new client and authenticate with the PDS.
    pub async fn login(handle: &str, password: &str) -> Result<Self> {
        Self::login_with_pds(handle, password, DEFAULT_PDS_URL).await
    }

    /// Create a new client with a custom PDS URL.
    pub async fn login_with_pds(handle: &str, password: &str, pds_url: &str) -> Result<Self> {
        let agent = AtpAgent::new(
            ReqwestClient::new(pds_url.to_string()),
            MemorySessionStore::default(),
        );

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
            did: session.did.to_string(),
        })
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
    pub async fn fetch_key_packages(&self, did: &str) -> Result<Vec<KeyPackageRecord>> {
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

        let output = self
            .agent
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

            if let Ok(mut record) = serde_json::from_value::<KeyPackageRecord>(value) {
                record.uri = item.uri.to_string();
                record.cid = item.cid.as_ref().to_string();

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
    pub async fn fetch_events_from_did(
        &self,
        did: &str,
        cursor: Option<&str>,
    ) -> Result<(Vec<EventRecord>, Option<String>)> {
        let input = list_records::ParametersData {
            collection: Nsid::new(EVENT_NSID.to_string())
                .map_err(|e| Error::InvalidRecord(e.to_string()))?,
            cursor: cursor.map(|s| s.to_string()),
            limit: Some(100.try_into().unwrap()),
            repo: AtIdentifier::Did(
                did.parse().map_err(|_| Error::InvalidDid(did.to_string()))?,
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

        let mut records = Vec::new();
        for item in &output.records {
            let value = serde_json::to_value(&item.value)
                .map_err(|e| Error::Serialization(e.to_string()))?;

            if let Ok(mut record) = serde_json::from_value::<EventRecord>(value) {
                record.uri = item.uri.to_string();
                record.cid = item.cid.as_ref().to_string();
                record.author_did = did.to_string();
                records.push(record);
            }
        }

        Ok((records, output.cursor.clone()))
    }

    /// Fetch events matching a specific tag from a DID.
    pub async fn fetch_events_by_tag(
        &self,
        did: &str,
        tag: &[u8; 16],
    ) -> Result<Vec<EventRecord>> {
        let (all_events, _) = self.fetch_events_from_did(did, None).await?;

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
