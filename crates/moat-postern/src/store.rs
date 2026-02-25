//! In-memory record and blob store with on-disk persistence.
//!
//! Records are keyed by `(did, collection, rkey)` and stored in a `BTreeMap`
//! so they iterate in lexicographic rkey order — required for cursor-based
//! pagination.  Blobs are keyed by a SHA-256 hex CID.

use crate::config::AccountConfig;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

type RecordKey = (String, String, String);

pub struct Store {
    /// `(did, collection, rkey)` → record value.
    records: BTreeMap<RecordKey, Value>,
    /// `cid` → raw blob bytes.  Blobs are content-addressed globally.
    blobs: BTreeMap<String, Vec<u8>>,
    /// `handle` → `did`.
    handles: BTreeMap<String, String>,
    /// Monotonic counter used to generate rkeys when the caller omits one.
    counter: u64,
}

impl Store {
    pub fn new(accounts: &[AccountConfig]) -> Self {
        let mut handles = BTreeMap::new();
        for a in accounts {
            handles.insert(a.handle.clone(), a.did.clone());
        }
        Self {
            records: BTreeMap::new(),
            blobs: BTreeMap::new(),
            handles,
            counter: 0,
        }
    }

    /// Generate a unique, lexicographically-sortable rkey.
    pub fn next_rkey(&mut self) -> String {
        self.counter += 1;
        format!("{:020}", self.counter)
    }

    pub fn put_record(&mut self, did: &str, collection: &str, rkey: &str, value: Value) {
        self.records
            .insert((did.to_string(), collection.to_string(), rkey.to_string()), value);
    }

    pub fn get_record(&self, did: &str, collection: &str, rkey: &str) -> Option<&Value> {
        self.records
            .get(&(did.to_string(), collection.to_string(), rkey.to_string()))
    }

    /// Return `(records, next_cursor)`.
    ///
    /// - `cursor`     – exclusive lower bound on rkey (pagination offset).
    /// - `rkey_start` – inclusive lower bound on rkey (absolute filter).
    /// - `limit`      – max records to return.
    ///
    /// `next_cursor` is `Some(last_rkey)` when more pages exist, `None` on
    /// the final page.
    pub fn list_records(
        &self,
        did: &str,
        collection: &str,
        limit: usize,
        cursor: Option<&str>,
        rkey_start: Option<&str>,
    ) -> (Vec<(String, Value)>, Option<String>) {
        let cursor_bound = cursor.unwrap_or("");
        let start_bound = rkey_start.unwrap_or("");

        let mut iter = self
            .records
            .iter()
            .filter(|((d, c, _), _)| d == did && c == collection)
            .filter(|((_, _, rkey), _)| rkey.as_str() > cursor_bound)
            .filter(|((_, _, rkey), _)| rkey.as_str() >= start_bound)
            .map(|((_, _, rkey), val)| (rkey.clone(), val.clone()));

        let page: Vec<(String, Value)> = iter.by_ref().take(limit).collect();

        // Peek at the next element to decide whether a cursor is needed.
        let next_cursor = if iter.next().is_some() {
            page.last().map(|(rkey, _)| rkey.clone())
        } else {
            None
        };

        (page, next_cursor)
    }

    /// Remove a record.  Returns `true` if the record existed.
    pub fn delete_record(&mut self, did: &str, collection: &str, rkey: &str) -> bool {
        self.records
            .remove(&(did.to_string(), collection.to_string(), rkey.to_string()))
            .is_some()
    }

    /// Store `data`, returning its CID (`sha256:<hex>`).
    pub fn put_blob(&mut self, data: Vec<u8>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        let cid = format!("sha256:{}", hex_encode(&hash));
        self.blobs.insert(cid.clone(), data);
        cid
    }

    pub fn get_blob(&self, cid: &str) -> Option<&Vec<u8>> {
        self.blobs.get(cid)
    }

    pub fn resolve_handle(&self, handle: &str) -> Option<&String> {
        self.handles.get(handle)
    }

    /// Reverse-lookup: return the handle for a DID, or `None` if unknown.
    pub fn resolve_did(&self, did: &str) -> Option<String> {
        self.handles
            .iter()
            .find(|(_, d)| d.as_str() == did)
            .map(|(h, _)| h.clone())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub type SharedStore = Arc<RwLock<Store>>;
