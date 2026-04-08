use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A pre-configured account on Postern.
pub struct AccountConfig {
    /// The account's ATProto DID (e.g. `"did:plc:alice"`).
    pub did: String,
    /// The account's handle (e.g. `"alice.postern.test"`).
    pub handle: String,
}

/// Configuration for a Postern instance.
pub struct PosternConfig {
    /// Accounts available on this PDS.
    pub accounts: Vec<AccountConfig>,
    /// TCP port to bind. `None` = OS-assigned random port.
    pub port: Option<u16>,
    /// Root directory for on-disk state. `None` = a fresh timestamped
    /// directory under `/tmp/postern/`.
    pub data_dir: Option<PathBuf>,
}

/// Handle to a running Postern instance.
///
/// The server shuts down when this handle is dropped.
pub struct PosternHandle {
    pub(crate) url: String,
    pub(crate) data_dir: PathBuf,
    /// Sending on this channel signals the server to shut down.
    pub(crate) shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// Shared override for the `serviceEndpoint` field in DID documents.
    ///
    /// When `Some(url)`, all DID documents returned by Postern advertise
    /// this URL as their PDS endpoint instead of Postern's own bind address.
    /// Used by `TestWorld` to route Drawbridge's PDS verification calls
    /// through a `proxy-db-verify` Toxiproxy proxy.
    pub(crate) pds_endpoint_override: Arc<Mutex<Option<String>>>,
    /// Drawbridge URL advertised via `com.atproto.server.describeServer`.
    ///
    /// When `Some(url)`, `describeServer` includes a `social.moat.drawbridge`
    /// entry in its `services` map.  When `None`, `services` is empty.
    pub(crate) drawbridge_url: Arc<Mutex<Option<String>>>,
}

impl PosternHandle {
    /// Base URL of the server, e.g. `"http://localhost:54321"`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Path to the on-disk state directory (timestamped under `/tmp/postern/`).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Override the `serviceEndpoint` advertised in all DID documents.
    ///
    /// Set this to the `proxy-db-verify` Toxiproxy URL so Drawbridge's
    /// key-package verification calls are routed through the proxy.
    pub fn set_pds_endpoint_override(&self, url: &str) {
        *self.pds_endpoint_override.lock().unwrap() = Some(url.to_string());
    }

    /// Set the Drawbridge URL advertised via `com.atproto.server.describeServer`.
    ///
    /// After calling this, `GET /xrpc/com.atproto.server.describeServer` will
    /// include `services['social.moat.drawbridge']['endpoint']` in its response.
    pub fn set_drawbridge_url(&self, url: &str) {
        *self.drawbridge_url.lock().unwrap() = Some(url.to_string());
    }

    /// Clear the advertised Drawbridge URL so `describeServer` returns no
    /// `social.moat.drawbridge` entry.
    pub fn clear_drawbridge_url(&self) {
        *self.drawbridge_url.lock().unwrap() = None;
    }
}

impl Drop for PosternHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}
