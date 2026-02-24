use std::path::{Path, PathBuf};

/// A pre-configured account on Postern.
pub struct AccountConfig {
    /// The account's ATProto DID (e.g. `"did:test:alice"`).
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
}

impl Drop for PosternHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}
