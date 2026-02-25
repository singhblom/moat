//! `TestWorld` — orchestrates processes for a single beacon scenario.
//!
//! Each `TestWorld` owns:
//! - A **Postern** in-process PDS.
//! - A **Toxiproxy** subprocess with one named proxy per service.
//! - One **`moat-cli --http`** subprocess per participant, each connected to
//!   Postern through the `proxy-pds` Toxiproxy proxy.
//! - A typed [`MoatCliClient`] for each participant.
//!
//! Everything is cleaned up when `TestWorld` is dropped.

use crate::client::MoatCliClient;
use crate::toxiproxy::{ProxyHandle, ToxiproxyManager};
use anyhow::{Context, Result};
use moat_postern::{AccountConfig, PosternConfig, PosternHandle};
use std::{
    collections::HashMap,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command},
};
use tempfile::TempDir;

// ── ParticipantProcess ────────────────────────────────────────────────────────

struct ParticipantProcess {
    _child: Child,
    _storage: TempDir,
    pub client: MoatCliClient,
}

impl Drop for ParticipantProcess {
    fn drop(&mut self) {
        // Kill child; ignore errors (process may have already exited).
        let _ = self._child.kill();
    }
}

// ── TestWorld ─────────────────────────────────────────────────────────────────

/// Central orchestrator for a beacon integration scenario.
pub struct TestWorld {
    _postern: PosternHandle,
    /// Toxiproxy subprocess — kept alive so proxies remain functional.
    pub toxiproxy: ToxiproxyManager,
    /// The `proxy-pds` proxy: all participants' PDS traffic passes through it.
    pub pds_proxy: ProxyHandle,
    /// Direct Postern URL (useful for out-of-band inspection).
    postern_url: String,
    participants: HashMap<String, ParticipantProcess>,
}

impl TestWorld {
    /// Build a new `TestWorld` with the given participant handles.
    ///
    /// Accounts are created on Postern using simple `did:test:<handle>` DIDs.
    /// All PDS traffic is routed through a `proxy-pds` Toxiproxy proxy so that
    /// tests can inject network faults via [`TestWorld::toxiproxy`].
    ///
    /// All processes are ready (have passed their health check) when this
    /// returns.
    ///
    /// `handle_suffix` is appended to every handle, e.g. `".postern.test"`.
    pub async fn new(handles: &[&str], handle_suffix: &str) -> Result<Self> {
        // Build Postern accounts.
        let accounts: Vec<AccountConfig> = handles
            .iter()
            .map(|h| AccountConfig {
                did: format!("did:test:{h}"),
                handle: format!("{h}{handle_suffix}"),
            })
            .collect();

        // Spawn the in-process PDS.
        let postern = moat_postern::spawn_postern(PosternConfig {
            accounts,
            port: None,
            data_dir: None,
        })
        .await;
        let postern_url = postern.url().to_string();

        // Spawn Toxiproxy and create a proxy in front of Postern.
        // moat-cli processes will use the proxy URL instead of connecting
        // directly to Postern, so tests can inject faults later.
        let toxiproxy = ToxiproxyManager::spawn()
            .await
            .context("spawn toxiproxy")?;

        // Toxiproxy expects the upstream as "host:port" (no scheme).
        let postern_addr = postern_url
            .strip_prefix("http://")
            .unwrap_or(&postern_url)
            .to_string();
        let pds_proxy = toxiproxy
            .create_proxy("proxy-pds", &postern_addr)
            .await
            .context("create proxy-pds")?;

        let mut world = Self {
            _postern: postern,
            toxiproxy,
            pds_proxy: pds_proxy.clone(),
            postern_url,
            participants: HashMap::new(),
        };

        // Spawn a moat-cli --http process for each participant, configured to
        // reach Postern through the proxy.
        for &handle in handles {
            let full_handle = format!("{handle}{handle_suffix}");
            world
                .spawn_participant(handle, &full_handle, &pds_proxy.url.clone())
                .await
                .with_context(|| format!("spawning participant {handle}"))?;
        }

        Ok(world)
    }

    /// Get the typed HTTP client for a participant by short handle (without suffix).
    pub fn client(&self, handle: &str) -> &MoatCliClient {
        &self.participants[handle].client
    }

    /// The direct Postern base URL, e.g. `"http://127.0.0.1:PORT"`.
    ///
    /// Useful for out-of-band PDS inspection; participants communicate through
    /// `pds_proxy.url` instead.
    pub fn postern_url(&self) -> &str {
        &self.postern_url
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn spawn_participant(
        &mut self,
        short_handle: &str,
        full_handle: &str,
        pds_url: &str,
    ) -> Result<()> {
        let http_port = free_port()?;
        let http_addr = format!("127.0.0.1:{http_port}");
        let storage = TempDir::new().context("create temp storage dir")?;

        let moat_cli_bin = moat_cli_binary()?;

        let child = Command::new(&moat_cli_bin)
            .args([
                "--storage-dir",
                storage.path().to_str().unwrap(),
                "--pds-url",
                pds_url,
                "--http",
                &http_addr,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("spawn moat-cli for {full_handle}"))?;

        let base_url = format!("http://{http_addr}");
        let client = MoatCliClient::new(&base_url);

        // Wait until the HTTP server is up (up to 10 s).
        wait_for_http(&client, std::time::Duration::from_secs(10))
            .await
            .with_context(|| format!("waiting for moat-cli ({full_handle}) to start"))?;

        self.participants.insert(
            short_handle.to_string(),
            ParticipantProcess {
                _child: child,
                _storage: storage,
                client,
            },
        );
        Ok(())
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Find a free TCP port by binding to `127.0.0.1:0`.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

/// Path to the `moat-cli` binary in the Cargo target directory.
///
/// If the binary does not exist, this function builds it automatically.
fn moat_cli_binary() -> Result<PathBuf> {
    // Cargo sets CARGO_MANIFEST_DIR; walk up to the workspace root.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set — run via cargo test")?;

    // moat-beacon is at <workspace>/moat-beacon/, so workspace root is one level up.
    let workspace_root = PathBuf::from(&manifest_dir)
        .parent()
        .context("manifest_dir has no parent")?
        .to_path_buf();

    // Prefer the same profile that cargo is using (debug unless RELEASE).
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    // The moat-cli package defines its binary as "moat" (not "moat-cli").
    let bin = workspace_root.join("target").join(profile).join("moat");

    if !bin.exists() {
        // Auto-build moat-cli if not yet compiled.
        eprintln!("beacon: moat-cli not found, building…");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let status = Command::new(&cargo)
            .args(["build", "-p", "moat-cli"])
            .current_dir(&workspace_root)
            .status()
            .context("running cargo build -p moat-cli")?;
        if !status.success() {
            anyhow::bail!("cargo build -p moat-cli failed");
        }
        if !bin.exists() {
            anyhow::bail!(
                "moat binary still not found at {} after build",
                bin.display()
            );
        }
    }

    Ok(bin)
}

/// Poll `GET /status` until it returns 200 or the timeout elapses.
async fn wait_for_http(client: &MoatCliClient, timeout: std::time::Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if client.status().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::bail!("moat-cli HTTP server did not start within {:?}", timeout)
}
