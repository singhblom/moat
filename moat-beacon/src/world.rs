//! `TestWorld` — orchestrates processes for a single beacon scenario.
//!
//! Each `TestWorld` owns:
//! - A **Postern** in-process PDS.
//! - A **Toxiproxy** subprocess with one named proxy per service.
//! - One **`moat-cli --http`** subprocess per participant, each connected to
//!   Postern through the `proxy-pds` Toxiproxy proxy.
//! - A typed [`MoatCliClient`] for each participant.
//! - Optionally a **Drawbridge** WebSocket relay (via [`TestWorld::new_with_drawbridge`]).
//!
//! Everything is cleaned up when `TestWorld` is dropped.

use crate::client::MoatCliClient;
use crate::drawbridge::DrawbridgeProcess;
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
    /// Running child process; `None` when the participant has been killed (offline).
    child: Option<Child>,
    /// Persistent storage directory — kept alive across kill/restart cycles.
    #[allow(dead_code)]
    storage: TempDir,
    /// Full CLI args used to spawn the process (includes `--http <addr>`).
    /// Reused verbatim on restart so the HTTP port stays stable.
    spawn_args: Vec<String>,
    pub client: MoatCliClient,
}

impl Drop for ParticipantProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
    /// Optional Drawbridge relay (present when created via [`TestWorld::new_with_drawbridge`]).
    _drawbridge: Option<DrawbridgeProcess>,
    /// `proxy-db-verify` proxy: routes Drawbridge's PDS verification calls through
    /// Toxiproxy so tests can inject faults on the Drawbridge → Postern path.
    /// Only present when Drawbridge is enabled.
    pub db_verify_proxy: Option<ProxyHandle>,
    participants: HashMap<String, ParticipantProcess>,
    /// Path to the `moat` CLI binary; reused when restarting participants.
    moat_cli_bin: PathBuf,
}

impl TestWorld {
    /// Build a new `TestWorld` with the given participant handles (no Drawbridge).
    ///
    /// Accounts are created on Postern using `did:plc:<handle>` DIDs.
    /// All PDS traffic is routed through a `proxy-pds` Toxiproxy proxy so that
    /// tests can inject network faults via [`TestWorld::toxiproxy`].
    ///
    /// All processes are ready (have passed their health check) when this
    /// returns.
    ///
    /// `handle_suffix` is appended to every handle, e.g. `".postern.test"`.
    pub async fn new(handles: &[&str], handle_suffix: &str) -> Result<Self> {
        Self::build(handles, handle_suffix, false).await
    }

    /// Build a `TestWorld` with Drawbridge enabled.
    ///
    /// In addition to the base setup, this:
    /// - Spawns a Drawbridge WebSocket relay.
    /// - Creates a `proxy-db-verify` Toxiproxy proxy routing Drawbridge's
    ///   DID-resolution + PDS-verification calls to Postern.
    /// - Configures Postern's DID documents to advertise `proxy-db-verify` as
    ///   the PDS endpoint.
    /// - Passes `--drawbridge-url ws://drawbridge/ws` to each moat-cli process.
    ///
    /// Account DIDs use `did:plc:<handle>` format (required by Drawbridge's
    /// `PLCResolver`).
    pub async fn new_with_drawbridge(handles: &[&str], handle_suffix: &str) -> Result<Self> {
        Self::build(handles, handle_suffix, true).await
    }

    async fn build(handles: &[&str], handle_suffix: &str, with_drawbridge: bool) -> Result<Self> {
        // Build Postern accounts.  Use did:plc: format so Drawbridge's
        // PLCResolver accepts them (it enforces the did:plc: prefix).
        let accounts: Vec<AccountConfig> = handles
            .iter()
            .map(|h| AccountConfig {
                did: format!("did:plc:{h}"),
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
        let toxiproxy = ToxiproxyManager::spawn()
            .await
            .context("spawn toxiproxy")?;

        let postern_addr = postern_url
            .strip_prefix("http://")
            .unwrap_or(&postern_url)
            .to_string();
        let pds_proxy = toxiproxy
            .create_proxy("proxy-pds", &postern_addr)
            .await
            .context("create proxy-pds")?;

        // Optional Drawbridge setup.
        let (drawbridge, db_verify_proxy, drawbridge_ws_endpoint) = if with_drawbridge {
            // proxy-db-verify routes Drawbridge → Postern so we can fault-inject
            // Drawbridge's DID resolution and key-package verification calls.
            let db_verify = toxiproxy
                .create_proxy("proxy-db-verify", &postern_addr)
                .await
                .context("create proxy-db-verify")?;

            // Tell Postern to advertise proxy-db-verify as the PDS endpoint in
            // all DID documents.  Drawbridge will resolve test DIDs and then call
            // com.atproto.repo.listRecords through the proxy.
            postern.set_pds_endpoint_override(&db_verify.url);

            // Spawn Drawbridge with PLC_BASE_URL pointing at proxy-db-verify.
            let db = DrawbridgeProcess::spawn(&db_verify.url)
                .await
                .context("spawn drawbridge")?;

            let ws_endpoint = db.ws_endpoint();
            (Some(db), Some(db_verify), Some(ws_endpoint))
        } else {
            (None, None, None)
        };

        // Resolve the moat binary once for the whole world (also triggers
        // auto-build if needed).
        let moat_cli_bin = moat_cli_binary()?;

        let mut world = Self {
            _postern: postern,
            toxiproxy,
            pds_proxy: pds_proxy.clone(),
            postern_url,
            _drawbridge: drawbridge,
            db_verify_proxy,
            participants: HashMap::new(),
            moat_cli_bin,
        };

        for &handle in handles {
            let full_handle = format!("{handle}{handle_suffix}");
            world
                .spawn_participant(
                    handle,
                    &full_handle,
                    &pds_proxy.url.clone(),
                    drawbridge_ws_endpoint.as_deref(),
                )
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

    /// Kill a participant's process.  The participant is considered offline
    /// until [`TestWorld::restart_participant`] is called.
    ///
    /// The storage directory is **not** removed — it survives the restart.
    pub fn kill_participant(&mut self, handle: &str) -> Result<()> {
        let proc = self
            .participants
            .get_mut(handle)
            .ok_or_else(|| anyhow::anyhow!("unknown participant: {handle}"))?;
        if let Some(mut child) = proc.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    /// Restart a previously killed participant.
    ///
    /// Spawns a new process with the same CLI args (same HTTP port, same
    /// storage dir) and waits up to 10 s for the HTTP server to respond.
    pub async fn restart_participant(&mut self, handle: &str) -> Result<()> {
        let proc = self
            .participants
            .get_mut(handle)
            .ok_or_else(|| anyhow::anyhow!("unknown participant: {handle}"))?;

        let child = Command::new(&self.moat_cli_bin)
            .args(&proc.spawn_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("restart moat-cli for {handle}"))?;
        proc.child = Some(child);

        wait_for_http(&proc.client, std::time::Duration::from_secs(10))
            .await
            .with_context(|| format!("waiting for moat-cli ({handle}) to restart"))?;
        Ok(())
    }

    /// Returns `true` if the participant process is currently running.
    pub fn participant_is_online(&self, handle: &str) -> bool {
        self.participants
            .get(handle)
            .map(|p| p.child.is_some())
            .unwrap_or(false)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn spawn_participant(
        &mut self,
        short_handle: &str,
        full_handle: &str,
        pds_url: &str,
        drawbridge_ws: Option<&str>,
    ) -> Result<()> {
        let http_port = free_port()?;
        let http_addr = format!("127.0.0.1:{http_port}");
        let storage = TempDir::new().context("create temp storage dir")?;

        let mut args = vec![
            "--storage-dir".to_string(),
            storage.path().to_str().unwrap().to_string(),
            "--pds-url".to_string(),
            pds_url.to_string(),
            "--http".to_string(),
            http_addr.clone(),
        ];
        if let Some(db_url) = drawbridge_ws {
            args.push("--drawbridge-url".to_string());
            args.push(db_url.to_string());
        }

        let child = Command::new(&self.moat_cli_bin)
            .args(&args)
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
                child: Some(child),
                storage,
                spawn_args: args,
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
