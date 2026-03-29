//! `ToxiproxyManager` — find/download `toxiproxy-server`, spawn it, and
//! configure proxies via its HTTP management API.
//!
//! Toxiproxy puts a controllable TCP proxy in front of every downstream
//! service.  Tests use the management API to inject faults (latency, resets,
//! bandwidth limits) without changing any application code.
//!
//! Phase 2 just routes connections through clean proxies (no toxics).
//! Fault injection is added in Phase 3+.

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command},
};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

/// Pinned Toxiproxy release used when auto-downloading.
const TOXIPROXY_VERSION: &str = "2.12.0";

// ── ProxyHandle ───────────────────────────────────────────────────────────────

/// A proxy created inside the running Toxiproxy instance.
#[derive(Debug, Clone)]
pub struct ProxyHandle {
    /// Logical name (e.g. `"proxy-pds"`).
    pub name: String,
    /// `host:port` the proxy listens on (e.g. `"127.0.0.1:12345"`).
    pub listen_addr: String,
    /// Full HTTP URL usable as a PDS or service base URL
    /// (e.g. `"http://127.0.0.1:12345"`).
    pub url: String,
}

// ── ToxiproxyManager ──────────────────────────────────────────────────────────

/// Owns a `toxiproxy-server` subprocess and a reqwest client pointed at its
/// HTTP management API.
///
/// The subprocess is killed when this value is dropped.
pub struct ToxiproxyManager {
    child: Child,
    /// OS process group ID (= child PID, since it was spawned with
    /// `process_group(0)`).  Other children that should be cleaned up
    /// together should join this group.
    pub pgid: u32,
    mgmt_port: u16,
    client: Client,
}

impl ToxiproxyManager {
    /// Find or download the toxiproxy binary, spawn it on a randomly chosen
    /// management port, and wait until its HTTP API is accepting requests.
    pub async fn spawn() -> Result<Self> {
        let bin = find_or_download()
            .await
            .context("obtain toxiproxy-server binary")?;

        let mgmt_port = free_port().context("allocate toxiproxy management port")?;

        let mut cmd = Command::new(&bin);
        cmd.args(["-port", &mgmt_port.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        cmd.process_group(0); // new group; child PID becomes the PGID
        let child = cmd.spawn().context("spawn toxiproxy-server")?;

        let pgid = child.id();
        let client = Client::new();
        let mgr = Self {
            child,
            pgid,
            mgmt_port,
            client,
        };

        wait_for_mgmt_api(&mgr.client, mgmt_port)
            .await
            .context("waiting for toxiproxy management API to become ready")?;

        Ok(mgr)
    }

    /// HTTP management API base URL (`http://127.0.0.1:<port>`).
    pub fn mgmt_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.mgmt_port)
    }

    /// Create a TCP proxy named `name` that forwards to `upstream_addr`
    /// (`host:port`, no scheme).  The proxy listens on a randomly chosen local
    /// port.
    ///
    /// Returns a [`ProxyHandle`] containing the listen address and a full URL.
    pub async fn create_proxy(&self, name: &str, upstream_addr: &str) -> Result<ProxyHandle> {
        let listen_port = free_port().context("allocate proxy listen port")?;
        let listen_addr = format!("127.0.0.1:{listen_port}");

        let resp = self
            .client
            .post(format!("{}/proxies", self.mgmt_url()))
            .json(&json!({
                "name":     name,
                "listen":   listen_addr,
                "upstream": upstream_addr,
                "enabled":  true,
            }))
            .send()
            .await
            .context("POST /proxies")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("create_proxy '{name}' failed ({status}): {body}");
        }

        Ok(ProxyHandle {
            name: name.to_string(),
            listen_addr: listen_addr.clone(),
            url: format!("http://{listen_addr}"),
        })
    }

    /// Add a named toxic to a proxy.
    ///
    /// `kind` is a Toxiproxy toxic type string (e.g. `"latency"`, `"timeout"`,
    /// `"bandwidth"`, `"slow_close"`, `"reset_peer"`, `"limit_data"`).
    ///
    /// `attributes` is passed verbatim as the `attributes` JSON object.
    /// Example for latency: `json!({"latency": 200, "jitter": 50})`.
    pub async fn add_toxic(
        &self,
        proxy_name: &str,
        toxic_name: &str,
        kind: &str,
        toxicity: f64,
        attributes: serde_json::Value,
    ) -> Result<()> {
        let resp = self
            .client
            .post(format!(
                "{}/proxies/{proxy_name}/toxics",
                self.mgmt_url()
            ))
            .json(&json!({
                "name":       toxic_name,
                "type":       kind,
                "stream":     "upstream",
                "toxicity":   toxicity,
                "attributes": attributes,
            }))
            .send()
            .await
            .context("POST /toxics")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "add_toxic '{toxic_name}' to '{proxy_name}' failed ({status}): {body}"
            );
        }
        Ok(())
    }

    /// Remove a specific toxic from a proxy.
    pub async fn remove_toxic(&self, proxy_name: &str, toxic_name: &str) -> Result<()> {
        let resp = self
            .client
            .delete(format!(
                "{}/proxies/{proxy_name}/toxics/{toxic_name}",
                self.mgmt_url()
            ))
            .send()
            .await
            .context("DELETE /toxic")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "remove_toxic '{toxic_name}' from '{proxy_name}' failed ({status}): {body}"
            );
        }
        Ok(())
    }

    /// Disable a proxy entirely (simulates a complete connection blackout).
    pub async fn disable_proxy(&self, proxy_name: &str) -> Result<()> {
        self.set_proxy_enabled(proxy_name, false).await
    }

    /// Re-enable a previously disabled proxy.
    pub async fn enable_proxy(&self, proxy_name: &str) -> Result<()> {
        self.set_proxy_enabled(proxy_name, true).await
    }

    async fn set_proxy_enabled(&self, proxy_name: &str, enabled: bool) -> Result<()> {
        let resp = self
            .client
            .post(format!("{}/proxies/{proxy_name}", self.mgmt_url()))
            .json(&json!({ "enabled": enabled }))
            .send()
            .await
            .context("POST /proxy (update enabled)")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("set_proxy_enabled({proxy_name}, {enabled}) failed ({status}): {body}");
        }
        Ok(())
    }
}

impl Drop for ToxiproxyManager {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Binary management ─────────────────────────────────────────────────────────

/// Return a path to a usable `toxiproxy-server` binary, downloading it if
/// necessary.
///
/// Search order:
/// 1. `TOXIPROXY_BIN` environment variable (must point to an existing file).
/// 2. `toxiproxy-server` in `PATH`.
/// 3. Cached binary at `~/.cache/moat-beacon/toxiproxy-{VERSION}/toxiproxy-server`.
/// 4. Auto-download from the GitHub releases CDN and cache it.
async fn find_or_download() -> Result<PathBuf> {
    // 1. Explicit env override.
    if let Ok(bin) = std::env::var("TOXIPROXY_BIN") {
        let path = PathBuf::from(&bin);
        anyhow::ensure!(path.exists(), "TOXIPROXY_BIN={bin} does not exist");
        return Ok(path);
    }

    // 2. PATH lookup.
    if let Some(path) = which_toxiproxy() {
        return Ok(path);
    }

    // 3. Local cache.
    let cached = cached_bin_path();
    if cached.exists() {
        return Ok(cached);
    }

    // 4. Download from GitHub.
    eprintln!("beacon: toxiproxy-server not found; downloading v{TOXIPROXY_VERSION}…");
    download_toxiproxy(&cached)
        .await
        .context("download toxiproxy-server")?;
    Ok(cached)
}

/// Search `PATH` for `toxiproxy-server` using portable `split_paths`.
fn which_toxiproxy() -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("toxiproxy-server");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Filesystem path for the cached binary.
fn cached_bin_path() -> PathBuf {
    beacon_cache_dir()
        .join(format!("toxiproxy-{TOXIPROXY_VERSION}"))
        .join("toxiproxy-server")
}

/// Base cache dir: `$XDG_CACHE_HOME/moat-beacon` → `~/.cache/moat-beacon`
/// → `/tmp/moat-beacon-cache` (fallback).
fn beacon_cache_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("moat-beacon")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache").join("moat-beacon")
    } else {
        PathBuf::from("/tmp/moat-beacon-cache")
    }
}

/// Construct the GitHub release download URL for the current OS / architecture.
fn release_url() -> Result<String> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        "windows" => "windows",
        other => anyhow::bail!("unsupported OS for toxiproxy auto-download: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => anyhow::bail!("unsupported arch for toxiproxy auto-download: {other}"),
    };
    let ext = if os == "windows" { ".exe" } else { "" };
    Ok(format!(
        "https://github.com/Shopify/toxiproxy/releases/download/v{TOXIPROXY_VERSION}/toxiproxy-server-{os}-{arch}{ext}"
    ))
}

/// Download the toxiproxy-server binary to `dest` and make it executable.
async fn download_toxiproxy(dest: &PathBuf) -> Result<()> {
    let url = release_url()?;
    eprintln!("beacon: fetching {url}");

    let bytes = Client::new()
        .get(&url)
        .send()
        .await
        .context("GET toxiproxy release")?
        .error_for_status()
        .context("toxiproxy download HTTP error")?
        .bytes()
        .await
        .context("read toxiproxy response body")?;

    // Create parent directories.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).context("create toxiproxy cache dir")?;
    }

    // Write to a temp path first, then rename atomically.
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &bytes).context("write toxiproxy binary")?;

    // Set executable bit on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)
            .context("stat toxiproxy tmp file")?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp, perms).context("chmod toxiproxy")?;
    }

    std::fs::rename(&tmp, dest).context("install toxiproxy binary")?;
    eprintln!("beacon: toxiproxy cached at {}", dest.display());
    Ok(())
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

/// Poll `GET /version` until Toxiproxy's management API responds or the
/// 10-second deadline expires.
async fn wait_for_mgmt_api(client: &Client, port: u16) -> Result<()> {
    let url = format!("http://127.0.0.1:{port}/version");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::bail!("toxiproxy management API at {url} did not start within 10 s")
}
