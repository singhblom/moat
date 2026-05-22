//! `DrawbridgeProcess` — build and spawn the Drawbridge Go relay binary.
//!
//! [`DrawbridgeProcess`] builds the `moat-drawbridge` Go binary on first use
//! (skipped if the binary is already newer than all `*.go` sources), spawns it
//! on a random free port, and waits for `GET /health` to return 200 before
//! returning.  The process is killed when the value is dropped.
//!
//! Environment variables passed to the subprocess:
//! - `RELAY_TLS=false`
//! - `RELAY_ADDR=:PORT`
//! - `RELAY_PUBLIC_URL=ws://127.0.0.1:PORT`
//! - `LOG_FORMAT=text`
//! - `PLC_BASE_URL=<url>` (set via [`DrawbridgeProcess::set_plc_base_url`])

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

/// A single FCM push captured by a recording-mode Drawbridge relay.
/// Returned by [`DrawbridgeProcess::fetch_push_log`].
#[derive(Debug, Deserialize)]
pub struct RecordedPush {
    pub token: String,
    pub tag: String,
    pub rkey: String,
    pub payload: String,
}

/// A running Drawbridge WebSocket relay process.
///
/// Killed automatically on drop.
pub struct DrawbridgeProcess {
    child: Child,
    /// WebSocket base URL, e.g. `"ws://127.0.0.1:PORT"`.
    /// Append `/ws` to get the full WebSocket endpoint.
    pub ws_url: String,
    /// HTTP base URL for the health endpoint, e.g. `"http://127.0.0.1:PORT"`.
    pub http_url: String,
}

impl DrawbridgeProcess {
    /// Build (if needed) and spawn the Drawbridge binary.
    ///
    /// `plc_base_url` is passed as `PLC_BASE_URL` to the subprocess.
    /// Set it to the `proxy-db-verify` Toxiproxy URL so Drawbridge's DID
    /// resolution and PDS verification calls route through the proxy.
    ///
    /// `pgid` is the process group ID to join (from [`ToxiproxyManager::pgid`]).
    pub async fn spawn(plc_base_url: &str, pgid: u32) -> Result<Self> {
        Self::spawn_with_env(plc_base_url, pgid, &[]).await
    }

    /// Spawn a Drawbridge relay with `FCM_SENDER=recording` set.
    ///
    /// The relay will capture every FCM send in memory and expose it via
    /// `GET /test/push-log`.  Use [`fetch_push_log`] and [`reset_push_log`]
    /// from tests to assert FCM dispatch behaviour.
    pub async fn spawn_with_recording_fcm(plc_base_url: &str, pgid: u32) -> Result<Self> {
        Self::spawn_with_env(plc_base_url, pgid, &[("FCM_SENDER", "recording")]).await
    }

    async fn spawn_with_env(
        plc_base_url: &str,
        pgid: u32,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let bin = drawbridge_binary().context("obtain drawbridge binary")?;
        let port = free_port().context("allocate drawbridge port")?;

        let mut cmd = Command::new(&bin);
        cmd.env("RELAY_TLS", "false")
            .env("RELAY_ADDR", format!(":{port}"))
            .env("RELAY_PUBLIC_URL", format!("ws://127.0.0.1:{port}"))
            .env("LOG_FORMAT", "text")
            .env("PLC_BASE_URL", plc_base_url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        #[cfg(unix)]
        cmd.process_group(pgid as i32);
        let child = cmd.spawn().context("spawn drawbridge process")?;

        let http_url = format!("http://127.0.0.1:{port}");
        let ws_url = format!("ws://127.0.0.1:{port}");

        let proc = Self {
            child,
            ws_url,
            http_url: http_url.clone(),
        };

        wait_for_health(&http_url, Duration::from_secs(10))
            .await
            .context("waiting for drawbridge /health")?;

        Ok(proc)
    }

    /// Full WebSocket endpoint URL, e.g. `"ws://127.0.0.1:PORT/ws"`.
    pub fn ws_endpoint(&self) -> String {
        format!("{}/ws", self.ws_url)
    }

    /// Fetch all FCM pushes recorded since the last reset.
    /// Only works when the relay was started with `spawn_with_recording_fcm`.
    pub async fn fetch_push_log(&self) -> Result<Vec<RecordedPush>> {
        let client = Client::new();
        let url = format!("{}/test/push-log", self.http_url);
        client
            .get(&url)
            .send()
            .await
            .context("GET /test/push-log")?
            .json()
            .await
            .context("parse push log")
    }

    /// Clear all recorded FCM pushes on the relay.
    /// Only works when the relay was started with `spawn_with_recording_fcm`.
    pub async fn reset_push_log(&self) -> Result<()> {
        let client = Client::new();
        let url = format!("{}/test/push-log/reset", self.http_url);
        let resp = client
            .post(&url)
            .send()
            .await
            .context("POST /test/push-log/reset")?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("reset_push_log failed: {status}");
        }
        Ok(())
    }
}

impl Drop for DrawbridgeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Binary management ─────────────────────────────────────────────────────────

/// Return the path to the compiled drawbridge binary, building it if necessary.
///
/// Skips the build if the binary exists and is newer than all `*.go` source
/// files in `moat-drawbridge/`.
fn drawbridge_binary() -> Result<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set — run via cargo test")?;

    // moat-beacon is at <workspace>/moat-beacon/, workspace root is one level up.
    let workspace_root = PathBuf::from(&manifest_dir)
        .parent()
        .context("manifest_dir has no parent")?
        .to_path_buf();

    let src_dir = workspace_root.join("moat-drawbridge");
    anyhow::ensure!(
        src_dir.exists(),
        "moat-drawbridge source directory not found at {}",
        src_dir.display()
    );

    let bin_dir = workspace_root.join("target").join("moat-drawbridge");
    std::fs::create_dir_all(&bin_dir).context("create target/moat-drawbridge/")?;
    let bin = bin_dir.join("drawbridge");

    if needs_rebuild(&bin, &src_dir) {
        build_drawbridge(&src_dir, &bin)?;
    }

    Ok(bin)
}

/// Returns `true` if the binary is missing or older than any `*.go` source.
fn needs_rebuild(bin: &PathBuf, src_dir: &PathBuf) -> bool {
    let bin_mtime = match std::fs::metadata(bin).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return true, // binary missing
    };

    // Walk src_dir for *.go files.
    let go_files = match std::fs::read_dir(src_dir) {
        Ok(d) => d,
        Err(_) => return true,
    };

    for entry in go_files.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("go") {
            if let Ok(mtime) = std::fs::metadata(&path).and_then(|m| m.modified()) {
                if mtime > bin_mtime {
                    return true;
                }
            }
        }
    }
    false
}

fn build_drawbridge(src_dir: &Path, bin: &Path) -> Result<()> {
    eprintln!("beacon: building drawbridge…");

    // Verify Go is available.
    let go = which_go().context(
        "go not found in PATH — install Go to run Drawbridge integration tests",
    )?;

    let status = Command::new(&go)
        .args([
            "build",
            "-o",
            bin.to_str().unwrap(),
            "./...",
        ])
        .current_dir(src_dir)
        .status()
        .context("running go build")?;

    if !status.success() {
        anyhow::bail!("go build failed in {}", src_dir.display());
    }

    eprintln!("beacon: drawbridge built at {}", bin.display());
    Ok(())
}

fn which_go() -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("go");
        if candidate.exists() {
            return Some(candidate);
        }
        // Windows
        let candidate_exe = dir.join("go.exe");
        if candidate_exe.exists() {
            return Some(candidate_exe);
        }
    }
    None
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

/// Poll `GET /health` until it returns 200 or the timeout elapses.
async fn wait_for_health(http_url: &str, timeout: Duration) -> Result<()> {
    let client = Client::new();
    let url = format!("{http_url}/health");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::bail!("drawbridge /health at {url} did not return 200 within {timeout:?}")
}
