//! `TestWorld` — orchestrates processes for a single beacon scenario.
//!
//! Each `TestWorld` owns:
//! - A **Postern** in-process PDS.
//! - A **Toxiproxy** subprocess with one named proxy per service.
//! - One **`moat-cli --http`** subprocess per participant, each connected to
//!   Postern through the `proxy-pds` Toxiproxy proxy.
//! - A typed [`MoatCliClient`] for each participant.
//! - Optionally one or more **Drawbridge** relay instances.
//!
//! ## Relay topology
//!
//! [`TestWorld::new_with_drawbridge`] takes `(handle, relay_label)` tuples.
//! Participants with the same label share a Drawbridge relay; distinct labels
//! spawn separate relays.  This lets callers express any topology — shared
//! relay, per-participant relays, or mixed — with a single constructor.
//!
//! Everything is cleaned up when `TestWorld` is dropped.


use crate::client::MoatCliClient;
use crate::config::WorldConfig;
use crate::drawbridge::DrawbridgeProcess;
use crate::pgroup::{install_signal_handlers, ProcessGroup};
use crate::toxiproxy::{ProxyHandle, ToxiproxyManager};
use anyhow::{Context, Result};
use moat_postern::{AccountConfig, PosternConfig, PosternHandle};
use std::{
    collections::HashMap,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    fs::File,
};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use tempfile::TempDir;

/// Which implementation a participant runs.
#[derive(Clone, Debug, PartialEq)]
pub enum ParticipantKind {
    /// Rust CLI (`moat-cli --http`)
    RustCli,
    /// Dart headless server (`moat_dart_server --http`)
    DartServer,
}

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
    /// Which binary to use when restarting.
    kind: ParticipantKind,
    pub client: MoatCliClient,
    /// Path to the stderr log file for this participant (under /tmp).
    pub log_path: PathBuf,
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
    /// Owns the OS process group for all children.  Dropped first (declared
    /// first) so `killpg` runs before the individual child Drop impls try to
    /// `kill()` + `wait()` — the individual waits then collect the zombies.
    process_group: ProcessGroup,
    _postern: PosternHandle,
    /// Toxiproxy subprocess — kept alive so proxies remain functional.
    pub toxiproxy: ToxiproxyManager,
    /// The `proxy-pds` proxy: all participants' PDS traffic passes through it.
    pub pds_proxy: ProxyHandle,
    /// Direct Postern URL (useful for out-of-band inspection).
    postern_url: String,
    /// Drawbridge relay instances. Dropped on `TestWorld` drop, which kills the
    /// child processes. Exposed publicly so tests can call push-log methods on
    /// recording-mode relays.
    pub drawbridges: Vec<DrawbridgeProcess>,
    /// `proxy-db-verify` proxy: routes Drawbridge's PDS verification calls through
    /// Toxiproxy so tests can inject faults on the Drawbridge → Postern path.
    /// Only present when Drawbridge is enabled.
    pub db_verify_proxy: Option<ProxyHandle>,
    participants: HashMap<String, ParticipantProcess>,
    /// Path to the `moat` CLI binary; reused when restarting participants.
    moat_cli_bin: PathBuf,
    /// Path to the compiled Dart server binary; reused when restarting participants.
    dart_server_bin: Option<PathBuf>,
    /// Path to the Rust FFI dylib (`librust_lib_moat_flutter.dylib`); injected
    /// as `--lib-path` when spawning Dart participants.
    rust_lib_path: Option<PathBuf>,
}

impl TestWorld {
    /// Build a new `TestWorld` with the given participant handles (no Drawbridge).
    ///
    /// All participants run the Rust CLI (`moat-cli --http`).
    ///
    /// `handle_suffix` is appended to every handle, e.g. `".postern.test"`.
    pub async fn new(handles: &[&str], handle_suffix: &str) -> Result<Self> {
        let participants: Vec<_> = handles.iter().map(|h| (*h, None)).collect();
        let kinds = vec![ParticipantKind::RustCli; handles.len()];
        Self::build(&participants, &kinds, handle_suffix, false).await
    }

    /// Build a `TestWorld` with Drawbridge relay(s).
    ///
    /// Each tuple is `(handle, relay_label)`.  Participants with the same
    /// label share a single Drawbridge relay; distinct labels spawn separate
    /// relay instances.
    ///
    /// All participants run the Rust CLI (`moat-cli --http`).
    pub async fn new_with_drawbridge(
        participants: &[(&str, &str)],
        handle_suffix: &str,
    ) -> Result<Self> {
        let with_labels: Vec<_> = participants
            .iter()
            .map(|(h, label)| (*h, Some(*label)))
            .collect();
        let kinds = vec![ParticipantKind::RustCli; participants.len()];
        Self::build(&with_labels, &kinds, handle_suffix, false).await
    }

    /// Build a `TestWorld` from a [`WorldConfig`].
    ///
    /// Each distinct `relay_label` in the config spawns one Drawbridge relay;
    /// participants sharing a label share a relay.  `push_mode` is derived
    /// from whether any participant has a relay label.
    pub async fn from_config(config: &WorldConfig, handle_suffix: &str) -> Result<Self> {
        let participants: Vec<(&str, Option<&str>)> = config
            .participants
            .iter()
            .map(|p| (p.handle, p.relay_label))
            .collect();
        let kinds: Vec<ParticipantKind> = config.participants.iter().map(|p| p.kind.clone()).collect();
        Self::build(&participants, &kinds, handle_suffix, false).await
    }

    /// Build a `TestWorld` where each participant can be a different implementation.
    ///
    /// `kinds` must have the same length as `handles`.  Use
    /// [`ParticipantKind::DartServer`] to run the headless Dart server instead
    /// of moat-cli for a given participant.
    pub async fn new_with_kinds(
        handles: &[&str],
        kinds: &[ParticipantKind],
        handle_suffix: &str,
    ) -> Result<Self> {
        let participants: Vec<_> = handles.iter().map(|h| (*h, None)).collect();
        Self::build(&participants, kinds, handle_suffix, false).await
    }

    /// Like [`new_with_drawbridge`] but each participant can be a different
    /// implementation.
    ///
    /// Each tuple is `(handle, relay_label)`.  `kinds` must have the same
    /// length.  Use [`ParticipantKind::DartServer`] to run the Dart headless
    /// server for a given participant.
    pub async fn new_with_kinds_and_drawbridge(
        participants: &[(&str, &str)],
        kinds: &[ParticipantKind],
        handle_suffix: &str,
    ) -> Result<Self> {
        let with_labels: Vec<_> = participants
            .iter()
            .map(|(h, label)| (*h, Some(*label)))
            .collect();
        Self::build(&with_labels, kinds, handle_suffix, false).await
    }

    /// Like [`new_with_drawbridge`] but spawns Drawbridge relay(s) in FCM
    /// recording mode (`FCM_SENDER=recording`). Use [`push_log`] and
    /// [`reset_push_log`] to assert on FCM dispatch in tests.
    ///
    /// All participants run the Rust CLI (`moat-cli --http`).
    pub async fn new_with_drawbridge_recording_fcm(
        participants: &[(&str, &str)],
        handle_suffix: &str,
    ) -> Result<Self> {
        let with_labels: Vec<_> = participants
            .iter()
            .map(|(h, label)| (*h, Some(*label)))
            .collect();
        let kinds = vec![ParticipantKind::RustCli; participants.len()];
        Self::build(&with_labels, &kinds, handle_suffix, true).await
    }

    /// Fetch all FCM pushes recorded by the first Drawbridge relay since the
    /// last reset. Panics if the world was not created with
    /// [`new_with_drawbridge_recording_fcm`].
    pub async fn push_log(&self) -> Vec<crate::drawbridge::RecordedPush> {
        self.drawbridges
            .first()
            .expect("no drawbridge in this TestWorld")
            .fetch_push_log()
            .await
            .expect("fetch_push_log failed")
    }

    /// Clear the FCM push log on the first Drawbridge relay. Panics if the
    /// world was not created with [`new_with_drawbridge_recording_fcm`].
    pub async fn reset_push_log(&self) {
        self.drawbridges
            .first()
            .expect("no drawbridge in this TestWorld")
            .reset_push_log()
            .await
            .expect("reset_push_log failed");
    }

    /// Poll the first Drawbridge relay's `/health` endpoint until the live
    /// connection count equals `n`, then return. Useful for waiting until a
    /// killed participant's socket has been detected as closed before starting
    /// a grace-window timer. Times out after `timeout` and panics.
    pub async fn wait_for_drawbridge_connections(&self, n: usize, timeout: std::time::Duration) {
        let db = self.drawbridges.first().expect("no drawbridge in this TestWorld");
        let url = format!("{}/health", db.http_url);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(resp) = reqwest::get(&url).await {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if body["connections"].as_u64().map(|c| c as usize) == Some(n) {
                        return;
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                panic!("Drawbridge connection count did not reach {n} within {timeout:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn build(
        participants: &[(&str, Option<&str>)],
        kinds: &[ParticipantKind],
        handle_suffix: &str,
        recording_fcm: bool,
    ) -> Result<Self> {
        assert_eq!(
            participants.len(),
            kinds.len(),
            "participants and kinds must have equal length"
        );

        let handles: Vec<&str> = participants.iter().map(|(h, _)| *h).collect();

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
        // Toxiproxy is spawned with process_group(0), making it the leader of
        // a new process group.  All subsequent children join the same group so
        // that ProcessGroup::drop (and the signal handler) can kill them all
        // with a single killpg().
        let toxiproxy = ToxiproxyManager::spawn()
            .await
            .context("spawn toxiproxy")?;
        let pgid = toxiproxy.pgid;
        let process_group = ProcessGroup::new(pgid);
        install_signal_handlers();

        let postern_addr = postern_url
            .strip_prefix("http://")
            .unwrap_or(&postern_url)
            .to_string();
        let pds_proxy = toxiproxy
            .create_proxy("proxy-pds", &postern_addr)
            .await
            .context("create proxy-pds")?;

        // Collect relay labels and deduplicate to determine which Drawbridge
        // instances to spawn.
        let has_drawbridge = participants.iter().any(|(_, label)| label.is_some());

        let (drawbridges, db_verify_proxy, drawbridge_ws_endpoints) = if has_drawbridge {
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

            // Deduplicate relay labels: spawn one Drawbridge per unique label.
            let mut unique_labels: Vec<&str> = Vec::new();
            for (_, label) in participants {
                if let Some(l) = label {
                    if !unique_labels.contains(l) {
                        unique_labels.push(l);
                    }
                }
            }

            let mut dbs = Vec::with_capacity(unique_labels.len());
            let mut label_to_ws: HashMap<&str, String> = HashMap::new();
            for label in &unique_labels {
                let db = if recording_fcm {
                    DrawbridgeProcess::spawn_with_recording_fcm(&db_verify.url, pgid).await
                } else {
                    DrawbridgeProcess::spawn(&db_verify.url, pgid).await
                }
                .with_context(|| format!("spawn drawbridge for relay {label}"))?;
                label_to_ws.insert(label, db.ws_endpoint());
                dbs.push(db);
            }

            // Map each participant to its relay's WS endpoint.
            let endpoints: Vec<Option<String>> = participants
                .iter()
                .map(|(_, label)| label.map(|l| label_to_ws[l].clone()))
                .collect();

            // Advertise the first relay URL via Postern's describeServer so all
            // participants can discover it after login without a CLI flag.
            if let Some(url) = label_to_ws.values().next() {
                postern.set_drawbridge_url(url);
            }

            (dbs, Some(db_verify), endpoints)
        } else {
            let endpoints: Vec<Option<String>> = participants.iter().map(|_| None).collect();
            (vec![], None, endpoints)
        };

        // Resolve the moat binary once for the whole world (also triggers
        // auto-build if needed).
        let moat_cli_bin = moat_cli_binary()?;

        // If any participant is a Dart server, build the Dart binary + FFI lib.
        let (dart_server_bin, dart_lib_path) =
            if kinds.contains(&ParticipantKind::DartServer) {
                let (dart_bin, lib) = dart_server_binary()?;
                (Some(dart_bin), Some(lib))
            } else {
                (None, None)
            };

        // Intermediate holder for a spawned-but-not-yet-ready participant.
        struct PendingParticipant {
            short_handle: String,
            child: Child,
            client: MoatCliClient,
            storage: TempDir,
            spawn_args: Vec<String>,
            kind: ParticipantKind,
            log_path: PathBuf,
        }

        // Phase 1: spawn all participant processes (fast — no waiting).
        let mut pending: Vec<PendingParticipant> = Vec::with_capacity(handles.len());
        for (i, (&handle, kind)) in handles.iter().zip(kinds.iter()).enumerate() {
            let full_handle = format!("{handle}{handle_suffix}");
            let drawbridge_ws = drawbridge_ws_endpoints[i].as_deref();

            let http_port = free_port()?;
            let http_addr = format!("127.0.0.1:{http_port}");
            let storage = make_storage_dir(handle)?;

            let mut args = vec![
                "--storage-dir".to_string(),
                storage.path().to_str().unwrap().to_string(),
                "--pds-url".to_string(),
                pds_proxy.url.clone(),
                "--http".to_string(),
                http_addr.clone(),
            ];
            let _ = drawbridge_ws; // URL is discovered via describeServer; no CLI flag needed
            if *kind == ParticipantKind::DartServer {
                if let Some(ref lib) = dart_lib_path {
                    args.push("--lib-path".to_string());
                    args.push(lib.to_str().unwrap().to_string());
                }
            }

            let bin = match kind {
                ParticipantKind::RustCli => moat_cli_bin.clone(),
                ParticipantKind::DartServer => {
                    dart_server_bin.clone().expect("dart_server_bin not set")
                }
            };

            let (log_file, log_path) = open_participant_log(handle)?;
            eprintln!(
                "[beacon] storage[{handle}]: {}",
                storage.path().display()
            );

            let mut cmd = Command::new(&bin);
            cmd.args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::from(log_file));
            #[cfg(unix)]
            cmd.process_group(pgid as i32);
            let child = cmd
                .spawn()
                .with_context(|| format!("spawn participant ({kind:?}) for {full_handle}"))?;

            let client = MoatCliClient::new(format!("http://{http_addr}"));

            pending.push(PendingParticipant {
                short_handle: handle.to_string(),
                child,
                client,
                storage,
                spawn_args: args,
                kind: kind.clone(),
                log_path,
            });
        }

        // Phase 2: wait for all HTTP servers to come up concurrently.
        {
            let mut join_set: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();
            for p in &pending {
                let client = p.client.clone();
                let short = p.short_handle.clone();
                join_set.spawn(async move {
                    wait_for_http(&client, std::time::Duration::from_secs(10))
                        .await
                        .with_context(|| format!("waiting for participant ({short}) to start"))
                });
            }
            while let Some(res) = join_set.join_next().await {
                res??;
            }
        }

        let mut world = Self {
            process_group,
            _postern: postern,
            toxiproxy,
            pds_proxy: pds_proxy.clone(),
            postern_url,
            drawbridges,
            db_verify_proxy,
            participants: HashMap::new(),
            moat_cli_bin,
            dart_server_bin,
            rust_lib_path: dart_lib_path,
        };

        for p in pending {
            world.participants.insert(
                p.short_handle,
                ParticipantProcess {
                    child: Some(p.child),
                    storage: p.storage,
                    spawn_args: p.spawn_args,
                    kind: p.kind,
                    client: p.client,
                    log_path: p.log_path,
                },
            );
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

        let bin = match proc.kind {
            ParticipantKind::RustCli => self.moat_cli_bin.clone(),
            ParticipantKind::DartServer => self
                .dart_server_bin
                .clone()
                .expect("dart_server_bin not set"),
        };

        let pgid = self.process_group.pgid();
        let (log_file, log_path) = open_participant_log(&format!("{handle}-restart"))?;
        let mut cmd = Command::new(&bin);
        cmd.args(&proc.spawn_args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file));
        #[cfg(unix)]
        cmd.process_group(pgid as i32);
        let child = cmd
            .spawn()
            .with_context(|| format!("restart participant for {handle}"))?;
        proc.child = Some(child);
        proc.log_path = log_path;

        wait_for_http(&proc.client, std::time::Duration::from_secs(10))
            .await
            .with_context(|| format!("waiting for participant ({handle}) to restart"))?;
        Ok(())
    }

    /// Spawn an additional process for an existing Postern account.
    ///
    /// Use this to simulate any additional device (second, third, …) for an
    /// existing user.  The new process connects to the same PDS proxy but uses a
    /// fresh storage directory, giving it a distinct `device_id`.  The caller
    /// must log in using the same handle/password as the first device.
    ///
    /// Pass `kind` to choose between [`ParticipantKind::RustCli`] and
    /// [`ParticipantKind::DartServer`].  If `kind` is `DartServer` and the Dart
    /// binary has not been built yet, it is compiled on demand.
    ///
    /// The new participant is registered under `label` in this world.
    pub async fn spawn_nth_device(
        &mut self,
        label: &str,
        kind: ParticipantKind,
    ) -> Result<MoatCliClient> {
        let http_port = free_port()?;
        let http_addr = format!("127.0.0.1:{http_port}");
        let storage = make_storage_dir(label)?;

        let mut args = vec![
            "--storage-dir".to_string(),
            storage.path().to_str().unwrap().to_string(),
            "--pds-url".to_string(),
            self.pds_proxy.url.clone(),
            "--http".to_string(),
            http_addr.clone(),
        ];

        let bin = match kind {
            ParticipantKind::RustCli => self.moat_cli_bin.clone(),
            ParticipantKind::DartServer => {
                // Build Dart binary + FFI lib on demand if not already available.
                if self.dart_server_bin.is_none() {
                    let (dart_bin, lib) = dart_server_binary()?;
                    self.dart_server_bin = Some(dart_bin);
                    self.rust_lib_path = Some(lib);
                }
                let dart_bin = self
                    .dart_server_bin
                    .clone()
                    .expect("dart_server_bin not set after build");
                let lib_path = self
                    .rust_lib_path
                    .as_ref()
                    .expect("rust_lib_path not set after build");
                args.push("--lib-path".to_string());
                args.push(lib_path.to_str().unwrap().to_string());
                dart_bin
            }
        };

        let pgid = self.process_group.pgid();
        let (log_file, log_path) = open_participant_log(label)?;
        eprintln!(
            "[beacon] storage[{label}]: {}",
            storage.path().display()
        );
        let mut cmd = Command::new(&bin);
        cmd.args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file));
        #[cfg(unix)]
        cmd.process_group(pgid as i32);
        let child = cmd
            .spawn()
            .with_context(|| format!("spawn second device ({kind:?}) for {label}"))?;

        let client = MoatCliClient::new(format!("http://{http_addr}"));
        wait_for_http(&client, std::time::Duration::from_secs(10))
            .await
            .with_context(|| format!("waiting for second device ({label}) to start"))?;

        self.participants.insert(
            label.to_string(),
            ParticipantProcess {
                child: Some(child),
                storage,
                spawn_args: args,
                kind,
                client: client.clone(),
                log_path,
            },
        );

        Ok(client)
    }

    /// Returns `true` if the participant process is currently running.
    pub fn participant_is_online(&self, handle: &str) -> bool {
        self.participants
            .get(handle)
            .map(|p| p.child.is_some())
            .unwrap_or(false)
    }

}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Open a stderr log file for a participant under `/tmp/moat-beacon/`.
///
/// Path: `/tmp/moat-beacon/<label>-<timestamp_ms>.log`
///
/// Prints the path to stderr so test output shows where to find it.
fn open_participant_log(label: &str) -> Result<(File, PathBuf)> {
    let dir = PathBuf::from("/tmp/moat-beacon");
    std::fs::create_dir_all(&dir).context("create /tmp/moat-beacon")?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = dir.join(format!("{label}-{ts}.log"));
    let file = File::create(&path)
        .with_context(|| format!("create log file {}", path.display()))?;
    eprintln!("[beacon] log: {}", path.display());
    Ok((file, path))
}

/// Create a per-participant storage directory under `/tmp/moat-beacon-data/`.
///
/// Storage is intentionally not cleaned up on drop so that `debug.log` is
/// available for inspection after a test exits. Clear `/tmp/moat-beacon-data/`
/// by hand when the accumulation matters; CI runs on fresh machines.
fn make_storage_dir(label: &str) -> Result<TempDir> {
    let base = std::path::Path::new("/tmp/moat-beacon-data");
    std::fs::create_dir_all(base).context("create /tmp/moat-beacon-data")?;
    tempfile::Builder::new()
        .prefix(&format!("moat-beacon-{label}-"))
        .disable_cleanup(true)
        .tempdir_in(base)
        .context("create persistent storage dir")
}

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

/// Returns `true` if any `.dart` file under `dir` has a modification time
/// strictly newer than `since`.  Directories named `.dart_tool`, `build`, or
/// `.git` are skipped to keep the walk fast.
fn dart_source_is_newer(dir: &std::path::Path, since: std::time::SystemTime) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == ".dart_tool" || name_str == "build" || name_str == ".git" {
            continue;
        }
        if path.is_dir() {
            if dart_source_is_newer(&path, since) {
                return true;
            }
        } else if path.extension().is_some_and(|e| e == "dart") {
            let mtime = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            if mtime > since {
                return true;
            }
        }
    }
    false
}

/// Path to the compiled `moat_dart_server` binary and Rust FFI dylib.
///
/// Builds the Rust FFI lib (`rust_lib_moat_flutter`) and compiles the Dart
/// server binary if either is missing.  Returns `(dart_binary, lib_path)`.
fn dart_server_binary() -> Result<(PathBuf, PathBuf)> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set — run via cargo test")?;

    let workspace_root = PathBuf::from(&manifest_dir)
        .parent()
        .context("manifest_dir has no parent")?
        .to_path_buf();

    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };

    // ── 1. Build the Rust FFI dylib ───────────────────────────────────────────
    let rust_crate_dir = workspace_root.join("moat-dart").join("app").join("rust");
    let lib_name = format!(
        "{}rust_lib_moat_flutter.{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_EXTENSION
    );
    let lib_path = rust_crate_dir.join("target").join(profile).join(&lib_name);

    if !lib_path.exists() {
        eprintln!("beacon: rust_lib_moat_flutter not found, building…");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let mut cmd = Command::new(&cargo);
        cmd.arg("build")
            .arg("--manifest-path")
            .arg(rust_crate_dir.join("Cargo.toml"));
        if !cfg!(debug_assertions) {
            cmd.arg("--release");
        }
        let status = cmd
            .current_dir(&workspace_root)
            .status()
            .context("running cargo build rust_lib_moat_flutter")?;
        if !status.success() {
            anyhow::bail!("cargo build rust_lib_moat_flutter failed");
        }
        if !lib_path.exists() {
            anyhow::bail!(
                "rust_lib_moat_flutter still not found at {} after build",
                lib_path.display()
            );
        }
    }

    // ── 2. Compile the Dart server binary ─────────────────────────────────────
    let dart_bin_dir = workspace_root.join("target").join("moat-dart-server");
    std::fs::create_dir_all(&dart_bin_dir).context("create moat-dart-server output dir")?;
    let dart_bin = dart_bin_dir.join("moat_dart_server");

    let dart_needs_rebuild = !dart_bin.exists() || {
        let bin_mtime = std::fs::metadata(&dart_bin)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        // Rebuild if any .dart file in moat-dart/ is newer than the binary.
        let dart_src_dir = workspace_root.join("moat-dart");
        dart_source_is_newer(&dart_src_dir, bin_mtime)
    };

    if dart_needs_rebuild {
        eprintln!("beacon: moat_dart_server missing or stale, compiling…");
        let dart_source = workspace_root
            .join("moat-dart")
            .join("server")
            .join("bin")
            .join("moat_dart_server.dart");
        let status = Command::new("dart")
            .args(["compile", "exe"])
            .arg(&dart_source)
            .arg("-o")
            .arg(&dart_bin)
            .current_dir(&workspace_root)
            .status()
            .context("running dart compile exe moat_dart_server")?;
        if !status.success() {
            anyhow::bail!("dart compile exe moat_dart_server failed");
        }
        if !dart_bin.exists() {
            anyhow::bail!(
                "moat_dart_server still not found at {} after compile",
                dart_bin.display()
            );
        }
    }

    Ok((dart_bin, lib_path))
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
