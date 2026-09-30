//! Process-group registry and signal handler setup.
//!
//! Every `TestWorld` puts all its child processes in a dedicated OS process
//! group so they can be cleaned up as a unit.  [`ProcessGroup`] registers the
//! group ID globally; a background signal handler kills every registered group
//! when the test binary receives SIGINT or SIGTERM.
//!
//! ## Why this is needed
//!
//! Rust's `Drop` runs on normal exit and on panics (stack unwind), which
//! covers successful tests and test failures.  But when the test binary is
//! killed by a signal — Ctrl+C, `cargo test` timeout, OOM killer — the
//! default signal disposition terminates the process immediately without
//! unwinding.  Child processes (moat-cli, Toxiproxy, Drawbridge) then become
//! orphans and keep running until the machine reboots.
//!
//! The signal handler here intercepts SIGINT and SIGTERM, kills all registered
//! groups, then re-raises with the default handler so the process exits
//! normally.  (SIGKILL cannot be caught and still orphans children, but that
//! case is rare in practice.)

use std::sync::{Mutex, OnceLock};

// ── Global registry ───────────────────────────────────────────────────────────

static REGISTRY: OnceLock<Mutex<Vec<i32>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<i32>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn kill_pgid(pgid: i32) {
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

fn kill_all_registered() {
    if let Ok(pgids) = registry().lock() {
        for &pgid in pgids.iter() {
            kill_pgid(pgid);
        }
    }
}

// ── ProcessGroup ─────────────────────────────────────────────────────────────

/// Guard for a Unix process group.
///
/// Registers the group in the global registry on creation so the signal
/// handler can kill it if the test binary is interrupted.  On drop, sends
/// `SIGKILL` to the entire group and deregisters.
///
/// Create one per `TestWorld` using the PID of the first child spawned with
/// `Command::process_group(0)` (that child's PID becomes the PGID).  Pass
/// `guard.pgid()` to every subsequent `Command::process_group(pgid)` call so
/// all children join the same group.
pub struct ProcessGroup {
    pgid: i32,
}

impl ProcessGroup {
    pub fn new(pgid: u32) -> Self {
        let pgid = pgid as i32;
        registry().lock().unwrap().push(pgid);
        Self { pgid }
    }

    /// The OS process group ID; pass to `Command::process_group(pgid)`.
    pub fn pgid(&self) -> u32 {
        self.pgid as u32
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        kill_pgid(self.pgid);
        if let Ok(mut guard) = registry().lock() {
            guard.retain(|&p| p != self.pgid);
        }
    }
}

// ── Orphan reaping ───────────────────────────────────────────────────────────

/// Kill leftover beacon child processes that have been reparented to init.
///
/// Closes the one hole [`ProcessGroup`] and the signal handler cannot: if the
/// *test binary* dies without unwinding — SIGKILL, or a `pkill` that matches
/// `cargo` rather than the test binary it spawned — its children keep running.
/// They are not merely untidy: they hold their storage roots and ports, burn
/// CPU alongside later runs, and show up in `beacon triage` as devices stuck
/// mid-bootstrap, which is indistinguishable from a real stall until you
/// notice the process is still alive. That has already cost one
/// misattributed diagnosis.
///
/// Only processes whose parent is init (PPID 1) are killed. A concurrently
/// running test's children have a live parent, so this cannot disturb them —
/// which matters because beacon tests run in parallel within a binary and
/// several `cargo test` invocations may overlap.
pub fn reap_orphaned_children() {
    static REAP: std::sync::Once = std::sync::Once::new();
    REAP.call_once(|| {
        let Ok(out) = std::process::Command::new("ps")
            .args(["-A", "-o", "pid=,ppid=,command="])
            .output()
        else {
            return;
        };
        let listing = String::from_utf8_lossy(&out.stdout);

        let mut reaped = 0usize;
        for line in listing.lines() {
            let mut parts = line.split_whitespace();
            let (Some(pid), Some(ppid)) = (parts.next(), parts.next()) else {
                continue;
            };
            if ppid != "1" {
                continue; // still owned by a live test
            }
            let cmd = parts.collect::<Vec<_>>().join(" ");
            let ours = cmd.contains("/tmp/moat-beacon-data/")
                || cmd.contains("moat-beacon/toxiproxy")
                || cmd.contains("target/moat-drawbridge/drawbridge")
                || cmd.contains("target/moat-dart-server/moat_dart_server");
            if !ours {
                continue;
            }
            if let Ok(pid) = pid.parse::<i32>() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                reaped += 1;
            }
        }
        if reaped > 0 {
            eprintln!("[beacon] reaped {reaped} orphaned child process(es) from a previous run");
        }
    });
}

// ── Signal handler ────────────────────────────────────────────────────────────

/// Install SIGINT + SIGTERM handlers (idempotent — safe to call repeatedly).
///
/// A background thread waits for either signal, kills every registered process
/// group, then re-raises with the default handler so the test binary exits
/// with the expected signal status.
pub fn install_signal_handlers() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let mut signals =
            signal_hook::iterator::Signals::new([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM])
                .expect("install beacon signal handlers");

        std::thread::Builder::new()
            .name("beacon-signal-handler".into())
            .spawn(move || {
                for sig in signals.forever() {
                    kill_all_registered();
                    // Restore the default disposition and re-raise so the
                    // process exits with the correct signal status.
                    unsafe {
                        libc::signal(sig, libc::SIG_DFL);
                        libc::raise(sig);
                    }
                }
            })
            .expect("spawn beacon signal handler thread");
    });
}
