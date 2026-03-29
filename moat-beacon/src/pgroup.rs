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
