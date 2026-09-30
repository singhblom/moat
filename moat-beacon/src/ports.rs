//! Ephemeral port reservation for the processes a test world spawns.
//!
//! The obvious way to find a free port is to bind `127.0.0.1:0`, read the
//! port the OS chose, and drop the listener. Every component here used to
//! do exactly that, in three separate copies. It has two failure modes,
//! and the first is the common one:
//!
//! 1. **We collide with ourselves.** Dropping the listener returns the
//!    port to the pool *immediately*, so the very next call in the same
//!    process can be handed the same number back. A `TestWorld` allocates
//!    a Postern port, a Drawbridge port, a Toxiproxy management port, one
//!    proxy listen port per link and one HTTP port per participant — a
//!    dozen calls in quick succession, each of which can collide with a
//!    port a sibling component is about to bind but has not bound yet.
//! 2. **Something else on the machine takes it.** Rarer, and not fixable
//!    from here: only the caller, which owns the spawn, could retry.
//!
//! This module fixes (1) and narrows (2). A [`ReservedPort`] keeps the
//! listener *open*, so the OS cannot hand the same port to another
//! reservation, and the caller releases it at the last possible moment —
//! immediately before spawning the child that binds it. A process-wide
//! set of already-issued ports covers the gap after release, so a number
//! is never handed out twice even once its listener is gone.
//!
//! This was not theoretical. Running beacon's proptests with
//! `BEACON_PARALLEL=4` reproduced it as Toxiproxy failing to start a
//! proxy with `listen tcp 127.0.0.1:57013: bind: address already in use`.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};

/// Ports this process has already handed out, so one is never issued
/// twice — including after its listener has been released and the OS
/// considers it free again.
fn issued() -> &'static Mutex<HashSet<u16>> {
    static ISSUED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    ISSUED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// How many times to ask the OS for a port before giving up. Only a
/// collision with an already-issued port costs an attempt, so exhausting
/// this many means something is badly wrong rather than unlucky.
const MAX_ATTEMPTS: usize = 50;

/// A port held open on this process's behalf until the child that will
/// bind it is ready to start.
///
/// Holding the listener is what stops a second reservation being handed
/// the same number. It also means the port is *unavailable* to the child
/// until [`release`](Self::release) is called — so call it immediately
/// before spawning, and not earlier.
#[derive(Debug)]
pub struct ReservedPort {
    port: u16,
    /// `None` once released. The port stays recorded in [`issued`], so it
    /// is still never re-issued.
    listener: Option<TcpListener>,
}

impl ReservedPort {
    /// The reserved port number. Valid before and after release.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Give the port up so a child process can bind it.
    ///
    /// Call this immediately before spawning that child: everything
    /// between here and the child's `bind` is the window in which an
    /// unrelated process could take the port, and it should be as short
    /// as possible.
    pub fn release(&mut self) {
        self.listener.take();
    }
}

/// Reserve a free localhost port, holding it until the caller releases it.
///
/// Prefer this to binding `:0` ad hoc — see the module docs for why
/// dropping the listener immediately is not sufficient.
pub fn reserve_port() -> Result<ReservedPort> {
    for _ in 0..MAX_ATTEMPTS {
        let listener =
            TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
        let port = listener.local_addr().context("read ephemeral port")?.port();

        // A port we have issued before may have been released and returned
        // to the pool; taking it again would hand two components the same
        // number.
        if issued().lock().expect("port registry poisoned").insert(port) {
            return Ok(ReservedPort {
                port,
                listener: Some(listener),
            });
        }
    }
    anyhow::bail!(
        "could not find an unused localhost port in {MAX_ATTEMPTS} attempts; \
         the ephemeral range may be exhausted"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the old implementation lacked: two reservations alive
    /// at once cannot name the same port.
    #[test]
    fn concurrent_reservations_are_distinct() {
        let held: Vec<ReservedPort> =
            (0..25).map(|_| reserve_port().expect("reserve")).collect();
        let mut seen = HashSet::new();
        for r in &held {
            assert!(
                seen.insert(r.port()),
                "port {} was reserved twice while still held",
                r.port()
            );
        }
    }

    /// A released port must not be re-issued either. Dropping the listener
    /// returns it to the OS pool, which is exactly how the old code handed
    /// the same number to two components.
    #[test]
    fn a_released_port_is_never_issued_again() {
        let mut first = reserve_port().expect("reserve");
        let released = first.port();
        first.release();

        for _ in 0..50 {
            let next = reserve_port().expect("reserve");
            assert_ne!(
                next.port(),
                released,
                "a released port was handed out a second time"
            );
        }
    }

    /// Releasing has to actually free the port, or the child could never
    /// bind it.
    #[test]
    fn releasing_lets_the_port_be_bound() {
        let mut reserved = reserve_port().expect("reserve");
        let port = reserved.port();
        assert!(
            TcpListener::bind(("127.0.0.1", port)).is_err(),
            "a held reservation must keep the port bound"
        );

        reserved.release();
        TcpListener::bind(("127.0.0.1", port))
            .expect("a released port must be bindable by the child");
    }
}
