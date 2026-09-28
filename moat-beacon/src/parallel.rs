//! Optionally-parallel case runner for property-based integration tests.
//!
//! [`run_parallel_cases`] is a drop-in replacement for the `proptest!` macro
//! that can run cases concurrently when the `BEACON_PARALLEL` environment
//! variable is set.
//!
//! ## Usage
//!
//! ```text
//! # default: sequential, same behaviour as before
//! cargo test -p moat-beacon
//!
//! # 2× speedup on a specific slow test
//! BEACON_PARALLEL=2 cargo test -p moat-beacon --test proptest_three_party_push
//! ```
//!
//! ## Why not always parallel?
//!
//! Each test case spawns real OS processes (moat-cli × N, Toxiproxy, Drawbridge).
//! Too many worlds at once starve each other and flake on startup timeouts.
//! `BEACON_PARALLEL` lets you opt in when running a single test in isolation.
//!
//! ## World slots
//!
//! The libtest harness runs a binary's tests on one thread per core.
//! [`world_slot`] bounds how many of them stand up a `TestWorld` at once;
//! `BEACON_WORLDS` overrides each binary's default.
//!
//! ## Trade-offs vs. `proptest!`
//!
//! - **No shrinking** — failing inputs are not minimised.  The full generated
//!   value is printed so it can be replayed with `beacon replay`.
//! - **No regression file** — failing seeds are not written to disk.  Record
//!   them manually from the failure output.

use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use std::future::Future;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

struct Slots {
    limit: usize,
    in_use: Mutex<usize>,
    freed: Condvar,
}

static SLOTS: OnceLock<Slots> = OnceLock::new();

/// Held while a test runs its world; dropping it frees the slot.
pub struct WorldSlot(&'static Slots);

impl Drop for WorldSlot {
    fn drop(&mut self) {
        let mut in_use = self.0.in_use.lock().unwrap_or_else(|e| e.into_inner());
        *in_use -= 1;
        self.0.freed.notify_one();
    }
}

/// Block until fewer than the binary's limit of worlds are running.
/// The limit is `BEACON_WORLDS` if set, else `default_limit`; the first
/// call in a process fixes it.
pub fn world_slot(default_limit: usize) -> WorldSlot {
    let slots = SLOTS.get_or_init(|| Slots {
        limit: std::env::var("BEACON_WORLDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n: &usize| n > 0)
            .unwrap_or(default_limit),
        in_use: Mutex::new(0),
        freed: Condvar::new(),
    });
    let mut in_use = slots.in_use.lock().unwrap_or_else(|e| e.into_inner());
    while *in_use >= slots.limit {
        in_use = slots.freed.wait(in_use).unwrap_or_else(|e| e.into_inner());
    }
    *in_use += 1;
    WorldSlot(slots)
}

/// Run one scenario future on a fresh current-thread runtime, inside a
/// [`world_slot`].
pub fn run_world<F: Future<Output = ()>>(default_limit: usize, fut: F) {
    let _slot = world_slot(default_limit);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(fut);
}

/// Run `cases` inputs drawn from `strategy` through `test_fn`.
///
/// Concurrency is controlled by the `BEACON_PARALLEL` environment variable
/// (default `1` = sequential).  Cases are run in batches: all cases in a
/// batch execute concurrently on separate OS threads; the next batch starts
/// only after the previous one finishes.
///
/// Panics after all batches complete if any case panicked, printing each
/// failure message.
pub fn run_parallel_cases<S, F>(strategy: S, cases: usize, test_fn: F)
where
    S: Strategy,
    S::Value: Send + 'static,
    F: Fn(S::Value) + Send + Sync + 'static,
{
    let concurrency = std::env::var("BEACON_PARALLEL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1);

    let test_fn = Arc::new(test_fn);
    let mut runner = TestRunner::default();

    // Generate all inputs upfront (fast, sequential).
    let mut values: Vec<S::Value> = (0..cases)
        .map(|_| {
            strategy
                .new_tree(&mut runner)
                .expect("strategy failed to generate a value")
                .current()
        })
        .collect();

    let mut failures: Vec<(usize, String)> = Vec::new();
    let mut case_offset = 0;

    while !values.is_empty() {
        let batch_size = concurrency.min(values.len());
        let batch: Vec<_> = values.drain(..batch_size).collect();

        let handles: Vec<_> = batch
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                let f = test_fn.clone();
                let idx = case_offset + i;
                std::thread::Builder::new()
                    .name(format!("case-{idx}"))
                    .spawn(move || f(value))
                    .expect("spawn thread")
            })
            .collect();

        for (i, handle) in handles.into_iter().enumerate() {
            if let Err(panic_val) = handle.join() {
                let msg = if let Some(s) = panic_val.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic_val.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "(non-string panic payload)".to_string()
                };
                failures.push((case_offset + i, msg));
            }
        }

        case_offset += batch_size;
    }

    if !failures.is_empty() {
        let detail: Vec<String> = failures
            .iter()
            .map(|(i, msg)| format!("  case {i}:\n    {}", msg.replace('\n', "\n    ")))
            .collect();
        panic!(
            "{}/{cases} test cases failed:\n{}",
            failures.len(),
            detail.join("\n")
        );
    }
}
