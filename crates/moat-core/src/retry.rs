//! How long an event that could not be processed is worth retrying.
//!
//! What can unlock such an event is something fetched *after* it: the
//! commit that reaches its epoch, or the Welcome for its group. Both are
//! published before the events that depend on them, so they arrive in the
//! same poll or within a poll or two of it. An event still unreadable past
//! that point is one the device will never read — another user's ring or
//! stealth traffic, or a group's traffic from before the device joined —
//! and retrying it only costs a decrypt attempt per poll, forever.
//!
//! Dropping an event does not lose history the user can recover: a message
//! from before the device joined reaches it through history sync.
//!
//! The rule lives here so both hosts give up on the same events.

/// Every event gets at least this many poll cycles, so a device polling
/// slowly still sees the next fetch or two before giving up.
pub const MIN_RETRY_ATTEMPTS: u32 = 3;

/// Every event is retried for at least this long, so a device polling
/// quickly does not give up before a slow publisher's commit lands.
pub const MAX_RETRY_AGE_MS: i64 = 10 * 60 * 1000;

/// Whether an event that has just failed another poll cycle is still worth
/// keeping.
///
/// `first_seen_ms` is when the device first fetched it (0 when unknown),
/// `attempts` how many poll cycles have now ended with it unprocessed. It is
/// dropped only once it has had both its minimum cycles and its minimum time.
pub fn keep_for_retry(first_seen_ms: i64, attempts: u32, now_ms: i64) -> bool {
    attempts < MIN_RETRY_ATTEMPTS || now_ms.saturating_sub(first_seen_ms) < MAX_RETRY_AGE_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn a_fresh_event_is_kept() {
        assert!(keep_for_retry(NOW, 1, NOW));
    }

    /// A device polling every few minutes reaches the age limit on its
    /// first retry; it still gets its minimum cycles.
    #[test]
    fn an_old_event_is_kept_until_it_has_had_its_cycles() {
        let first_seen = NOW - 2 * MAX_RETRY_AGE_MS;
        assert!(keep_for_retry(first_seen, 1, NOW));
        assert!(keep_for_retry(first_seen, MIN_RETRY_ATTEMPTS - 1, NOW));
        assert!(!keep_for_retry(first_seen, MIN_RETRY_ATTEMPTS, NOW));
    }

    /// A device polling every second burns through its cycles in seconds;
    /// it still waits out the age limit.
    #[test]
    fn a_retried_event_is_kept_until_it_is_old_enough() {
        assert!(keep_for_retry(NOW - MAX_RETRY_AGE_MS + 1, 500, NOW));
        assert!(!keep_for_retry(NOW - MAX_RETRY_AGE_MS, 500, NOW));
    }

    /// Events buffered before first-seen times were recorded carry 0, and
    /// are dropped once they have had their cycles.
    #[test]
    fn an_event_with_no_first_seen_time_is_dropped_after_its_cycles() {
        assert!(keep_for_retry(0, MIN_RETRY_ATTEMPTS - 1, NOW));
        assert!(!keep_for_retry(0, MIN_RETRY_ATTEMPTS, NOW));
    }
}
