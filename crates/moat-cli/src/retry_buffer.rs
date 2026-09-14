//! Events that were fetched but could not be processed yet. How long each
//! is kept is decided by [`moat_core::keep_for_retry`], shared with the
//! Dart host.

/// An event kept for retry on later polls.
#[derive(Debug, Clone)]
pub struct UnprocessedEvent {
    /// Indices of the conversations the event's author takes part in, when
    /// known at fetch time. Empty for events restored from disk.
    pub conv_indices: Vec<usize>,
    pub record: moat_atproto::EventRecord,
    /// The DID whose PDS the event was fetched from.
    pub source_did: String,
    /// When this device first fetched it, in milliseconds since the Unix
    /// epoch. 0 for events buffered before this was recorded.
    pub first_seen_ms: i64,
    /// How many poll cycles have ended with the event still unprocessed.
    pub attempts: u32,
}
