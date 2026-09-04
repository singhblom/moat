//! Requested-sync scenario — the requesting device (D2) runs the Rust CLI, the donor (D1) runs Dart.
//!
//! Same story as [`super::sync_request_history`]: D2 sleeps through a
//! whole conversation, is fanned into it with membership but no history,
//! and asks D1 for the rest. This cell exercises the runtime mix named in
//! its suffix — see that module's `run_with` for why the body is shared
//! rather than copied.

use std::future::Future;
use std::pin::Pin;

use crate::scenarios::Action;
use crate::world::ParticipantKind;

pub(crate) fn run_boxed(
    _actions: Vec<Action>,
    verbose: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(run(verbose))
}

pub async fn run(verbose: bool) {
    super::sync_request_history::run_with(
        ParticipantKind::DartServer,
        ParticipantKind::RustCli,
        "dr",
        verbose,
    )
    .await
}
