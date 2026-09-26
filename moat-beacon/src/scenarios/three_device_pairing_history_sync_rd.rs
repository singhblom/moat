//! Three-device pairing history-sync scenario — existing device (D1) runs the
//! Dart headless server and serves the history; new devices run the Rust CLI.
//!
//! Same story as [`super::three_device_pairing_history_sync`]: D1 already
//! has conversation history with Bob predating D2/D3, and both must sync it
//! in via pairing. See that module's `run_with` for why the body is shared
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
    super::three_device_pairing_history_sync::run_with(
        ParticipantKind::DartServer,
        ParticipantKind::RustCli,
        "rd",
        verbose,
    )
    .await
}
