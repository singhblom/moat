//! Offer scenario — the offering device (D1) runs Dart, the recipient runs
//! the Rust CLI.
//!
//! Same story as [`super::sync_offer_history`], on the axis that matters:
//! D1 is the device that lists its siblings and offers. That whole path is
//! Dart's here.

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
    super::sync_offer_history::run_with(
        ParticipantKind::DartServer,
        ParticipantKind::RustCli,
        "dr",
        verbose,
    )
    .await
}
