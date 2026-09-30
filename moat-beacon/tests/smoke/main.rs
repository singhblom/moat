//! Deterministic Beacon scenarios, one `TestWorld` per test.
//!
//! One binary for the whole family, so cargo links Beacon once; at most
//! [`WORLDS`] worlds run at a time (`BEACON_WORLDS` overrides).

mod image_smoke;
mod send_failure;

use moat_beacon::scenarios::*;
use moat_beacon::world::ParticipantKind;

const WORLDS: usize = 2;
const R: ParticipantKind = ParticipantKind::RustCli;
const D: ParticipantKind = ParticipantKind::DartServer;

macro_rules! scenario_tests {
    ($($(#[$attr:meta])* $name:ident => $run:expr,)*) => {
        $(
            $(#[$attr])*
            #[test]
            fn $name() {
                moat_beacon::parallel::run_world(WORLDS, $run);
            }
        )*
    };
}

scenario_tests! {
    alice_sends_bob_receives => two_party_smoke::run(),
    dart_offers_history_without_prompting_the_recipient => sync_offer_history::run_with(D, R, "dr", true),
    history_arrives_before_membership => sync_history_before_membership::run(true),
    lost_device_pairing_recovers => lost_device_pairing::run(true),
    offered_history_is_accepted_without_a_prompt => sync_offer_history::run(true),
    pairing_cancelled_leaves_no_ring => pairing_cancelled::run(true),
    pairing_rejected_leaves_no_ring => pairing_rejected::run(true),
    pairing_retry_after_abandoned_succeeds => pairing_retry_after_abandoned::run(true),
    post_fan_out_delivery_converges => post_fan_out_delivery::run(true),
    post_fan_out_delivery_dr_converges => post_fan_out_delivery::run_dr(true),
    post_fan_out_delivery_rd_converges => post_fan_out_delivery::run_rd(true),
    sender_exceeds_tag_window_converges => sender_exceeds_tag_window::run(true),
    sender_exceeds_tag_window_d_converges => sender_exceeds_tag_window::run_dart_recipient(true),
    staggered_device_pairing_converges => staggered_device_pairing::run(true),
    sync_request_after_cancelled_pairing_prompts => sync_request_after_cancelled_pairing::run_with(R, "r", true),
    sync_request_after_cancelled_pairing_d_prompts => sync_request_after_cancelled_pairing::run_with(D, "d", true),
    sync_request_after_idle_converges => sync_request_history::run_after_idle(true),
    sync_request_after_idle_dd_converges => sync_request_history::run_after_idle_dd(true),
    sync_request_delivers_missing_history => sync_request_history::run(true),
    sync_request_delivers_missing_history_dd => sync_request_history::run_with(D, D, "dd", true),
    sync_request_delivers_missing_history_dr => sync_request_history::run_with(D, R, "dr", true),
    sync_request_delivers_missing_history_rd => sync_request_history::run_with(R, D, "rd", true),
    three_device_pairing_converges => three_device_pairing::run(true),
    three_device_pairing_history_sync_converges => three_device_pairing_history_sync::run(true),
    three_device_pairing_history_sync_dr_converges => three_device_pairing_history_sync::run_with(R, D, "dr", true),
    three_device_pairing_history_sync_rd_converges => three_device_pairing_history_sync::run_with(D, R, "rd", true),
    sync_offer_across_drawbridges_dd => sync_offer_history::run_across_drawbridges(D, D, "dd", true),
    sync_offer_across_drawbridges_dr => sync_offer_history::run_across_drawbridges(D, R, "dr", true),
    sync_offer_across_drawbridges_rd => sync_offer_history::run_across_drawbridges(R, D, "rd", true),
    sync_offer_across_drawbridges_rr => sync_offer_history::run_across_drawbridges(R, R, "rr", true),
    sync_request_across_drawbridges_dd => sync_request_history::run_across_drawbridges(D, D, "dd", true),
    sync_request_across_drawbridges_dr => sync_request_history::run_across_drawbridges(D, R, "dr", true),
    sync_request_across_drawbridges_rd => sync_request_history::run_across_drawbridges(R, D, "rd", true),
    sync_request_across_drawbridges_rr => sync_request_history::run_across_drawbridges(R, R, "rr", true),
    two_device_pairing_across_drawbridges_dd => two_device_pairing::run_across_drawbridges(D, D, "dd", true),
    two_device_pairing_across_drawbridges_dr => two_device_pairing::run_across_drawbridges(D, R, "dr", true),
    two_device_pairing_across_drawbridges_rd => two_device_pairing::run_across_drawbridges(R, D, "rd", true),
    two_device_pairing_across_drawbridges_rr => two_device_pairing::run_across_drawbridges(R, R, "rr", true),
    three_party_conversation => three_party_smoke::run_with([R, R, R]),
    three_party_conversation_dart => three_party_smoke::run_with([D, D, D]),
    three_party_conversation_mixed => three_party_smoke::run_with([R, D, D]),
    two_device_pairing_converges => two_device_pairing::run(true),
    two_device_pairing_dd_converges => two_device_pairing::run_with(D, D, "dd", true),
    two_device_pairing_dr_converges => two_device_pairing::run_with(D, R, "dr", true),
    two_device_pairing_rd_converges => two_device_pairing::run_with(R, D, "rd", true),
    watched_before_welcome_converges => watched_before_welcome::run(true),
    watched_before_welcome_d_converges => watched_before_welcome::run_dart_joiner(true),
}
