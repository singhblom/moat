use moat_beacon::actions::multi_device_action_sequence;
use moat_beacon::world::ParticipantKind;

fn cases() -> usize {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4)
}

fn run_cell(d1_kind: ParticipantKind, d2_kind: ParticipantKind) {
    let n = cases();
    moat_beacon::parallel::run_parallel_cases(multi_device_action_sequence(), n, move |actions| {
        let d1 = d1_kind.clone();
        let d2 = d2_kind.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(moat_beacon::scenarios::multi_device_chat::run(
            d1, d2, actions, false,
        ));
    });
}

// This cell was silently green until 2026-07-24, when `multi_device_chat::run`
// stopped swallowing send failures: a device fanned into a conversation via
// same-user fan-out could never send in it. Fixed by minting KP-lane
// KeyPackages with the identity signing key — see the signing-key note in
// `moat-core/src/device_ring.rs`.
#[test]
fn multi_device_chat_rr() {
    let _slot = moat_beacon::parallel::world_slot(super::WORLDS);
    run_cell(ParticipantKind::RustCli, ParticipantKind::RustCli);
}

#[test]
fn multi_device_chat_rd() {
    let _slot = moat_beacon::parallel::world_slot(super::WORLDS);
    run_cell(ParticipantKind::RustCli, ParticipantKind::DartServer);
}

#[test]
fn multi_device_chat_dr() {
    let _slot = moat_beacon::parallel::world_slot(super::WORLDS);
    run_cell(ParticipantKind::DartServer, ParticipantKind::RustCli);
}

#[test]
fn multi_device_chat_dd() {
    let _slot = moat_beacon::parallel::world_slot(super::WORLDS);
    run_cell(ParticipantKind::DartServer, ParticipantKind::DartServer);
}
