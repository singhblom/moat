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
        rt.block_on(moat_beacon::scenarios::multi_device_chat::run(d1, d2, actions, false));
    });
}

// Was silently green before 2026-07-24: `multi_device_chat::run`'s
// SendUserMessage handler used to swallow send failures
// (`if ... .is_ok() { record it }`) instead of asserting on them, which hid
// a real, deterministic bug — see `fanned-in-device-signing-key-bug.md`.
// Device 1 (D2) was fanned into the conversation via same-user fan-out
// (a KP-lane KeyPackage, not its own identity KeyPackage) and can
// therefore never successfully send in it: `encrypt_event` always signs
// with the device's one persistent identity key, which doesn't match the
// signature key D2's leaf in this group actually carries. Any action
// sequence that generates a `SendUserMessage { device: 1, .. }` now fails
// loudly instead of silently. Un-ignore once that bug is fixed.
#[ignore = "blocked on fanned-in-device-signing-key-bug.md: D2 can never send after same-user fan-out"]
#[test]
fn multi_device_chat_rr() {
    run_cell(ParticipantKind::RustCli, ParticipantKind::RustCli);
}

// Cells involving a Dart participant are #[ignore] pending Phase G.  The
// FFI tick() shim currently hardcodes `sibling_stealth: &[]` so Dart
// devices don't publish bootstrap KPs (Phase C); Rust adders therefore
// have no pending KP for Dart peers and ring add stalls.  Phase G adds
// SiblingStealth to the FFI surface (FRB regen + WASM rebuild) and wires
// the Dart driver to populate it.
#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[test]
fn multi_device_chat_rd() {
    run_cell(ParticipantKind::RustCli, ParticipantKind::DartServer);
}

#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[test]
fn multi_device_chat_dr() {
    run_cell(ParticipantKind::DartServer, ParticipantKind::RustCli);
}

#[ignore = "blocked on Phase G FFI: Dart bootstrap KP publication"]
#[test]
fn multi_device_chat_dd() {
    run_cell(ParticipantKind::DartServer, ParticipantKind::DartServer);
}
