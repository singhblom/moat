//! `beacon` binary — run or replay moat-beacon scenarios.
//!
//! Usage:
//!   beacon run <scenario-name>   — run a named scenario with verbose output
//!   beacon replay <seed>         — replay a failing proptest seed (future)

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("run") => {
            let name = args.get(2).map(|s| s.as_str()).unwrap_or("smoke");
            eprintln!("beacon: running scenario '{name}'");
            eprintln!("(Use `cargo test -p moat-beacon` to run all scenarios)");
            // TODO (Phase 5): look up named scenario in a registry and run it.
        }
        Some("replay") => {
            let seed = args.get(2).map(|s| s.as_str()).unwrap_or("<seed>");
            eprintln!("beacon: replay seed '{seed}'");
            // TODO (Phase 5): restore proptest state from seed and replay.
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  beacon run <scenario-name>   Run a named scenario");
            eprintln!("  beacon replay <seed>         Replay a failing proptest seed");
            std::process::exit(1);
        }
    }
}
