//! `beacon` binary — run or replay moat-beacon scenarios.
//!
//! Usage:
//!   beacon list                      List available scenarios
//!   beacon run <name>                Run a named scenario once (verbose, random actions)
//!   beacon replay <name> <seed>      Replay a proptest seed (same seed → same actions)

use moat_beacon::scenarios::{get_scenario, SCENARIOS};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("list") => {
            for s in SCENARIOS {
                eprintln!("{:<25} {}", s.name, s.description);
            }
        }

        Some("run") => {
            let name = match args.get(2) {
                Some(n) => n.as_str(),
                None => {
                    eprintln!("Usage: beacon run <scenario-name>");
                    std::process::exit(1);
                }
            };
            let scenario = match get_scenario(name) {
                Some(s) => s,
                None => {
                    eprintln!("Unknown scenario: {name}");
                    eprintln!("Run `beacon list` to see available scenarios.");
                    std::process::exit(1);
                }
            };
            let actions = scenario.generate_actions();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");
            rt.block_on(scenario.run(actions, true));
        }

        Some("replay") => {
            let name = match args.get(2) {
                Some(n) => n.as_str(),
                None => {
                    eprintln!("Usage: beacon replay <scenario-name> <seed>");
                    std::process::exit(1);
                }
            };
            let seed_str = match args.get(3) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("Usage: beacon replay <scenario-name> <seed>");
                    std::process::exit(1);
                }
            };
            let scenario = match get_scenario(name) {
                Some(s) => s,
                None => {
                    eprintln!("Unknown scenario: {name}");
                    eprintln!("Run `beacon list` to see available scenarios.");
                    std::process::exit(1);
                }
            };
            let actions = match scenario.actions_from_seed(seed_str) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("Invalid seed: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("Replaying seed: {seed_str}");
            eprintln!("Action count:   {}", actions.len());
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");
            rt.block_on(scenario.run(actions, true));
        }

        _ => {
            eprintln!("Usage:");
            eprintln!("  beacon list                      List available scenarios");
            eprintln!("  beacon run <name>                Run a named scenario once (verbose)");
            eprintln!("  beacon replay <name> <seed>      Replay a proptest seed");
            std::process::exit(1);
        }
    }
}
