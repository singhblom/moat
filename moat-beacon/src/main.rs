//! `beacon` binary — run or replay moat-beacon scenarios.
//!
//! Usage:
//!   beacon list                      List available scenarios
//!   beacon run <name>                Run a named scenario once (verbose, random actions)
//!   beacon replay <name> <seed>      Replay a proptest seed (same seed → same actions)
//!   beacon triage [n]                Report preserved storage roots whose device never joined a ring

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

        Some("triage") => {
            let limit = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(10);
            triage(limit);
        }

        _ => {
            eprintln!("Usage:");
            eprintln!("  beacon list                      List available scenarios");
            eprintln!("  beacon run <name>                Run a named scenario once (verbose)");
            eprintln!("  beacon replay <name> <seed>      Replay a proptest seed");
            eprintln!("  beacon triage [n]                Report devices that never joined a ring");
            std::process::exit(1);
        }
    }
}

/// Scan preserved participant storage roots and report devices that never
/// reached `in_ring`.
///
/// Beacon deliberately does not clean up participant storage (see
/// `world::make_storage_dir`), so after a failing run every device's
/// `keys/ring.json` and `data/debug.log` are still on disk. What was missing
/// was any way to find the interesting one among hundreds of directories.
///
/// Reports, newest first: the ring state, the peer-state histogram, and the
/// path — so the next step is always `grep "ring: tick" <path>/data/debug.log`.
fn triage(limit: usize) {
    let base = std::path::Path::new("/tmp/moat-beacon-data");
    let Ok(entries) = std::fs::read_dir(base) else {
        eprintln!("no {} — run a scenario first", base.display());
        return;
    };

    let mut rows: Vec<(std::time::SystemTime, String, String, String, bool)> = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let dir = entry.path();
        let ring_json = dir.join("data/keys/ring.json");
        // Dart participants persist through DocumentBackend, whose root is the
        // storage dir itself — not the `data/` subdir the Rust CLI uses.
        let dart_json = dir.join("device_ring/ring_state.json");
        let path = if ring_json.exists() {
            ring_json
        } else if dart_json.exists() {
            dart_json
        } else {
            continue;
        };
        let Ok(raw) = std::fs::read_to_string(&path) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { continue };

        let ring = v.get("ring");
        let state = ring
            .and_then(|r| r.get("state"))
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| if ring.is_some() { "?" } else { "solo" })
            .to_string();
        let gen = ring
            .and_then(|r| r.get("generation"))
            .and_then(|g| g.as_u64())
            .map(|g| format!(" gen={g}"))
            .unwrap_or_default();

        let mut hist: std::collections::BTreeMap<String, usize> = Default::default();
        if let Some(peers) = v.get("peers").and_then(|p| p.as_object()) {
            for ps in peers.values() {
                let s = ps.get("state").and_then(|s| s.as_str()).unwrap_or("?");
                let link = ps
                    .get("ring_link")
                    .and_then(|l| l.get("state"))
                    .and_then(|s| s.as_str())
                    .map(|l| format!("/{l}"))
                    .unwrap_or_default();
                *hist.entry(format!("{s}{link}")).or_default() += 1;
            }
        }
        let peers = if hist.is_empty() {
            "none".to_string()
        } else {
            hist.iter()
                .map(|(k, n)| format!("{k}={n}"))
                .collect::<Vec<_>>()
                .join(" ")
        };

        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        // A DID with a single device has no ring by design, so plain
        // `solo` with no peers is the expected state for e.g. `bob` and for
        // every two-party participant — flagging those would bury the real
        // ones (368 of 1310 roots on first run). Suspect means: we know of
        // siblings but are not in a ring with them, or we started forming
        // one and stopped.
        let suspect = state != "in_ring" && (state != "solo" || !hist.is_empty());
        let label = dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("moat-beacon-"))
            .and_then(|n| n.rsplit_once('-').map(|(l, _)| l.to_string()))
            .unwrap_or_default();
        rows.push((
            mtime,
            format!("{label}: ring={state}{gen}"),
            peers,
            dir.display().to_string(),
            suspect,
        ));
    }

    rows.sort_by_key(|r| std::cmp::Reverse(r.0));
    let suspects: Vec<_> = rows.iter().filter(|r| r.4).collect();

    eprintln!(
        "{} storage roots scanned, {} suspect (know of siblings but not in a ring with them)\n",
        rows.len(),
        suspects.len()
    );
    for (_, state, peers, path, _) in suspects.into_iter().take(limit) {
        eprintln!("  {state}\n  peers: {peers}\n  {path}\n");
    }
    eprintln!("next: grep 'tick in' <path>/data/debug.log   (Dart: <path>/../../moat-beacon/<label>-*.log)");
}
