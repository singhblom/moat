//! Standalone Postern instance for manual testing (e.g. driving the
//! Flutter app in an Android emulator against a local PDS instead of real
//! bsky.social). Every other Postern user (`moat-beacon`) embeds it
//! in-process via `spawn_postern` and tears it down when the test ends;
//! this binary just does the same thing and then blocks forever, so it
//! stays up for interactive use.
//!
//! Usage: `cargo run -p moat-postern --bin dev_server [-- <port>]`
//! (default port 4000). Binds `0.0.0.0` so an Android emulator can reach it
//! via `10.0.2.2:<port>`; a process on this same host (Drawbridge, moat-cli)
//! reaches it via `127.0.0.1:<port>`.
//!
//! Seeds two accounts sharing the `did:plc:` prefix `moat-beacon`'s
//! `TestWorld` uses, so nothing here surprises anyone used to that harness.
//! No password validation — this is a test PDS (see `server.rs`) — so any
//! password works for `alice.postern.test` / `bob.postern.test`.

use moat_postern::{AccountConfig, PosternConfig};

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4000);

    let accounts = vec![
        AccountConfig {
            did: "did:plc:alice-dev".to_string(),
            handle: "alice.postern.test".to_string(),
        },
        AccountConfig {
            did: "did:plc:bob-dev".to_string(),
            handle: "bob.postern.test".to_string(),
        },
    ];

    let postern = moat_postern::spawn_postern(PosternConfig {
        accounts,
        port: Some(port),
        data_dir: None,
        bind_addr: Some("0.0.0.0".to_string()),
    })
    .await;

    println!("Postern dev server running.");
    println!();
    println!("  PDS URL — from this Mac (moat-cli, Drawbridge):  http://127.0.0.1:{port}");
    println!("  PDS URL — from an Android emulator:              http://10.0.2.2:{port}");
    println!();
    println!("  Accounts (any password — Postern does not validate one):");
    println!("    alice.postern.test  (did:plc:alice-dev)");
    println!("    bob.postern.test    (did:plc:bob-dev)");
    println!();
    println!("  State directory: {}", postern.data_dir().display());
    println!();
    println!("Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    println!("Shutting down.");
}
