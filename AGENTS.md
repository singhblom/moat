# Repository Guidelines

## Project Structure & Module Organization
Moat is a Rust workspace containing `crates/moat-core` (MLS crypto), `crates/moat-atproto` (PDS client), and `crates/moat-cli` (Ratatui UI). The Flutter app with its FRB wrapper lives in `moat-flutter/`, the Go relay is `moat-drawbridge/`, and lexicons sit in `lexicons/social/moat/`. `CLAUDE.md` covers architecture boundaries; sync all MLS, stealth, or record changes with `PROTOCOL.md`.

## Build, Test, and Development Commands
- `cargo fmt && cargo clippy --workspace --all-targets` / `cargo build --workspace` – format, lint, and compile the workspace  
- `cargo test -p moat-core` / `cargo test -p moat-atproto` – crypto + record suites  
- `cargo run -p moat-cli -- --storage-dir /tmp/moat-alice`, `-- fetch --repository handle.bsky.social`, `-- status` – run the TUI or diagnostics (use unique storage dirs for multi-device tests)  
- `cd moat-flutter && flutter pub get && flutter test && flutter run` – sync, test, and launch the Flutter app; rerun `flutter_rust_bridge_codegen generate` after touching `moat-flutter/rust/src/api/`  
- `cd moat-drawbridge && go test ./... && go run .` – verify and run the relay

## Coding Style & Naming Conventions
Rust uses 4-space indent, `snake_case` functions, and `UpperCamelCase` types; keep crypto in `moat-core` via `MoatSession` so clients stay IO-only. Flutter follows `dart format lib test`, `UpperCamelCase` classes, and `snake_case.dart` files. Go stays `go fmt` clean with concise packages, and lexicon JSON must follow the existing `event`, `keyPackage`, and `stealthAddress` naming.

## Testing Guidelines
`moat-core` ships ~70 unit tests plus property cases in `crates/moat-core/tests/proptest_padding_tag.rs`; extend them when modifying padding buckets (256B/1KB/4KB), tag derivation, or transcript integrity. `moat-atproto`, Flutter (Dart + FRB), and `moat-drawbridge` suites are thinner, so any change there should include targeted tests for invite handling, keystore persistence, relay auth, or CLI subcommands. Use `tempfile::tempdir()` or `Directory.systemTemp` for filesystem isolation and run `cargo test -p <crate>`, `flutter test --coverage`, and `go test -race ./...` before opening a PR.

## Commit, PR, & Protocol Guidelines
Commits use short imperative subjects (“Fix emoji bugs”), keep related changes together, and reference issues (`Refs #123`). PRs summarize behavior shifts, risks, and the verification commands run, plus screenshots or terminal captures for UI updates. `PROTOCOL.md` captures the MLS ciphersuite (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), stealth invite flow, padding buckets, rotating tags, and the `~/.moat/mls.bin` format—update it (and the lexicons) whenever those systems change, and refresh `CLAUDE.md` when adding commands or build steps. Avoid committing artifacts from `~/.moat`, `moat-flutter/build/`, or generated FRB code, and use placeholder DIDs/handles in docs or tests.
