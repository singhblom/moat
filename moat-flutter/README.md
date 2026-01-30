# Moat Flutter

Flutter app for Moat encrypted messenger. Uses flutter_rust_bridge to call moat-core for MLS cryptography.

## Requirements

- Flutter 3.x
- Rust toolchain with Android targets
- Android SDK (API 29+)

## Setup

Install the flutter_rust_bridge codegen tool:

```bash
cargo install flutter_rust_bridge_codegen
```

## Running

Start an Android emulator, then:

```bash
cd moat-flutter
flutter run
```

## Development

After modifying Rust code in `rust/src/api/`, regenerate Dart bindings:

```bash
flutter_rust_bridge_codegen generate
```

## Architecture

- `rust/` — Thin Rust wrapper that re-exports moat-core's API for FRB
- `lib/src/rust/` — Auto-generated Dart bindings (do not edit)
- `lib/main.dart` — Flutter app entry point
