# Flutter and Android participants

The Dart side reaches the local stack the same way the Rust side does, but the
URLs are compile-time defines rather than flags, and an emulator sees a
different address than the host.

## Desktop / Chrome

```bash
cd moat-dart/app
flutter run --dart-define=MOAT_PDS_URL=http://127.0.0.1:4000
```

For web with persistent localStorage and the CORS headers WASM threading
needs:

```bash
cd moat-dart/app && ./scripts/run-web.sh
```

That script fixes the browser profile so `localStorage` survives restarts —
plain `flutter run -d chrome` uses a temp profile and wipes it on exit, which
makes a device look freshly installed every run.

## Android emulator

The emulator reaches the host at `10.0.2.2`, not `127.0.0.1`. Postern binds
`0.0.0.0` for this reason.

```bash
cd moat-dart/app
flutter run --dart-define=MOAT_PDS_URL=http://10.0.2.2:4000
```

Add `--dart-define=MOAT_DRAWBRIDGE_URL=ws://10.0.2.2:8080/ws` when testing
push; use `ws://127.0.0.1:8080/ws` on desktop.

## The WASM binary must match the Rust

The web build loads a compiled WASM artifact that is **not** rebuilt by
`flutter run`. Any change to `moat-core` or `moat-dart/app/rust` leaves it
stale, and a stale binary fails at runtime with `Offset is outside the bounds
of the DataView` — which looks like a data bug rather than a build problem.

Rebuild before testing web after any Rust change:

```bash
cd moat-dart/app
flutter_rust_bridge_codegen build-web \
  --wasm-pack-rustflags="-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=1073741824 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base"
```

The shared-memory linker flags are not optional and FRB does not supply them:
without them the WASM memory is not a `SharedArrayBuffer` and the worker pool
fails with `DataCloneError`. Checking the browser console for either of those
two errors is the first thing to do on a web pass — if one appears, nothing
else observed in that session means anything.

## Headless Dart

`moat-dart/server` runs the same shared code as the app without a UI, and is
what `moat-beacon` drives as a Dart-side participant. Use it when the question
is whether Dart and Rust agree, rather than how something looks.

## Known local-only artifact

Profile names show as truncated DIDs (`alice-de`) with `?` avatars against
Postern. Profiles come from the public Bluesky AppView, which cannot resolve
Postern's DIDs, so the fallback applies. Not a defect — real accounts resolve
normally. Worth saying out loud in a handover, because it looks like one.
