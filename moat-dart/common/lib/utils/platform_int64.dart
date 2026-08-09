import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

/// `flutter_rust_bridge`'s `PlatformInt64` is a *conditional* typedef —
/// `int` on native (`_io.dart`), `BigInt` on web (`_web.dart`), since JS
/// numbers can't hold full 64-bit precision. Code that assigns a plain
/// `int` to a `PlatformInt64` field/param, or reads one back into an
/// `int`, is only correct on native — `flutter test` (native VM) won't
/// catch the web-only type error; only `flutter build web` will.
///
/// [toPlatformInt64] wraps the package's own [PlatformInt64Util.from].
/// [platformInt64ToInt] has no equivalent upstream export, so it
/// discriminates at runtime instead: `is BigInt` is false on native
/// (where the value truly is an `int`) and true on web.
PlatformInt64 toPlatformInt64(int value) => PlatformInt64Util.from(value);

// The `as int` below is flagged as unnecessary by `dart analyze` (which
// resolves PlatformInt64 == int on native) but is required on web, where
// this branch is unreachable at runtime yet must still satisfy the `int`
// return type statically.
int platformInt64ToInt(PlatformInt64 value) =>
    // ignore: unnecessary_cast
    value is BigInt ? value.toInt() : value as int;
