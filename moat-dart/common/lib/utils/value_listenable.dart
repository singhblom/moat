/// Minimal Flutter-independent stand-ins for `package:flutter/foundation.dart`'s
/// `ValueListenable`/`ValueNotifier`. `moat_dart_common` has no Flutter
/// dependency — it's shared with the headless `moat_dart_server`, which runs
/// under plain `dart run` (see `ConversationRepository`'s "no ChangeNotifier"
/// note) — so services that want to expose a "current value + change
/// notifications" API to the Flutter app use this instead. Same shape as
/// Flutter's real types, so app-layer code can adapt one with a few lines
/// (e.g. forwarding into a local Flutter `ValueNotifier` via `addListener`)
/// rather than reinventing the pattern per screen.
abstract class ValueListenable<T> {
  T get value;
  void addListener(void Function() listener);
  void removeListener(void Function() listener);
}

class SimpleValueNotifier<T> implements ValueListenable<T> {
  SimpleValueNotifier(this._value);

  T _value;
  final List<void Function()> _listeners = [];

  @override
  T get value => _value;

  set value(T newValue) {
    if (_value == newValue) return;
    _value = newValue;
    // Snapshot before iterating — a listener that adds/removes another
    // listener mid-notification must not corrupt this pass.
    for (final listener in List<void Function()>.of(_listeners)) {
      listener();
    }
  }

  @override
  void addListener(void Function() listener) {
    _listeners.add(listener);
  }

  @override
  void removeListener(void Function() listener) {
    _listeners.remove(listener);
  }

  void dispose() {
    _listeners.clear();
  }
}
