/// Flutter-independent stand-ins for `ValueListenable`/`ValueNotifier`.
/// `moat_dart_common` has no Flutter dependency (it's shared with the
/// headless server), so services expose change notifications through these
/// instead. Same shape as Flutter's, so the app can adapt one cheaply —
/// see `asFlutter` in the app's `common_listenable.dart`.
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
