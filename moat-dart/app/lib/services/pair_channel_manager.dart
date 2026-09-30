import 'package:flutter/foundation.dart' as flutter;
import 'package:moat_dart_common/moat_dart_common.dart';

/// Global holder of the interactive app's [PairChannelService].
///
/// The service is constructed only after login, inside `AuthGate`'s
/// `_startPollingIfNeeded`, so it can't be a compile-time `Provider`.
/// Listenable, because the app-wide progress strip sits above the login
/// cycle and has to follow it.
class PairChannelManager {
  static final PairChannelManager instance = PairChannelManager._();
  PairChannelManager._();

  final flutter.ValueNotifier<PairChannelService?> _service =
      flutter.ValueNotifier(null);

  flutter.ValueListenable<PairChannelService?> get listenable => _service;

  PairChannelService? get service => _service.value;

  /// Must be called once per login, alongside the other post-login services.
  void init({required ServiceBundle bundle}) => _service.value = bundle.pairChannel;

  /// Called on logout, alongside the other post-login services.
  void clear() {
    _service.value?.dispose();
    _service.value = null;
  }
}
