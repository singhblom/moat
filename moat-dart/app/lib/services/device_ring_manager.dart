import 'package:moat_dart_common/moat_dart_common.dart';

/// Global singleton holding the interactive app's [DeviceRingService].
///
/// Same shape and reason as [PairChannelManager]: the
/// service is constructed only after login, inside `AuthGate`, so it can't
/// be a compile-time `Provider`. Screens that need ring state — today the
/// linked-devices list — reach it via `DeviceRingManager.instance.service`.
class DeviceRingManager {
  static final DeviceRingManager instance = DeviceRingManager._();
  DeviceRingManager._();

  DeviceRingService? _service;

  DeviceRingService? get service => _service;

  /// Must be called once per login, alongside the other post-login services.
  void init(DeviceRingService service) {
    _service = service;
  }

  /// Called on logout, alongside the other post-login services.
  void clear() {
    _service = null;
  }
}
