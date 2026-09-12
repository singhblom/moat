import 'package:moat_dart_common/moat_dart_common.dart';

/// Global singleton owning the interactive app's [SyncRequestService].
///
/// Same shape and for the same reason as [PairingManager]: the service
/// depends on [AuthService]/[DrawbridgeService]/[DeviceRingService]/
/// [SyncService], all constructed only after login, so it can't be a
/// compile-time `Provider`. Screens reach the live service via
/// `SyncRequestManager.instance.service`.
class SyncRequestManager {
  static final SyncRequestManager instance = SyncRequestManager._();
  SyncRequestManager._();

  SyncRequestService? _service;

  SyncRequestService? get service => _service;

  /// Must be called once per login, alongside the other post-login
  /// services in `AuthGate._startPollingIfNeeded`.
  void init({required ServiceBundle bundle}) {
    _service = bundle.syncRequest;
  }

  /// Called on logout, alongside the other post-login services.
  void clear() {
    _service?.dispose();
    _service = null;
  }
}
