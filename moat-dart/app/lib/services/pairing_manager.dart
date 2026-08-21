import 'dart:async';

import 'package:moat_dart_common/moat_dart_common.dart';

/// Global singleton owning the interactive app's [PairingService].
///
/// Mirrors [ConversationManager]'s lazy-init-after-login shape: the service
/// depends on [AuthService]/[DrawbridgeService]/[DeviceRingService]/
/// [SyncService], all of which are only constructed post-login inside
/// `AuthGate`'s `_startPollingIfNeeded`, so this can't be a compile-time
/// `Provider`. Screens reach the live service via [PairingManager.instance.service].
class PairingManager {
  static final PairingManager instance = PairingManager._();
  PairingManager._();

  PairingService? _service;

  PairingService? get service => _service;

  /// Must be called once per login, alongside `DeviceRingService`/
  /// `SyncService` construction in `AuthGate._startPollingIfNeeded`.
  void init({
    required AuthService authService,
    required DrawbridgeService drawbridge,
    required DeviceRingService ring,
    required SyncService sync,
    required ConversationStorage conversationStorage,
    required MessageStorage messageStorage,
  }) {
    _service = PairingService(
      auth: authService,
      drawbridge: drawbridge,
      ring: ring,
      sync: sync,
      conversationStorage: conversationStorage,
      messageStorage: messageStorage,
    );
  }

  /// Called on logout, alongside the other post-login services.
  void clear() {
    unawaited(_service?.dispose());
    _service = null;
  }
}
