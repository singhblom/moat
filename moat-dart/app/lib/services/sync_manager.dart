import 'package:flutter/foundation.dart' as flutter;
import 'package:moat_dart_common/moat_dart_common.dart';

/// Global holder of the interactive app's [SyncService].
///
/// Same shape as [PairingManager], but listenable: the app-wide progress
/// strip sits above the login cycle and has to follow it.
class SyncManager {
  static final SyncManager instance = SyncManager._();
  SyncManager._();

  final flutter.ValueNotifier<SyncService?> service = flutter.ValueNotifier(null);

  /// Must be called once per login, alongside the other post-login services.
  void init(SyncService sync) => service.value = sync;

  /// Called on logout, alongside the other post-login services.
  void clear() => service.value = null;
}
