import 'dart:math';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// Manages FCM token lifecycle and device ID persistence.
///
/// Call [init] once after Firebase.initializeApp(). The service requests
/// notification permission, generates (or restores) a stable device ID, and
/// calls [onToken] whenever a token is available or refreshed.
class PushService {
  final SecureStorageService _secureStorage;
  void Function(String deviceId, String token)? onToken;

  PushService({required SecureStorageService secureStorage})
      : _secureStorage = secureStorage;

  Future<void> init() async {
    final messaging = FirebaseMessaging.instance;

    final settings = await messaging.requestPermission(
      alert: true,
      badge: true,
      sound: true,
    );
    if (settings.authorizationStatus == AuthorizationStatus.denied) {
      moatLog('PushService: notification permission denied');
      return;
    }

    final deviceId = await _ensureDeviceId();

    final token = await messaging.getToken();
    if (token != null) {
      moatLog('PushService: FCM token obtained');
      onToken?.call(deviceId, token);
    }

    messaging.onTokenRefresh.listen((newToken) async {
      moatLog('PushService: FCM token refreshed');
      onToken?.call(deviceId, newToken);
    });
  }

  Future<String> _ensureDeviceId() async {
    final existing = await _secureStorage.loadDeviceId();
    if (existing != null) return existing;
    final id = _generateDeviceId();
    await _secureStorage.saveDeviceId(id);
    return id;
  }

  static String _generateDeviceId() {
    final rng = Random.secure();
    final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
