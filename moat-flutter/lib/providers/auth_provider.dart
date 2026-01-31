import 'package:flutter/foundation.dart';
import '../services/atproto_client.dart';
import '../services/secure_storage.dart';
import '../src/rust/api/simple.dart';

/// Authentication state
enum AuthState {
  /// Initial state, checking for existing session
  loading,
  /// Not logged in
  unauthenticated,
  /// Logged in and ready
  authenticated,
}

/// Provider for authentication and key management
class AuthProvider extends ChangeNotifier {
  final AtprotoClient _atprotoClient;
  final SecureStorageService _secureStorage;
  MoatSessionHandle? _moatSession;

  AuthState _state = AuthState.loading;
  String? _did;
  String? _handle;
  String? _deviceName;

  AuthProvider({
    AtprotoClient? atprotoClient,
    SecureStorageService? secureStorage,
  })  : _atprotoClient = atprotoClient ?? AtprotoClient(),
        _secureStorage = secureStorage ?? SecureStorageService();

  AuthState get state => _state;
  bool get isAuthenticated => _state == AuthState.authenticated;
  bool get isLoading => _state == AuthState.loading;
  String? get did => _did;
  String? get handle => _handle;
  String? get deviceName => _deviceName;
  AtprotoClient get atprotoClient => _atprotoClient;
  MoatSessionHandle? get moatSession => _moatSession;

  /// Initialize the provider and check for existing session
  Future<void> init() async {
    _state = AuthState.loading;
    notifyListeners();

    try {
      // Try to restore existing session
      final session = await _secureStorage.loadSession();
      if (session != null) {
        _atprotoClient.restoreSession(session);
        _did = session.did;
        _handle = session.handle;
        _deviceName = await _secureStorage.loadDeviceName();

        // Restore MLS state
        await _restoreMlsState();

        _state = AuthState.authenticated;
      } else {
        _state = AuthState.unauthenticated;
      }
    } catch (e) {
      debugPrint('Failed to restore session: $e');
      _state = AuthState.unauthenticated;
    }

    notifyListeners();
  }

  /// Login with handle, app password, and device name
  Future<void> login(String handle, String password,
      {required String deviceName}) async {
    // Authenticate with ATProto
    final session = await _atprotoClient.login(handle, password);
    await _secureStorage.saveSession(session);

    _did = session.did;
    _handle = session.handle;
    _deviceName = deviceName;

    // Save device name
    await _secureStorage.saveDeviceName(deviceName);

    // Initialize MLS session
    await _initializeMlsSession();

    // Generate and publish keys if needed
    await _ensureKeysPublished();

    _state = AuthState.authenticated;
    notifyListeners();
  }

  /// Logout and clear all data
  Future<void> logout() async {
    _atprotoClient.logout();
    await _secureStorage.clearAll();

    _moatSession = null;
    _did = null;
    _handle = null;
    _deviceName = null;
    _state = AuthState.unauthenticated;

    notifyListeners();
  }

  Future<void> _restoreMlsState() async {
    final mlsState = await _secureStorage.loadMlsState();
    if (mlsState != null) {
      _moatSession = await MoatSessionHandle.fromState(state: mlsState);
    } else {
      _moatSession = MoatSessionHandle.newSession();
    }
  }

  Future<void> _initializeMlsSession() async {
    // Check for existing MLS state
    final mlsState = await _secureStorage.loadMlsState();
    if (mlsState != null) {
      _moatSession = await MoatSessionHandle.fromState(state: mlsState);
    } else {
      _moatSession = MoatSessionHandle.newSession();
      await _saveMlsState();
    }
  }

  Future<void> _saveMlsState() async {
    if (_moatSession != null) {
      final state = await _moatSession!.exportState();
      await _secureStorage.saveMlsState(state);
    }
  }

  Future<void> _ensureKeysPublished() async {
    // Check if we already have stealth keys
    final hasStealthKeys = await _secureStorage.hasStealthKeypair();
    if (!hasStealthKeys) {
      await _generateAndPublishStealthAddress();
    }

    // Check if we have a key bundle (and thus published key package)
    final keyBundle = await _secureStorage.loadKeyBundle();
    if (keyBundle == null) {
      await _generateAndPublishKeyPackage();
    }
  }

  Future<void> _generateAndPublishStealthAddress() async {
    // Generate stealth keypair using moat-core via FFI
    final keypair = generateStealthKeypair();

    // Save locally
    await _secureStorage.saveStealthKeypair(
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
    );

    // Publish to PDS
    await _atprotoClient.publishStealthAddress(keypair.publicKey);
  }

  Future<void> _generateAndPublishKeyPackage() async {
    if (_moatSession == null || _did == null || _deviceName == null) {
      throw StateError('MLS session or device name not initialized');
    }

    // Generate key package with DID and device name (MoatCredential)
    final result = await _moatSession!.generateKeyPackage(
      did: _did!,
      deviceName: _deviceName!,
    );

    // Save key bundle locally (private keys)
    await _secureStorage.saveKeyBundle(result.keyBundle);

    // Publish key package to PDS (public)
    await _atprotoClient.publishKeyPackage(result.keyPackage);

    // Save updated MLS state
    await _saveMlsState();
  }

  /// Save MLS state after operations
  Future<void> saveMlsState() async {
    await _saveMlsState();
  }
}
