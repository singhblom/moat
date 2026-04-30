import 'dart:async';
import 'dart:math';
import 'dart:typed_data';
import 'atproto_client.dart';
import 'drawbridge_service.dart';
import 'secure_storage.dart';
import 'debug_log.dart';
import '../rust/api/simple.dart';
import '../utils/welcome_envelope.dart';

/// Authentication state
enum AuthState {
  loading,
  unauthenticated,
  authenticated,
}

/// Core authentication and key management service.
/// No Flutter dependency — pure Dart business logic extracted from AuthProvider.
class AuthService {
  final AtprotoClient _atprotoClient;
  final SecureStorageService _secureStorage;
  final String? drawbridgeUrl;
  MoatSessionHandle? _moatSession;

  AuthState _state = AuthState.loading;
  String? _did;
  String? _handle;
  String? _deviceName;

  AuthService({
    required AtprotoClient atprotoClient,
    required SecureStorageService secureStorage,
    this.drawbridgeUrl,
  })  : _atprotoClient = atprotoClient,
        _secureStorage = secureStorage {
    _atprotoClient.onSessionRefreshed = (session) {
      _secureStorage.saveSession(session);
      moatLog('AuthService: Auto-refreshed session persisted');
    };
  }

  AuthState get state => _state;
  bool get isAuthenticated => _state == AuthState.authenticated;
  bool get isLoading => _state == AuthState.loading;
  String? get did => _did;
  String? get handle => _handle;
  String? get deviceName => _deviceName;
  AtprotoClient get atprotoClient => _atprotoClient;
  MoatSessionHandle? get moatSession => _moatSession;
  SecureStorageService get secureStorage => _secureStorage;

  /// Initialize and check for existing session.
  Future<void> init() async {
    _state = AuthState.loading;

    try {
      final session = await _secureStorage.loadSession();
      if (session != null) {
        _atprotoClient.restoreSession(session);
        _did = session.did;
        _handle = session.handle;
        _deviceName = await _secureStorage.loadDeviceName();

        try {
          await _atprotoClient.refreshSession();
          await _secureStorage.saveSession(_atprotoClient.session!);
          moatLog('AuthService: Session refreshed successfully');
        } catch (e) {
          moatLog('AuthService: Failed to refresh session: $e');
          _state = AuthState.unauthenticated;
          return;
        }

        await _restoreMlsState();
        await _ensureKeysPublished();

        _state = AuthState.authenticated;
        await _initDrawbridge();
      } else {
        _state = AuthState.unauthenticated;
      }
    } catch (e) {
      moatLog('Failed to restore session: $e');
      _state = AuthState.unauthenticated;
    }
  }

  /// Login with handle, app password, and device name.
  Future<void> login(String handle, String password,
      {required String deviceName}) async {
    final session = await _atprotoClient.login(handle, password);
    await _secureStorage.saveSession(session);

    _did = session.did;
    _handle = session.handle;
    _deviceName = deviceName;

    await _secureStorage.saveDeviceName(deviceName);
    await _initializeMlsSession();
    await _ensureKeysPublished();

    _state = AuthState.authenticated;
    await _initDrawbridge();
  }

  /// Call when the app goes to background.
  ///
  /// Disconnects Drawbridge (if active) to free the socket.
  void suspend() {
    DrawbridgeService.instance.disconnectAll();
  }

  /// Call when the app returns to the foreground.
  ///
  /// Re-establishes the Drawbridge connection if authenticated.
  Future<void> resume() async {
    if (!isAuthenticated) return;
    await _initDrawbridge();
  }

  /// Connect to Drawbridge and publish own relay URL.
  ///
  /// URL resolution order:
  ///   1. [drawbridgeUrl] `"disabled"` → skip entirely
  ///   2. [drawbridgeUrl] non-null → explicit override
  ///   3. PDS-advertised via `com.atproto.server.describeServer`
  ///   4. [defaultDrawbridgeUrl] — hardcoded fallback
  ///
  /// Safe to call multiple times — DrawbridgeService is idempotent.
  Future<void> _initDrawbridge() async {
    if (drawbridgeUrl == "disabled" ||_did == null) return;

    final session = _atprotoClient.session;
    if (session == null) return;

    final keyBundle = await _secureStorage.loadKeyBundle();
    if (keyBundle == null) return;

    final pdsAdvertised = drawbridgeUrl == null
        ? await _atprotoClient.describeServerDrawbridgeUrl(session.pdsUrl)
        : null;
    final url = drawbridgeUrl ?? pdsAdvertised ?? defaultDrawbridgeUrl;

    if (drawbridgeUrl != null) {
      moatLog('AuthService: Using explicit drawbridge override: $url');
    } else if (pdsAdvertised != null) {
      moatLog('AuthService: Using PDS-advertised drawbridge: $url');
    } else {
      moatLog('AuthService: Using default drawbridge: $url');
    }

    DrawbridgeService.instance.init(did: _did!, keyBundle: keyBundle);
    unawaited(DrawbridgeService.instance.connectOwn(url));
    try {
      await _atprotoClient.publishDrawbridgeConfig(url);
    } catch (e) {
      moatLog('AuthService: Failed to publish drawbridge config: $e');
    }
  }

  /// Logout and clear all data.
  Future<void> logout() async {
    _atprotoClient.logout();
    await _secureStorage.clearAll();

    _moatSession = null;
    _did = null;
    _handle = null;
    _deviceName = null;
    _state = AuthState.unauthenticated;
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
    final hasStealthKeys = await _secureStorage.hasStealthKeypair();
    moatLog('AuthService: hasStealthKeys=$hasStealthKeys');
    if (!hasStealthKeys) {
      moatLog('AuthService: Generating and publishing stealth address...');
      await _generateAndPublishStealthAddress();
      moatLog('AuthService: Stealth address published');
    } else {
      await _ensureStealthAddressOnPds();
    }

    final keyBundle = await _secureStorage.loadKeyBundle();
    moatLog('AuthService: hasKeyBundle=${keyBundle != null}');
    if (keyBundle == null) {
      moatLog('AuthService: Generating and publishing key package...');
      await _generateAndPublishKeyPackage();
      moatLog('AuthService: Key package published');
    } else {
      moatLog('AuthService: Using existing key bundle');
    }
  }

  Future<void> _generateAndPublishStealthAddress() async {
    if (_deviceName == null) {
      throw StateError('Device name not set');
    }

    final keypair = generateStealthKeypair();

    await _secureStorage.saveStealthKeypair(
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
    );

    await _atprotoClient.publishStealthAddress(keypair.publicKey, _deviceName!);
  }

  Future<void> _ensureStealthAddressOnPds() async {
    if (_did == null || _deviceName == null) return;

    final stealthRecords = await _atprotoClient.fetchStealthAddresses(_did!);
    final hasOurAddress = stealthRecords.any((r) => r.deviceName == _deviceName);

    if (!hasOurAddress) {
      moatLog('AuthService: Our stealth address not on PDS, re-publishing...');
      final stealthPubkey = await _secureStorage.loadStealthPublicKey();
      if (stealthPubkey != null) {
        await _atprotoClient.publishStealthAddress(stealthPubkey, _deviceName!);
        moatLog('AuthService: Stealth address re-published for device $_deviceName');
      } else {
        moatLog('AuthService: ERROR - have private key but no public key stored');
      }
    } else {
      moatLog('AuthService: Stealth address already on PDS for device $_deviceName');
    }
  }

  /// Replenish the PDS key package after a Welcome has consumed the previous one.
  ///
  /// Reuses the existing signing key so all joined MLS groups remain usable.
  /// Does NOT replace the stored key bundle.
  Future<void> replenishKeyPackage() async {
    if (_moatSession == null || _did == null || _deviceName == null) {
      throw StateError('MLS session or device name not initialized');
    }
    final keyBundle = await _secureStorage.loadKeyBundle();
    if (keyBundle == null) {
      throw StateError('No key bundle available for replenishment');
    }
    final newKeyPackage = await _moatSession!.replenishKeyPackage(
      did: _did!,
      deviceName: _deviceName!,
      keyBundle: keyBundle,
    );
    await _atprotoClient.publishKeyPackage(newKeyPackage);
    await _saveMlsState();
  }

  Future<void> _generateAndPublishKeyPackage() async {
    if (_moatSession == null || _did == null || _deviceName == null) {
      throw StateError('MLS session or device name not initialized');
    }

    final result = await _moatSession!.generateKeyPackage(
      did: _did!,
      deviceName: _deviceName!,
    );

    await _secureStorage.saveKeyBundle(result.keyBundle);
    await _atprotoClient.publishKeyPackage(result.keyPackage);
    await _saveMlsState();
  }

  /// Save MLS state after operations.
  Future<void> saveMlsState() async {
    await _saveMlsState();
  }

  /// Get the current key bundle.
  Future<Uint8List?> getKeyBundle() async {
    return await _secureStorage.loadKeyBundle();
  }

  /// Get the stealth private key for decrypting invites.
  Future<Uint8List?> getStealthPrivateKey() async {
    return await _secureStorage.loadStealthPrivateKey();
  }

  /// Create a new conversation with a recipient.
  Future<CreateConversationResult> createConversation({
    required String recipientDid,
    required List<Uint8List> recipientStealthPubkeys,
    required Uint8List recipientKeyPackage,
  }) async {
    if (_moatSession == null || _did == null || _deviceName == null) {
      throw StateError('Not authenticated');
    }

    final keyBundle = await _secureStorage.loadKeyBundle();
    if (keyBundle == null) {
      throw StateError('No key bundle available');
    }

    final groupId = await _moatSession!.createGroup(
      did: _did!,
      deviceName: _deviceName!,
      keyBundle: keyBundle,
    );

    final welcomeResult = await _moatSession!.addMember(
      groupId: groupId,
      keyBundle: keyBundle,
      newMemberKeyPackage: recipientKeyPackage,
    );

    final envelope = encodeWelcomeEnvelope(welcomeResult.welcome);
    final stealthCiphertext = await encryptForStealth(
      recipientScanPubkeys: recipientStealthPubkeys,
      welcomeBytes: envelope,
    );

    final random = Random.secure();
    final randomTag = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      randomTag[i] = random.nextInt(256);
    }

    await _saveMlsState();

    return CreateConversationResult(
      groupId: groupId,
      randomTag: randomTag,
      stealthCiphertext: stealthCiphertext,
      epoch: 1,
    );
  }

  /// Process a Welcome message to join a conversation.
  Future<Uint8List> processWelcome(Uint8List welcomeBytes) async {
    if (_moatSession == null) {
      throw StateError('MLS session not initialized');
    }

    final groupId = await _moatSession!.processWelcome(welcomeBytes: welcomeBytes);
    await _saveMlsState();
    return groupId;
  }

  /// Try to decrypt a stealth-encrypted payload.
  Future<Uint8List?> tryDecryptStealthPayload(Uint8List ciphertext) async {
    final stealthPrivkey = await _secureStorage.loadStealthPrivateKey();
    if (stealthPrivkey == null) {
      return null;
    }
    return tryDecryptStealth(scanPrivkey: stealthPrivkey, payload: ciphertext);
  }

  /// Populate candidate tags for all members in a group.
  Future<void> populateConversationTags(Uint8List groupId) async {
    if (_moatSession == null) return;
    final tags = _moatSession!.populateCandidateTags(groupId: groupId);
    for (final tag in tags) {
      await registerTag(Uint8List.fromList(tag), groupId);
    }
  }

  /// Register a tag in the tag map.
  Future<void> registerTag(Uint8List tag, Uint8List groupId) async {
    final tagHex = _bytesToHex(tag);
    final groupIdHex = _bytesToHex(groupId);
    await _secureStorage.registerTag(tagHex, groupIdHex);
  }

  /// Look up a conversation by tag.
  Future<String?> lookupByTag(Uint8List tag) async {
    final tagHex = _bytesToHex(tag);
    return await _secureStorage.lookupByTag(tagHex);
  }

  /// Get all DIDs in a group (deduplicated).
  Future<List<String>> getGroupDids(Uint8List groupId) async {
    if (_moatSession == null) {
      throw StateError('MLS session not initialized');
    }
    return await _moatSession!.getGroupDids(groupId: groupId);
  }

  String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

/// Result of creating a conversation.
class CreateConversationResult {
  final Uint8List groupId;
  final Uint8List randomTag;
  final Uint8List stealthCiphertext;
  final int epoch;

  CreateConversationResult({
    required this.groupId,
    required this.randomTag,
    required this.stealthCiphertext,
    required this.epoch,
  });
}
