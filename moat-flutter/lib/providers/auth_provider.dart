import 'dart:math';
import 'package:flutter/foundation.dart';
import '../services/atproto_client.dart';
import '../services/secure_storage.dart';
import '../services/debug_log.dart';
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

        // Try to refresh the session token (it may have expired)
        try {
          await _atprotoClient.refreshSession();
          // Save the refreshed session
          await _secureStorage.saveSession(_atprotoClient.session!);
          moatLog('AuthProvider: Session refreshed successfully');
        } catch (e) {
          moatLog('AuthProvider: Failed to refresh session: $e');
          // If refresh fails, the session is truly invalid - user must log in again
          _state = AuthState.unauthenticated;
          notifyListeners();
          return;
        }

        // Restore MLS state
        await _restoreMlsState();

        // Verify keys are published (may need to re-publish if PDS was cleared)
        await _ensureKeysPublished();

        _state = AuthState.authenticated;
      } else {
        _state = AuthState.unauthenticated;
      }
    } catch (e) {
      moatLog('Failed to restore session: $e');
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
    moatLog('AuthProvider: hasStealthKeys=$hasStealthKeys');
    if (!hasStealthKeys) {
      moatLog('AuthProvider: Generating and publishing stealth address...');
      await _generateAndPublishStealthAddress();
      moatLog('AuthProvider: Stealth address published');
    } else {
      // We have local stealth keys, but ensure our address is published on PDS
      await _ensureStealthAddressOnPds();
    }

    // Check if we have a key bundle (and thus published key package)
    final keyBundle = await _secureStorage.loadKeyBundle();
    moatLog('AuthProvider: hasKeyBundle=${keyBundle != null}');
    if (keyBundle == null) {
      moatLog('AuthProvider: Generating and publishing key package...');
      await _generateAndPublishKeyPackage();
      moatLog('AuthProvider: Key package published');
    } else {
      // We have a local key bundle, but we need to ensure OUR key package is on the PDS.
      // The existing key bundle might be from a previous session where publishing failed,
      // or the PDS might only have key packages from other devices.
      //
      // Since we can't easily parse MLS credentials in Dart to check device names,
      // we'll re-generate and publish a fresh key package. This ensures the Flutter
      // device's key package is definitely on the PDS.
      //
      // Note: This will create a new key package each time the app starts, but that's
      // acceptable for now - key packages are designed to be one-time-use anyway.
      moatLog('AuthProvider: Re-generating key package to ensure it is on PDS...');
      await _secureStorage.deleteKeyBundle();
      await _generateAndPublishKeyPackage();
      moatLog('AuthProvider: Key package published for device $_deviceName');

      // Also reset our own DID's rkey cursor so we don't miss welcome messages
      // that were published before we regenerated our key package
      if (_did != null) {
        moatLog('AuthProvider: Resetting own DID rkey cursor to catch any welcomes');
        await _secureStorage.deleteLastRkey(_did!);
      }
    }
  }

  Future<void> _generateAndPublishStealthAddress() async {
    if (_deviceName == null) {
      throw StateError('Device name not set');
    }

    // Generate stealth keypair using moat-core via FFI
    final keypair = generateStealthKeypair();

    // Save locally
    await _secureStorage.saveStealthKeypair(
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
    );

    // Publish to PDS with device name (v2: multi-device)
    await _atprotoClient.publishStealthAddress(keypair.publicKey, _deviceName!);
  }

  /// Ensure our stealth address is published on PDS (re-publish if missing)
  Future<void> _ensureStealthAddressOnPds() async {
    if (_did == null || _deviceName == null) {
      return;
    }

    // Fetch all stealth addresses for our DID
    final stealthRecords = await _atprotoClient.fetchStealthAddresses(_did!);

    // Check if our device's stealth address is already published
    final hasOurAddress = stealthRecords.any((r) => r.deviceName == _deviceName);

    if (!hasOurAddress) {
      moatLog('AuthProvider: Our stealth address not on PDS, re-publishing...');

      // Load our existing public key
      final stealthPubkey = await _secureStorage.loadStealthPublicKey();
      if (stealthPubkey != null) {
        await _atprotoClient.publishStealthAddress(stealthPubkey, _deviceName!);
        moatLog('AuthProvider: Stealth address re-published for device $_deviceName');
      } else {
        moatLog('AuthProvider: ERROR - have private key but no public key stored');
      }
    } else {
      moatLog('AuthProvider: Stealth address already on PDS for device $_deviceName');
    }
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

  /// Get the current key bundle
  Future<Uint8List?> getKeyBundle() async {
    return await _secureStorage.loadKeyBundle();
  }

  /// Get the stealth private key for decrypting invites
  Future<Uint8List?> getStealthPrivateKey() async {
    return await _secureStorage.loadStealthPrivateKey();
  }

  /// Create a new conversation with a recipient
  /// Returns the group ID and welcome ciphertext (stealth-encrypted for all devices)
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

    // Create MLS group
    final groupId = await _moatSession!.createGroup(
      did: _did!,
      deviceName: _deviceName!,
      keyBundle: keyBundle,
    );

    // Add recipient to group (generates Welcome message)
    final welcomeResult = await _moatSession!.addMember(
      groupId: groupId,
      keyBundle: keyBundle,
      newMemberKeyPackage: recipientKeyPackage,
    );

    // Encrypt Welcome for ALL of recipient's devices using key encapsulation
    // This allows any of their devices to decrypt and join the conversation
    final stealthCiphertext = await encryptForStealth(
      recipientScanPubkeys: recipientStealthPubkeys,
      welcomeBytes: welcomeResult.welcome,
    );

    // Generate random 16-byte tag for the invite
    final random = Random.secure();
    final randomTag = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      randomTag[i] = random.nextInt(256);
    }

    // Save MLS state
    await _saveMlsState();

    return CreateConversationResult(
      groupId: groupId,
      randomTag: randomTag,
      stealthCiphertext: stealthCiphertext,
      epoch: 1, // After adding first member, epoch is 1
    );
  }

  /// Process a Welcome message to join a conversation
  /// Returns the group ID
  Future<Uint8List> processWelcome(Uint8List welcomeBytes) async {
    if (_moatSession == null) {
      throw StateError('MLS session not initialized');
    }

    final groupId = await _moatSession!.processWelcome(welcomeBytes: welcomeBytes);
    await _saveMlsState();
    return groupId;
  }

  /// Try to decrypt a stealth-encrypted payload
  /// Returns the decrypted bytes if successful, null if not for us
  Future<Uint8List?> tryDecryptStealthPayload(Uint8List ciphertext) async {
    final stealthPrivkey = await _secureStorage.loadStealthPrivateKey();
    if (stealthPrivkey == null) {
      return null;
    }
    return tryDecryptStealth(scanPrivkey: stealthPrivkey, payload: ciphertext);
  }

  /// Derive a conversation tag from group ID and epoch
  Uint8List deriveConversationTag(Uint8List groupId, int epoch) {
    return deriveTag(groupId: groupId, epoch: BigInt.from(epoch));
  }

  /// Register a tag in the tag map
  Future<void> registerTag(Uint8List tag, Uint8List groupId) async {
    final tagHex = _bytesToHex(tag);
    final groupIdHex = _bytesToHex(groupId);
    await _secureStorage.registerTag(tagHex, groupIdHex);
  }

  /// Look up a conversation by tag
  Future<String?> lookupByTag(Uint8List tag) async {
    final tagHex = _bytesToHex(tag);
    return await _secureStorage.lookupByTag(tagHex);
  }

  /// Get all DIDs in a group (deduplicated)
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

/// Result of creating a conversation
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
