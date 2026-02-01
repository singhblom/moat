import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'atproto_client.dart';

/// Keys for secure storage
const _sessionKey = 'moat_session';
const _stealthPrivateKeyKey = 'moat_stealth_private_key';
const _stealthPublicKeyKey = 'moat_stealth_public_key';
const _keyBundleKey = 'moat_key_bundle';
const _mlsStateKey = 'moat_mls_state';
const _deviceNameKey = 'moat_device_name';
const _watchListKey = 'moat_watch_list';
const _lastRkeysKey = 'moat_last_rkeys';
const _tagMapKey = 'moat_tag_map';

/// Secure storage service for credentials and cryptographic keys
class SecureStorageService {
  final FlutterSecureStorage _storage;

  SecureStorageService({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                encryptedSharedPreferences: true,
              ),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  // --- Session management ---

  /// Save ATProto session
  Future<void> saveSession(AtprotoSession session) async {
    await _storage.write(
      key: _sessionKey,
      value: jsonEncode(session.toJson()),
    );
  }

  /// Load ATProto session
  Future<AtprotoSession?> loadSession() async {
    final json = await _storage.read(key: _sessionKey);
    if (json == null) return null;
    try {
      return AtprotoSession.fromJson(jsonDecode(json) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  /// Delete ATProto session
  Future<void> deleteSession() async {
    await _storage.delete(key: _sessionKey);
  }

  // --- Stealth key management ---

  /// Save stealth keypair
  Future<void> saveStealthKeypair({
    required Uint8List privateKey,
    required Uint8List publicKey,
  }) async {
    await Future.wait([
      _storage.write(
        key: _stealthPrivateKeyKey,
        value: base64Encode(privateKey),
      ),
      _storage.write(
        key: _stealthPublicKeyKey,
        value: base64Encode(publicKey),
      ),
    ]);
  }

  /// Load stealth private key
  Future<Uint8List?> loadStealthPrivateKey() async {
    final b64 = await _storage.read(key: _stealthPrivateKeyKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  /// Load stealth public key
  Future<Uint8List?> loadStealthPublicKey() async {
    final b64 = await _storage.read(key: _stealthPublicKeyKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  /// Check if stealth keypair exists
  Future<bool> hasStealthKeypair() async {
    final key = await _storage.read(key: _stealthPrivateKeyKey);
    return key != null;
  }

  /// Delete stealth keypair
  Future<void> deleteStealthKeypair() async {
    await Future.wait([
      _storage.delete(key: _stealthPrivateKeyKey),
      _storage.delete(key: _stealthPublicKeyKey),
    ]);
  }

  // --- Key bundle management ---

  /// Save MLS key bundle (private keys for key package)
  Future<void> saveKeyBundle(Uint8List keyBundle) async {
    await _storage.write(
      key: _keyBundleKey,
      value: base64Encode(keyBundle),
    );
  }

  /// Load MLS key bundle
  Future<Uint8List?> loadKeyBundle() async {
    final b64 = await _storage.read(key: _keyBundleKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  /// Delete key bundle
  Future<void> deleteKeyBundle() async {
    await _storage.delete(key: _keyBundleKey);
  }

  // --- Device name management ---

  /// Save device name
  Future<void> saveDeviceName(String deviceName) async {
    await _storage.write(key: _deviceNameKey, value: deviceName);
  }

  /// Load device name
  Future<String?> loadDeviceName() async {
    return await _storage.read(key: _deviceNameKey);
  }

  /// Check if device name exists
  Future<bool> hasDeviceName() async {
    final name = await _storage.read(key: _deviceNameKey);
    return name != null;
  }

  /// Delete device name
  Future<void> deleteDeviceName() async {
    await _storage.delete(key: _deviceNameKey);
  }

  // --- MLS state management ---

  /// Save MLS session state
  Future<void> saveMlsState(Uint8List state) async {
    await _storage.write(
      key: _mlsStateKey,
      value: base64Encode(state),
    );
  }

  /// Load MLS session state
  Future<Uint8List?> loadMlsState() async {
    final b64 = await _storage.read(key: _mlsStateKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  /// Delete MLS state
  Future<void> deleteMlsState() async {
    await _storage.delete(key: _mlsStateKey);
  }

  // --- Watch list management ---

  /// Save list of DIDs to watch for incoming invites
  Future<void> saveWatchList(List<String> dids) async {
    await _storage.write(
      key: _watchListKey,
      value: jsonEncode(dids),
    );
  }

  /// Load watch list
  Future<List<String>> loadWatchList() async {
    final json = await _storage.read(key: _watchListKey);
    if (json == null) return [];
    try {
      return (jsonDecode(json) as List<dynamic>).cast<String>();
    } catch (_) {
      return [];
    }
  }

  /// Add a DID to watch list
  Future<void> addToWatchList(String did) async {
    final list = await loadWatchList();
    if (!list.contains(did)) {
      list.add(did);
      await saveWatchList(list);
    }
  }

  /// Remove a DID from watch list
  Future<void> removeFromWatchList(String did) async {
    final list = await loadWatchList();
    list.remove(did);
    await saveWatchList(list);
  }

  /// Delete watch list
  Future<void> deleteWatchList() async {
    await _storage.delete(key: _watchListKey);
  }

  // --- Last rkeys management (for polling pagination) ---

  /// Save last seen rkey for a DID
  Future<void> saveLastRkey(String did, String rkey) async {
    final map = await loadLastRkeys();
    map[did] = rkey;
    await _storage.write(
      key: _lastRkeysKey,
      value: jsonEncode(map),
    );
  }

  /// Load all last rkeys
  Future<Map<String, String>> loadLastRkeys() async {
    final json = await _storage.read(key: _lastRkeysKey);
    if (json == null) return {};
    try {
      return (jsonDecode(json) as Map<String, dynamic>).cast<String, String>();
    } catch (_) {
      return {};
    }
  }

  /// Get last rkey for a specific DID
  Future<String?> getLastRkey(String did) async {
    final map = await loadLastRkeys();
    return map[did];
  }

  /// Delete last rkey for a specific DID
  Future<void> deleteLastRkey(String did) async {
    final map = await loadLastRkeys();
    map.remove(did);
    await _storage.write(
      key: _lastRkeysKey,
      value: jsonEncode(map),
    );
  }

  /// Delete all last rkeys
  Future<void> deleteLastRkeys() async {
    await _storage.delete(key: _lastRkeysKey);
  }

  // --- Tag map management (tag -> groupIdHex) ---

  /// Save tag map
  Future<void> saveTagMap(Map<String, String> tagMap) async {
    await _storage.write(
      key: _tagMapKey,
      value: jsonEncode(tagMap),
    );
  }

  /// Load tag map
  Future<Map<String, String>> loadTagMap() async {
    final json = await _storage.read(key: _tagMapKey);
    if (json == null) return {};
    try {
      return (jsonDecode(json) as Map<String, dynamic>).cast<String, String>();
    } catch (_) {
      return {};
    }
  }

  /// Register a tag for a conversation
  Future<void> registerTag(String tagHex, String groupIdHex) async {
    final map = await loadTagMap();
    map[tagHex] = groupIdHex;
    await saveTagMap(map);
  }

  /// Look up conversation by tag
  Future<String?> lookupByTag(String tagHex) async {
    final map = await loadTagMap();
    return map[tagHex];
  }

  /// Delete tag map
  Future<void> deleteTagMap() async {
    await _storage.delete(key: _tagMapKey);
  }

  // --- Full clear ---

  /// Delete all stored data
  Future<void> clearAll() async {
    await _storage.deleteAll();
  }
}
