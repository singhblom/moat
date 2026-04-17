import 'dart:convert';
import 'dart:typed_data';
import 'atproto_client.dart';
import 'storage_backend.dart';

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
const _deviceIdKey = 'moat_device_id';

/// Secure storage service for credentials and cryptographic keys.
/// Backend-agnostic: use [FileStorageBackend] for server, FlutterStorageBackend for app.
class SecureStorageService {
  final StorageBackend _storage;

  SecureStorageService({required StorageBackend storage}) : _storage = storage;

  // --- Session management ---

  Future<void> saveSession(AtprotoSession session) async {
    await _storage.write(_sessionKey, jsonEncode(session.toJson()));
  }

  Future<AtprotoSession?> loadSession() async {
    final json = await _storage.read(_sessionKey);
    if (json == null) return null;
    try {
      return AtprotoSession.fromJson(jsonDecode(json) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  Future<void> deleteSession() async {
    await _storage.delete(_sessionKey);
  }

  // --- Stealth key management ---

  Future<void> saveStealthKeypair({
    required Uint8List privateKey,
    required Uint8List publicKey,
  }) async {
    await Future.wait([
      _storage.write(_stealthPrivateKeyKey, base64Encode(privateKey)),
      _storage.write(_stealthPublicKeyKey, base64Encode(publicKey)),
    ]);
  }

  Future<Uint8List?> loadStealthPrivateKey() async {
    final b64 = await _storage.read(_stealthPrivateKeyKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  Future<Uint8List?> loadStealthPublicKey() async {
    final b64 = await _storage.read(_stealthPublicKeyKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  Future<bool> hasStealthKeypair() async {
    final key = await _storage.read(_stealthPrivateKeyKey);
    return key != null;
  }

  Future<void> deleteStealthKeypair() async {
    await Future.wait([
      _storage.delete(_stealthPrivateKeyKey),
      _storage.delete(_stealthPublicKeyKey),
    ]);
  }

  // --- Key bundle management ---

  Future<void> saveKeyBundle(Uint8List keyBundle) async {
    await _storage.write(_keyBundleKey, base64Encode(keyBundle));
  }

  Future<Uint8List?> loadKeyBundle() async {
    final b64 = await _storage.read(_keyBundleKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  Future<void> deleteKeyBundle() async {
    await _storage.delete(_keyBundleKey);
  }

  // --- Device name management ---

  Future<void> saveDeviceName(String deviceName) async {
    await _storage.write(_deviceNameKey, deviceName);
  }

  Future<String?> loadDeviceName() async {
    return await _storage.read(_deviceNameKey);
  }

  Future<bool> hasDeviceName() async {
    final name = await _storage.read(_deviceNameKey);
    return name != null;
  }

  Future<void> deleteDeviceName() async {
    await _storage.delete(_deviceNameKey);
  }

  // --- MLS state management ---

  Future<void> saveMlsState(Uint8List state) async {
    await _storage.write(_mlsStateKey, base64Encode(state));
  }

  Future<Uint8List?> loadMlsState() async {
    final b64 = await _storage.read(_mlsStateKey);
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  Future<void> deleteMlsState() async {
    await _storage.delete(_mlsStateKey);
  }

  // --- Watch list management ---

  Future<void> saveWatchList(List<String> dids) async {
    await _storage.write(_watchListKey, jsonEncode(dids));
  }

  Future<List<String>> loadWatchList() async {
    final json = await _storage.read(_watchListKey);
    if (json == null) return [];
    try {
      return (jsonDecode(json) as List<dynamic>).cast<String>();
    } catch (_) {
      return [];
    }
  }

  Future<void> addToWatchList(String did) async {
    final list = await loadWatchList();
    if (!list.contains(did)) {
      list.add(did);
      await saveWatchList(list);
    }
  }

  Future<void> removeFromWatchList(String did) async {
    final list = await loadWatchList();
    list.remove(did);
    await saveWatchList(list);
  }

  Future<void> deleteWatchList() async {
    await _storage.delete(_watchListKey);
  }

  // --- Last rkeys management (for polling pagination) ---

  Future<void> saveLastRkey(String did, String rkey) async {
    final map = await loadLastRkeys();
    map[did] = rkey;
    await _storage.write(_lastRkeysKey, jsonEncode(map));
  }

  Future<Map<String, String>> loadLastRkeys() async {
    final json = await _storage.read(_lastRkeysKey);
    if (json == null) return {};
    try {
      return (jsonDecode(json) as Map<String, dynamic>).cast<String, String>();
    } catch (_) {
      return {};
    }
  }

  Future<String?> getLastRkey(String did) async {
    final map = await loadLastRkeys();
    return map[did];
  }

  Future<void> deleteLastRkey(String did) async {
    final map = await loadLastRkeys();
    map.remove(did);
    await _storage.write(_lastRkeysKey, jsonEncode(map));
  }

  Future<void> deleteLastRkeys() async {
    await _storage.delete(_lastRkeysKey);
  }

  // --- Tag map management (tag -> groupIdHex) ---

  Future<void> saveTagMap(Map<String, String> tagMap) async {
    await _storage.write(_tagMapKey, jsonEncode(tagMap));
  }

  Future<Map<String, String>> loadTagMap() async {
    final json = await _storage.read(_tagMapKey);
    if (json == null) return {};
    try {
      return (jsonDecode(json) as Map<String, dynamic>).cast<String, String>();
    } catch (_) {
      return {};
    }
  }

  Future<void> registerTag(String tagHex, String groupIdHex) async {
    final map = await loadTagMap();
    map[tagHex] = groupIdHex;
    await saveTagMap(map);
  }

  Future<String?> lookupByTag(String tagHex) async {
    final map = await loadTagMap();
    return map[tagHex];
  }

  Future<void> deleteTagMap() async {
    await _storage.delete(_tagMapKey);
  }

  // --- Device ID management ---

  Future<void> saveDeviceId(String deviceId) async {
    await _storage.write(_deviceIdKey, deviceId);
  }

  Future<String?> loadDeviceId() async {
    return await _storage.read(_deviceIdKey);
  }

  // --- Full clear ---

  Future<void> clearAll() async {
    await _storage.deleteAll();
  }
}
