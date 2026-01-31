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

  // --- Full clear ---

  /// Delete all stored data
  Future<void> clearAll() async {
    await _storage.deleteAll();
  }
}
