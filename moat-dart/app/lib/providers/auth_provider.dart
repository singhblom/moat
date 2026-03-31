import 'package:flutter/foundation.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// Provider for authentication and key management.
/// Thin [ChangeNotifier] wrapper around [AuthService].
class AuthProvider extends ChangeNotifier {
  final AuthService _service;

  AuthProvider({required AuthService service}) : _service = service;

  AuthState get state => _service.state;
  bool get isAuthenticated => _service.isAuthenticated;
  bool get isLoading => _service.isLoading;
  String? get did => _service.did;
  String? get handle => _service.handle;
  String? get deviceName => _service.deviceName;
  AtprotoClient get atprotoClient => _service.atprotoClient;
  MoatSessionHandle? get moatSession => _service.moatSession;
  SecureStorageService get secureStorage => _service.secureStorage;

  /// Exposes the underlying [AuthService] for services that need it directly.
  AuthService get service => _service;

  Future<void> init() async {
    await _service.init();
    notifyListeners();
  }

  Future<void> login(String handle, String password,
      {required String deviceName}) async {
    await _service.login(handle, password, deviceName: deviceName);
    notifyListeners();
  }

  Future<void> logout() async {
    await _service.logout();
    notifyListeners();
  }

  Future<void> saveMlsState() => _service.saveMlsState();

  Future<Uint8List?> getKeyBundle() => _service.getKeyBundle();

  Future<Uint8List?> getStealthPrivateKey() => _service.getStealthPrivateKey();

  Future<CreateConversationResult> createConversation({
    required String recipientDid,
    required List<Uint8List> recipientStealthPubkeys,
    required Uint8List recipientKeyPackage,
  }) =>
      _service.createConversation(
        recipientDid: recipientDid,
        recipientStealthPubkeys: recipientStealthPubkeys,
        recipientKeyPackage: recipientKeyPackage,
      );

  Future<Uint8List> processWelcome(Uint8List welcomeBytes) =>
      _service.processWelcome(welcomeBytes);

  Future<Uint8List?> tryDecryptStealthPayload(Uint8List ciphertext) =>
      _service.tryDecryptStealthPayload(ciphertext);

  Future<void> populateConversationTags(Uint8List groupId) =>
      _service.populateConversationTags(groupId);

  Future<void> registerTag(Uint8List tag, Uint8List groupId) =>
      _service.registerTag(tag, groupId);

  Future<String?> lookupByTag(Uint8List tag) => _service.lookupByTag(tag);

  Future<List<String>> getGroupDids(Uint8List groupId) =>
      _service.getGroupDids(groupId);
}
