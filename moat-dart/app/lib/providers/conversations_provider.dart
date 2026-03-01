import 'package:flutter/foundation.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// Provider for managing conversations list.
/// Thin [ChangeNotifier] wrapper around [ConversationsService].
class ConversationsProvider extends ChangeNotifier {
  final ConversationsService _service;

  ConversationsProvider({required ConversationsService service})
      : _service = service;

  List<Conversation> get conversations => _service.conversations;
  bool get isLoading => _service.isLoading;

  Future<void> init() async {
    await _service.init();
    notifyListeners();
  }

  Future<void> refresh() async {
    await _service.refresh();
    notifyListeners();
  }

  Future<void> saveConversation(Conversation conversation) async {
    await _service.saveConversation(conversation);
    notifyListeners();
  }

  Future<void> deleteConversation(List<int> groupId) async {
    await _service.deleteConversation(groupId);
    notifyListeners();
  }

  Conversation? findByGroupId(List<int> groupId) =>
      _service.findByGroupId(groupId);

  Future<void> updateLastMessage(
    List<int> groupId, {
    required String preview,
    required DateTime timestamp,
    bool incrementUnread = false,
  }) async {
    await _service.updateLastMessage(
      groupId,
      preview: preview,
      timestamp: timestamp,
      incrementUnread: incrementUnread,
    );
    notifyListeners();
  }

  Future<void> markAsRead(List<int> groupId) async {
    await _service.markAsRead(groupId);
    notifyListeners();
  }

  Future<void> updateConversation(
    List<int> groupId, {
    int? epoch,
    String? displayName,
  }) async {
    await _service.updateConversation(groupId, epoch: epoch, displayName: displayName);
    notifyListeners();
  }
}
