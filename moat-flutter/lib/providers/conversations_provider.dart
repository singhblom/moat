import 'package:flutter/foundation.dart';
import '../models/conversation.dart';
import '../services/conversation_storage.dart';

/// Provider for managing conversations list
class ConversationsProvider extends ChangeNotifier {
  final ConversationStorage _storage;

  List<Conversation> _conversations = [];
  bool _isLoading = false;

  ConversationsProvider({ConversationStorage? storage})
      : _storage = storage ?? ConversationStorage();

  List<Conversation> get conversations => List.unmodifiable(_conversations);
  bool get isLoading => _isLoading;

  /// Initialize and load conversations from storage
  Future<void> init() async {
    _isLoading = true;
    notifyListeners();

    try {
      _conversations = await _storage.loadAll();
      _sortConversations();
    } catch (e) {
      debugPrint('Failed to load conversations: $e');
      _conversations = [];
    }

    _isLoading = false;
    notifyListeners();
  }

  /// Refresh conversations from storage
  Future<void> refresh() async {
    _isLoading = true;
    notifyListeners();

    try {
      _conversations = await _storage.loadAll();
      _sortConversations();
    } catch (e) {
      debugPrint('Failed to refresh conversations: $e');
    }

    _isLoading = false;
    notifyListeners();
  }

  /// Add or update a conversation
  Future<void> saveConversation(Conversation conversation) async {
    await _storage.save(conversation);

    final index = _conversations.indexWhere(
      (c) => _bytesEqual(c.groupId, conversation.groupId),
    );

    if (index >= 0) {
      _conversations[index] = conversation;
    } else {
      _conversations.add(conversation);
    }

    _sortConversations();
    notifyListeners();
  }

  /// Delete a conversation
  Future<void> deleteConversation(List<int> groupId) async {
    await _storage.delete(groupId);
    _conversations.removeWhere((c) => _bytesEqual(c.groupId, groupId));
    notifyListeners();
  }

  /// Find a conversation by group ID
  Conversation? findByGroupId(List<int> groupId) {
    try {
      return _conversations.firstWhere(
        (c) => _bytesEqual(c.groupId, groupId),
      );
    } catch (_) {
      return null;
    }
  }

  /// Update last message info for a conversation
  Future<void> updateLastMessage(
    List<int> groupId, {
    required String preview,
    required DateTime timestamp,
    bool incrementUnread = false,
  }) async {
    final conversation = findByGroupId(groupId);
    if (conversation == null) return;

    conversation.lastMessagePreview = preview;
    conversation.lastMessageAt = timestamp;
    if (incrementUnread) {
      conversation.unreadCount++;
    }

    await saveConversation(conversation);
  }

  /// Mark conversation as read
  Future<void> markAsRead(List<int> groupId) async {
    final conversation = findByGroupId(groupId);
    if (conversation == null) return;

    conversation.unreadCount = 0;
    await saveConversation(conversation);
  }

  void _sortConversations() {
    _conversations.sort((a, b) {
      final aTime = a.lastMessageAt ?? a.createdAt;
      final bTime = b.lastMessageAt ?? b.createdAt;
      return bTime.compareTo(aTime); // Most recent first
    });
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
