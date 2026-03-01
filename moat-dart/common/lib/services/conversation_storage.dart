import 'dart:convert';
import '../models/conversation.dart';
import 'document_backend.dart';

/// Local storage for conversations (non-sensitive metadata).
/// Uses a constructor-injected [DocumentBackend] — no path_provider dependency.
class ConversationStorage {
  static const _path = 'conversations/conversations.json';

  final DocumentBackend _backend;

  ConversationStorage({required DocumentBackend backend}) : _backend = backend;

  /// Load all conversations from storage.
  Future<List<Conversation>> loadAll() async {
    try {
      final contents = await _backend.read(_path);
      if (contents == null) return [];
      final list = jsonDecode(contents) as List<dynamic>;
      return list
          .map((e) => Conversation.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Save all conversations to storage.
  Future<void> saveAll(List<Conversation> conversations) async {
    final json = conversations.map((c) => c.toJson()).toList();
    await _backend.write(_path, jsonEncode(json));
  }

  /// Add or update a conversation.
  Future<void> save(Conversation conversation) async {
    final conversations = await loadAll();
    final index = conversations.indexWhere(
      (c) => _bytesEqual(c.groupId, conversation.groupId),
    );

    if (index >= 0) {
      conversations[index] = conversation;
    } else {
      conversations.add(conversation);
    }

    await saveAll(conversations);
  }

  /// Delete a conversation.
  Future<void> delete(List<int> groupId) async {
    final conversations = await loadAll();
    conversations.removeWhere((c) => _bytesEqual(c.groupId, groupId));
    await saveAll(conversations);
  }

  /// Find a conversation by group ID.
  Future<Conversation?> findByGroupId(List<int> groupId) async {
    final conversations = await loadAll();
    try {
      return conversations.firstWhere(
        (c) => _bytesEqual(c.groupId, groupId),
      );
    } catch (_) {
      return null;
    }
  }

  /// Clear all conversations.
  Future<void> clearAll() async {
    await _backend.delete(_path);
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
