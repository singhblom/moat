import 'dart:convert';
import 'package:web/web.dart' as web;
import '../models/conversation.dart';

/// Web localStorage-based storage for conversations
class ConversationStorage {
  static const _key = 'moat_conversations';

  /// Load all conversations from localStorage
  Future<List<Conversation>> loadAll() async {
    try {
      final json = web.window.localStorage.getItem(_key);
      if (json == null) return [];
      final list = jsonDecode(json) as List<dynamic>;
      return list
          .map((e) => Conversation.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Save all conversations to localStorage
  Future<void> saveAll(List<Conversation> conversations) async {
    final json = conversations.map((c) => c.toJson()).toList();
    web.window.localStorage.setItem(_key, jsonEncode(json));
  }

  /// Add or update a conversation
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

  /// Delete a conversation
  Future<void> delete(List<int> groupId) async {
    final conversations = await loadAll();
    conversations.removeWhere((c) => _bytesEqual(c.groupId, groupId));
    await saveAll(conversations);
  }

  /// Find a conversation by group ID
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

  /// Clear all conversations
  Future<void> clearAll() async {
    web.window.localStorage.removeItem(_key);
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
