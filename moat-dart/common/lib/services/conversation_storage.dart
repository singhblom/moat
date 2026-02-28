import 'dart:convert';
import 'dart:io';
import '../models/conversation.dart';

/// Local storage for conversations (non-sensitive metadata).
/// Uses a constructor-injected [Directory] — no path_provider dependency.
class ConversationStorage {
  static const _fileName = 'conversations.json';

  final Directory directory;

  ConversationStorage({required this.directory});

  File get _file => File('${directory.path}/$_fileName');

  /// Load all conversations from disk.
  Future<List<Conversation>> loadAll() async {
    try {
      await directory.create(recursive: true);
      final file = _file;
      if (!await file.exists()) {
        return [];
      }
      final contents = await file.readAsString();
      final list = jsonDecode(contents) as List<dynamic>;
      return list
          .map((e) => Conversation.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Save all conversations to disk.
  Future<void> saveAll(List<Conversation> conversations) async {
    await directory.create(recursive: true);
    final json = conversations.map((c) => c.toJson()).toList();
    await _file.writeAsString(jsonEncode(json));
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
    final file = _file;
    if (await file.exists()) {
      await file.delete();
    }
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
