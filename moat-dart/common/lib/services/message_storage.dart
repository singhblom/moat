import 'dart:convert';
import '../models/message.dart';
import 'document_backend.dart';

/// Local storage for messages (non-sensitive, already decrypted).
/// Uses a constructor-injected [DocumentBackend] — no path_provider dependency.
class MessageStorage {
  static const _dirPrefix = 'messages';

  final DocumentBackend _backend;

  MessageStorage({required DocumentBackend backend}) : _backend = backend;

  String _pathFor(String groupIdHex) => '$_dirPrefix/$groupIdHex.json';

  /// Load all messages for a conversation.
  Future<List<Message>> loadMessages(String groupIdHex) async {
    try {
      final contents = await _backend.read(_pathFor(groupIdHex));
      if (contents == null) return [];
      final list = jsonDecode(contents) as List<dynamic>;
      return list
          .map((e) => Message.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Save all messages for a conversation.
  Future<void> saveMessages(String groupIdHex, List<Message> messages) async {
    final json = messages.map((m) => m.toJson()).toList();
    await _backend.write(_pathFor(groupIdHex), jsonEncode(json));
  }

  /// Append a single message efficiently.
  Future<void> appendMessage(String groupIdHex, Message message) async {
    final messages = await loadMessages(groupIdHex);

    if (messages.any((m) => m.id == message.id)) {
      return; // Already exists
    }

    messages.add(message);
    messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    await saveMessages(groupIdHex, messages);
  }

  /// Append multiple messages efficiently.
  Future<void> appendMessages(
      String groupIdHex, List<Message> newMessages) async {
    if (newMessages.isEmpty) return;

    final messages = await loadMessages(groupIdHex);
    final existingIds = messages.map((m) => m.id).toSet();

    for (final message in newMessages) {
      if (!existingIds.contains(message.id)) {
        messages.add(message);
      }
    }

    messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    await saveMessages(groupIdHex, messages);
  }

  /// Toggle a reaction on a message. Returns the updated message, or null if
  /// the target message was not found.
  Future<Message?> toggleReaction(String groupIdHex, List<int> targetMessageId,
      String emoji, String senderDid) async {
    final messages = await loadMessages(groupIdHex);
    final targetHex =
        targetMessageId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    final index = messages.indexWhere((m) => m.messageIdHex == targetHex);
    if (index < 0) return null;

    final msg = messages[index];
    final existing = msg.reactions.indexWhere(
      (r) => r.emoji == emoji && r.senderDid == senderDid,
    );

    List<Reaction> updatedReactions;
    if (existing >= 0) {
      updatedReactions = List.of(msg.reactions)..removeAt(existing);
    } else {
      updatedReactions = [
        ...msg.reactions,
        Reaction(emoji: emoji, senderDid: senderDid),
      ];
    }

    final updated = msg.copyWith(reactions: updatedReactions);
    messages[index] = updated;
    await saveMessages(groupIdHex, messages);
    return updated;
  }

  /// Delete messages for a conversation.
  Future<void> deleteMessages(String groupIdHex) async {
    await _backend.delete(_pathFor(groupIdHex));
  }

  /// Clear all message storage.
  Future<void> clearAll() async {
    final paths = await _backend.list(_dirPrefix);
    for (final path in paths) {
      await _backend.delete(path);
    }
  }
}
