import 'dart:convert';
import 'package:web/web.dart' as web;
import '../models/message.dart';

/// Web localStorage-based storage for messages
class MessageStorage {
  static const _prefix = 'moat_messages_';

  String _keyFor(String groupIdHex) => '$_prefix$groupIdHex';

  /// Load all messages for a conversation
  Future<List<Message>> loadMessages(String groupIdHex) async {
    try {
      final json = web.window.localStorage.getItem(_keyFor(groupIdHex));
      if (json == null) return [];
      final list = jsonDecode(json) as List<dynamic>;
      return list
          .map((e) => Message.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Save all messages for a conversation
  Future<void> saveMessages(String groupIdHex, List<Message> messages) async {
    final json = messages.map((m) => m.toJson()).toList();
    web.window.localStorage.setItem(_keyFor(groupIdHex), jsonEncode(json));
  }

  /// Append a single message efficiently
  Future<void> appendMessage(String groupIdHex, Message message) async {
    final messages = await loadMessages(groupIdHex);

    // Check for duplicate by ID
    if (messages.any((m) => m.id == message.id)) {
      return; // Already exists
    }

    messages.add(message);
    // Sort by timestamp
    messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    await saveMessages(groupIdHex, messages);
  }

  /// Append multiple messages efficiently
  Future<void> appendMessages(
      String groupIdHex, List<Message> newMessages) async {
    if (newMessages.isEmpty) return;

    final messages = await loadMessages(groupIdHex);
    final existingIds = messages.map((m) => m.id).toSet();

    // Add only new messages
    for (final message in newMessages) {
      if (!existingIds.contains(message.id)) {
        messages.add(message);
      }
    }

    // Sort by timestamp
    messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    await saveMessages(groupIdHex, messages);
  }

  /// Toggle a reaction on a message. If the same (senderDid, emoji) exists, remove it; otherwise add it.
  /// Returns the updated message, or null if the target message was not found.
  Future<Message?> toggleReaction(String groupIdHex, List<int> targetMessageId, String emoji, String senderDid) async {
    final messages = await loadMessages(groupIdHex);
    final targetHex = targetMessageId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

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
      updatedReactions = [...msg.reactions, Reaction(emoji: emoji, senderDid: senderDid)];
    }

    final updated = msg.copyWith(reactions: updatedReactions);
    messages[index] = updated;
    await saveMessages(groupIdHex, messages);
    return updated;
  }

  /// Delete messages for a conversation
  Future<void> deleteMessages(String groupIdHex) async {
    web.window.localStorage.removeItem(_keyFor(groupIdHex));
  }

  /// Clear all message storage
  Future<void> clearAll() async {
    final storage = web.window.localStorage;
    final keysToRemove = <String>[];
    for (var i = 0; i < storage.length; i++) {
      final key = storage.key(i);
      if (key != null && key.startsWith(_prefix)) {
        keysToRemove.add(key);
      }
    }
    for (final key in keysToRemove) {
      storage.removeItem(key);
    }
  }
}
