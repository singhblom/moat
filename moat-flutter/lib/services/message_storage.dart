import 'dart:convert';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
import '../models/message.dart';

/// Local storage for messages (non-sensitive, already decrypted)
class MessageStorage {
  static const _dirName = 'messages';

  Directory? _dir;

  Future<Directory> _getDir() async {
    if (_dir != null) return _dir!;
    final appDir = await getApplicationDocumentsDirectory();
    _dir = Directory('${appDir.path}/$_dirName');
    if (!await _dir!.exists()) {
      await _dir!.create(recursive: true);
    }
    return _dir!;
  }

  File _getFileForGroup(Directory dir, String groupIdHex) {
    return File('${dir.path}/$groupIdHex.json');
  }

  /// Load all messages for a conversation
  Future<List<Message>> loadMessages(String groupIdHex) async {
    try {
      final dir = await _getDir();
      final file = _getFileForGroup(dir, groupIdHex);

      if (!await file.exists()) {
        return [];
      }

      final contents = await file.readAsString();
      final list = jsonDecode(contents) as List<dynamic>;
      return list
          .map((e) => Message.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Save all messages for a conversation
  Future<void> saveMessages(String groupIdHex, List<Message> messages) async {
    final dir = await _getDir();
    final file = _getFileForGroup(dir, groupIdHex);
    final json = messages.map((m) => m.toJson()).toList();
    await file.writeAsString(jsonEncode(json));
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
  Future<void> appendMessages(String groupIdHex, List<Message> newMessages) async {
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

  /// Delete messages for a conversation
  Future<void> deleteMessages(String groupIdHex) async {
    final dir = await _getDir();
    final file = _getFileForGroup(dir, groupIdHex);
    if (await file.exists()) {
      await file.delete();
    }
  }

  /// Clear all message storage
  Future<void> clearAll() async {
    final dir = await _getDir();
    if (await dir.exists()) {
      await dir.delete(recursive: true);
    }
  }
}
