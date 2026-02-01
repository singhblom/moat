import 'package:flutter/foundation.dart';
import '../models/message.dart';
import '../services/message_storage.dart';

/// Provider for messages in a specific conversation
class MessagesProvider extends ChangeNotifier {
  final String groupIdHex;
  final MessageStorage _storage;

  List<Message> _messages = [];
  bool _isLoading = false;
  String? _error;

  MessagesProvider(this.groupIdHex, {MessageStorage? storage})
      : _storage = storage ?? MessageStorage();

  List<Message> get messages => _messages;
  bool get isLoading => _isLoading;
  String? get error => _error;

  /// Load messages from storage
  Future<void> loadMessages() async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      _messages = await _storage.loadMessages(groupIdHex);
      // Ensure sorted by timestamp
      _messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    } catch (e) {
      _error = e.toString();
    }

    _isLoading = false;
    notifyListeners();
  }

  /// Add a single message (from polling)
  void addMessage(Message message) {
    // Check for duplicate
    if (_messages.any((m) => m.id == message.id)) {
      return;
    }

    _messages.add(message);
    _messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    notifyListeners();

    // Persist in background
    _storage.appendMessage(groupIdHex, message);
  }

  /// Add multiple messages (from polling)
  void addMessages(List<Message> newMessages) {
    if (newMessages.isEmpty) return;

    final existingIds = _messages.map((m) => m.id).toSet();
    var added = false;

    for (final message in newMessages) {
      if (!existingIds.contains(message.id)) {
        _messages.add(message);
        added = true;
      }
    }

    if (added) {
      _messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
      notifyListeners();

      // Persist in background
      _storage.appendMessages(groupIdHex, newMessages);
    }
  }

  /// Clear all messages (for testing/debugging)
  Future<void> clearMessages() async {
    _messages = [];
    notifyListeners();
    await _storage.deleteMessages(groupIdHex);
  }
}
