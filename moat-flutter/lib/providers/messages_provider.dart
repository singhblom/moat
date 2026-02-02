import 'dart:async';
import 'package:flutter/foundation.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../services/message_storage.dart';
import '../services/message_notifier.dart';
import '../services/send_service.dart';
import '../services/debug_log.dart';

/// A pending message waiting to be sent
class PendingMessage {
  final String localId;
  final String text;
  final Completer<Message> completer;

  PendingMessage({
    required this.localId,
    required this.text,
    required this.completer,
  });
}

/// Provider for messages in a specific conversation
class MessagesProvider extends ChangeNotifier {
  final String groupIdHex;
  final MessageStorage _storage;
  final Conversation _conversation;
  SendService? _sendService;

  List<Message> _messages = [];
  bool _isLoading = false;
  String? _error;
  bool _isSending = false;

  // Send queue for ordered message delivery
  final List<PendingMessage> _sendQueue = [];
  bool _isProcessingQueue = false;

  MessagesProvider(
    this.groupIdHex,
    this._conversation, {
    MessageStorage? storage,
  }) : _storage = storage ?? MessageStorage() {
    // Register to receive live message updates from polling
    MessageNotifier.instance.register(groupIdHex, addMessages);
  }

  @override
  void dispose() {
    MessageNotifier.instance.unregister(groupIdHex);
    super.dispose();
  }

  List<Message> get messages => _messages;
  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get isSending => _isSending;
  bool get hasQueuedMessages => _sendQueue.isNotEmpty;

  /// Initialize the send service (must be called before sending)
  void initSendService(SendService sendService) {
    _sendService = sendService;
  }

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

  /// Send a message (adds to queue and processes)
  Future<Message> sendMessage(String text) async {
    if (_sendService == null) {
      throw StateError('SendService not initialized');
    }

    // Generate local ID for tracking
    final localId = 'local_${DateTime.now().millisecondsSinceEpoch}';

    // Create optimistic message with sending status
    final optimisticMessage = Message(
      id: localId, // Temporary ID
      localId: localId,
      groupId: _conversation.groupId,
      senderDid: '', // Will be filled by send service
      content: text,
      timestamp: DateTime.now(),
      isOwn: true,
      epoch: _conversation.epoch,
      status: MessageStatus.sending,
    );

    // Add optimistic message to UI immediately
    _messages.add(optimisticMessage);
    _messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    notifyListeners();

    // Create completer for this message
    final completer = Completer<Message>();

    // Add to queue
    _sendQueue.add(PendingMessage(
      localId: localId,
      text: text,
      completer: completer,
    ));

    // Process queue
    _processQueue();

    return completer.future;
  }

  /// Process the send queue
  Future<void> _processQueue() async {
    if (_isProcessingQueue || _sendQueue.isEmpty) return;

    _isProcessingQueue = true;
    _isSending = true;
    notifyListeners();

    while (_sendQueue.isNotEmpty) {
      final pending = _sendQueue.first;

      try {
        moatLog('MessagesProvider: Processing send for ${pending.localId}');

        // Actually send the message
        final sentMessage = await _sendService!.sendMessage(
          conversation: _conversation,
          text: pending.text,
          localId: pending.localId,
        );

        // Replace optimistic message with real one
        _replaceMessage(pending.localId, sentMessage);

        // Persist to storage
        await _storage.appendMessage(groupIdHex, sentMessage);

        // Complete the future
        pending.completer.complete(sentMessage);

        // Remove from queue
        _sendQueue.removeAt(0);

        moatLog('MessagesProvider: Message sent successfully: ${sentMessage.id}');
      } catch (e) {
        moatLog('MessagesProvider: Failed to send message: $e');

        // Update message status to failed
        _updateMessageStatus(pending.localId, MessageStatus.failed);

        // Complete with error
        pending.completer.completeError(e);

        // Don't remove from queue - keep it for retry
        // But break the loop to stop processing
        break;
      }
    }

    _isProcessingQueue = false;
    _isSending = _sendQueue.isNotEmpty;
    notifyListeners();
  }

  /// Retry sending a failed message
  Future<void> retryMessage(String localId) async {
    // Find the pending message in the queue
    final pendingIndex = _sendQueue.indexWhere((p) => p.localId == localId);
    if (pendingIndex < 0) {
      moatLog('MessagesProvider: No pending message found for retry: $localId');
      return;
    }

    // Update status back to sending
    _updateMessageStatus(localId, MessageStatus.sending);

    // Create a new completer since the old one is already completed
    final oldPending = _sendQueue[pendingIndex];
    final newCompleter = Completer<Message>();
    _sendQueue[pendingIndex] = PendingMessage(
      localId: oldPending.localId,
      text: oldPending.text,
      completer: newCompleter,
    );

    // Process the queue
    _processQueue();
  }

  /// Cancel a failed message
  void cancelMessage(String localId) {
    // Remove from queue
    _sendQueue.removeWhere((p) => p.localId == localId);

    // Remove from messages
    _messages.removeWhere((m) => m.localId == localId || m.id == localId);
    notifyListeners();
  }

  /// Replace a message by local ID
  void _replaceMessage(String localId, Message newMessage) {
    final index = _messages.indexWhere(
      (m) => m.localId == localId || m.id == localId,
    );
    if (index >= 0) {
      _messages[index] = newMessage;
      _messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
      notifyListeners();
    }
  }

  /// Update message status by local ID
  void _updateMessageStatus(String localId, MessageStatus status) {
    final index = _messages.indexWhere(
      (m) => m.localId == localId || m.id == localId,
    );
    if (index >= 0) {
      _messages[index] = _messages[index].copyWith(status: status);
      notifyListeners();
    }
  }

  /// Add a single message (from polling)
  void addMessage(Message message) {
    // Check for duplicate by ID
    if (_messages.any((m) => m.id == message.id)) {
      return;
    }

    // Check if this is our own message that we already have locally
    // (received from another device or polling our own events)
    if (message.isOwn) {
      final existingIndex = _messages.indexWhere(
        (m) => m.localId != null && m.content == message.content && m.isOwn,
      );
      if (existingIndex >= 0) {
        // This is likely our own message coming back, skip it
        return;
      }
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
