import 'dart:async';
import '../models/conversation.dart';
import '../models/message.dart';
import 'send_service.dart';
import 'debug_log.dart';

/// A message waiting in the send queue.
class PendingMessage {
  final String localId;
  final String text;

  PendingMessage({required this.localId, required this.text});
}

/// Handles send orchestration: queuing, sequential processing, retry.
///
/// Communicates back to [ConversationRepository] via [onSent] and [onFailed] callbacks.
class SendQueue {
  final SendService _sendService;
  final Conversation _conversation;

  final List<PendingMessage> _queue = [];
  bool _isProcessing = false;

  void Function(String localId, Message confirmed)? onSent;
  void Function(String localId)? onFailed;

  SendQueue({
    required SendService sendService,
    required Conversation conversation,
  })  : _sendService = sendService,
        _conversation = conversation;

  bool get isProcessing => _isProcessing;
  bool get hasQueued => _queue.isNotEmpty;

  /// Enqueue a message for sending. Triggers processing immediately.
  void enqueue(PendingMessage pending) {
    _queue.add(pending);
    _processQueue();
  }

  /// Retry a failed message by localId.
  void retry(String localId) {
    _processQueue();
  }

  /// Cancel a pending message by localId.
  void cancel(String localId) {
    _queue.removeWhere((p) => p.localId == localId);
  }

  /// Send a reaction directly (no queuing).
  Future<void> sendReaction({
    required List<int> targetMessageId,
    required String emoji,
  }) async {
    await _sendService.sendReaction(
      conversation: _conversation,
      targetMessageId: targetMessageId,
      emoji: emoji,
    );
  }

  /// Send a message directly, bypassing the queue. Returns the sent Message.
  /// Used by the HTTP server for synchronous send-and-wait semantics.
  Future<Message> sendDirect(String text) async {
    final localId = 'local_${DateTime.now().millisecondsSinceEpoch}';
    return await _sendService.sendMessage(
      conversation: _conversation,
      text: text,
      localId: localId,
    );
  }

  Future<void> _processQueue() async {
    if (_isProcessing || _queue.isEmpty) return;

    _isProcessing = true;

    while (_queue.isNotEmpty) {
      final pending = _queue.first;

      try {
        moatLog('SendQueue: Processing send for ${pending.localId}');

        final sentMessage = await _sendService.sendMessage(
          conversation: _conversation,
          text: pending.text,
          localId: pending.localId,
        );

        _queue.removeAt(0);

        moatLog('SendQueue: Message sent successfully: ${sentMessage.id}');
        onSent?.call(pending.localId, sentMessage);
      } catch (e) {
        moatLog('SendQueue: Failed to send message: $e');
        onFailed?.call(pending.localId);
        break;
      }
    }

    _isProcessing = false;
  }
}
