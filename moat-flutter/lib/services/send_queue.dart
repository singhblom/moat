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
/// Owns a [SendService] reference. Not a ChangeNotifier — communicates
/// back to [ConversationRepository] via [onSent] and [onFailed] callbacks.
class SendQueue {
  final SendService _sendService;
  final Conversation _conversation;

  final List<PendingMessage> _queue = [];
  bool _isProcessing = false;

  /// Called when a message is successfully sent.
  void Function(String localId, Message confirmed)? onSent;

  /// Called when a message fails to send.
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

  /// Retry a failed message by localId. Resets it and restarts processing.
  void retry(String localId) {
    final index = _queue.indexWhere((p) => p.localId == localId);
    if (index < 0) {
      moatLog('SendQueue: No pending message found for retry: $localId');
      return;
    }
    _processQueue();
  }

  /// Cancel a pending message by localId.
  void cancel(String localId) {
    _queue.removeWhere((p) => p.localId == localId);
  }

  /// Send a reaction directly (no queuing — reactions are fire-and-forget
  /// from the queue's perspective, though the repository handles optimistic
  /// state).
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

  /// Process the queue sequentially. On success, calls [onSent]. On failure,
  /// calls [onFailed] and stops processing (the failed message stays at the
  /// front of the queue for retry).
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

        // Remove from queue before calling callback.
        _queue.removeAt(0);

        moatLog('SendQueue: Message sent successfully: ${sentMessage.id}');
        onSent?.call(pending.localId, sentMessage);
      } catch (e) {
        moatLog('SendQueue: Failed to send message: $e');
        onFailed?.call(pending.localId);
        // Stop processing — failed message stays at front for retry.
        break;
      }
    }

    _isProcessing = false;
  }
}
