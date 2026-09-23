import 'dart:async';
import 'dart:typed_data';
import '../models/conversation.dart';
import '../models/message.dart';
import 'blob_service.dart';
import 'send_service.dart';
import 'debug_log.dart';

/// A text send waiting in the queue.
class PendingMessage {
  final String localId;
  final String text;

  /// Published under this id on every attempt.
  final Uint8List messageId;

  PendingMessage({required this.localId, required this.text, required this.messageId});
}

/// Handles send orchestration: text is sent in order, images alongside.
///
/// Reports back to [ConversationRepository] via [onSent] and [onFailed].
/// A failed send leaves the queue, so later sends are not held behind it;
/// retrying enqueues it again.
class SendQueue {
  final SendService _sendService;
  final Conversation _conversation;

  final List<PendingMessage> _queue = [];
  bool _isProcessing = false;

  void Function(String localId, Message confirmed)? onSent;
  void Function(String localId, String error)? onFailed;

  SendQueue({
    required SendService sendService,
    required Conversation conversation,
  })  : _sendService = sendService,
        _conversation = conversation;

  bool get isProcessing => _isProcessing;
  bool get hasQueued => _queue.isNotEmpty;

  /// Enqueue a text send. Triggers processing immediately.
  void enqueue(PendingMessage pending) {
    _queue.add(pending);
    _processQueue();
  }

  /// Cancel a queued send by localId.
  void cancel(String localId) {
    _queue.removeWhere((p) => p.localId == localId);
  }

  /// Send an image now, reporting through [onSent] / [onFailed].
  Future<void> sendImage({
    required String localId,
    required Uint8List messageId,
    required Uint8List imageBytes,
    required BlobService blobService,
  }) async {
    try {
      final sent = await _sendService.sendImage(
        conversation: _conversation,
        imageBytes: imageBytes,
        localId: localId,
        messageId: messageId,
        blobService: blobService,
      );
      onSent?.call(localId, sent);
    } catch (e) {
      moatLog('SendQueue: Failed to send image $localId: $e');
      onFailed?.call(localId, e.toString());
    }
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

  Future<void> _processQueue() async {
    if (_isProcessing || _queue.isEmpty) return;

    _isProcessing = true;

    while (_queue.isNotEmpty) {
      final pending = _queue.removeAt(0);

      try {
        moatLog('SendQueue: Processing send for ${pending.localId}');

        final sentMessage = await _sendService.sendMessage(
          conversation: _conversation,
          text: pending.text,
          localId: pending.localId,
          messageId: pending.messageId,
        );

        moatLog('SendQueue: Message sent successfully: ${sentMessage.id}');
        onSent?.call(pending.localId, sentMessage);
      } catch (e) {
        moatLog('SendQueue: Failed to send message ${pending.localId}: $e');
        onFailed?.call(pending.localId, e.toString());
      }
    }

    _isProcessing = false;
  }
}
