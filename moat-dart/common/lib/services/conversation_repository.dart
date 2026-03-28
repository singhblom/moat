import 'dart:typed_data';
import '../models/message.dart';
import 'blob_service.dart';
import 'message_storage.dart';
import 'send_queue.dart';
import 'debug_log.dart';

/// Single owner of all message state for a conversation.
///
/// All reads and writes go through this class. Storage writes are serialized
/// via [_enqueueWrite]. No Flutter dependency — no ChangeNotifier.
class ConversationRepository {
  final String groupIdHex;
  final Uint8List groupId;
  final MessageStorage _storage;
  final SendQueue sendQueue;

  List<Message> _persisted = [];
  List<Message> _optimistic = [];
  bool _loaded = false;
  bool _isLoading = false;
  String? _error;

  Future<void>? _pendingWrite;

  ConversationRepository({
    required this.groupIdHex,
    required this.groupId,
    required MessageStorage storage,
    required this.sendQueue,
  }) : _storage = storage {
    sendQueue.onSent = _onSendSuccess;
    sendQueue.onFailed = _onSendFailed;
  }

  /// The merged view: persisted + optimistic, sorted by rkey.
  List<Message> get messages {
    if (!_loaded) return List.unmodifiable(_optimistic);
    final merged = <Message>[];
    merged.addAll(_persisted);
    for (final opt in _optimistic) {
      if (opt.messageId != null &&
          _persisted.any((p) =>
              p.messageId != null &&
              _bytesEqual(p.messageId!, opt.messageId!))) {
        continue;
      }
      merged.add(opt);
    }
    merged.sort((a, b) => a.rkey.compareTo(b.rkey));
    return List.unmodifiable(merged);
  }

  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get isLoaded => _loaded;
  bool get isSending => sendQueue.isProcessing;
  bool get hasQueuedMessages => sendQueue.hasQueued;

  /// Load persisted messages from disk.
  Future<void> loadMessages() async {
    _isLoading = true;
    _error = null;

    try {
      var loaded = await _storage.loadMessages(groupIdHex);
      loaded = loaded
          .where((m) =>
              m.status != MessageStatus.sending &&
              m.status != MessageStatus.failed)
          .toList();
      loaded.sort((a, b) => a.rkey.compareTo(b.rkey));
      _persisted = loaded;
      _loaded = true;
    } catch (e) {
      _error = e.toString();
    }

    _isLoading = false;
  }

  /// Release persisted messages from memory.
  void unloadMessages() {
    _persisted = [];
    _loaded = false;
  }

  /// Called by [ConversationManager] when polling delivers new messages.
  Future<void> mergeFromPolling(List<Message> incoming) async {
    if (incoming.isEmpty) return;

    if (_loaded) {
      _mergeIntoLoaded(incoming);
      await _enqueueWrite(() => _storage.saveMessages(groupIdHex, _persisted));
    } else {
      await _enqueueWrite(
          () => _storage.appendMessages(groupIdHex, incoming));
    }
  }

  /// Called by [ConversationManager] when a reaction event arrives.
  Future<void> applyReaction(
      List<int> targetMessageId, String emoji, String senderDid) async {
    if (_loaded) {
      final targetHex = targetMessageId
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      final index =
          _persisted.indexWhere((m) => m.messageIdHex == targetHex);
      if (index < 0) return;

      final msg = _persisted[index];
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

      _persisted[index] = msg.copyWith(reactions: updatedReactions);
      await _enqueueWrite(() => _storage.saveMessages(groupIdHex, _persisted));
    } else {
      await _enqueueWrite(
        () => _storage.toggleReaction(
            groupIdHex, targetMessageId, emoji, senderDid),
      );
    }
  }

  /// Enqueue a message for async send. Returns the localId.
  String sendMessage(String text) {
    final localId = 'local_${DateTime.now().millisecondsSinceEpoch}';

    final optimisticMessage = Message(
      id: localId,
      localId: localId,
      groupId: groupId,
      senderDid: '',
      content: text,
      timestamp: DateTime.now(),
      isOwn: true,
      epoch: 0,
      status: MessageStatus.sending,
    );

    _optimistic.add(optimisticMessage);

    sendQueue.enqueue(PendingMessage(localId: localId, text: text));
    return localId;
  }

  /// Send a message and await the result. Used by the HTTP server.
  Future<Message> sendMessageSync(String text) async {
    final message = await sendQueue.sendDirect(text);
    await _enqueueWrite(() => _storage.appendMessage(groupIdHex, message));
    return message;
  }

  /// Send an image and await the result. Used by the HTTP server.
  Future<Message> sendImageSync(
      Uint8List imageBytes, BlobService blobService) async {
    final message = await sendQueue.sendImageDirect(imageBytes, blobService);
    await _enqueueWrite(() => _storage.appendMessage(groupIdHex, message));
    return message;
  }

  /// Send a reaction.
  Future<void> sendReaction(Message targetMessage, String emoji) async {
    if (targetMessage.messageId == null) {
      moatLog('ConversationRepository: Cannot react to message without messageId');
      return;
    }

    _toggleReactionLocally(targetMessage.id, emoji, 'self');

    try {
      await sendQueue.sendReaction(
        targetMessageId: targetMessage.messageId!,
        emoji: emoji,
      );
      if (_loaded) {
        await _enqueueWrite(
            () => _storage.saveMessages(groupIdHex, _persisted));
      }
    } catch (e) {
      moatLog('ConversationRepository: Failed to send reaction: $e');
      _toggleReactionLocally(targetMessage.id, emoji, 'self');
    }
  }

  void retryMessage(String localId) {
    sendQueue.retry(localId);
  }

  void cancelMessage(String localId) {
    sendQueue.cancel(localId);
    _optimistic.removeWhere((m) => m.localId == localId || m.id == localId);
  }

  Future<void> clearMessages() async {
    _persisted = [];
    _optimistic = [];
    await _storage.deleteMessages(groupIdHex);
  }

  void _onSendSuccess(String localId, Message confirmed) {
    _optimistic.removeWhere(
        (m) => m.localId == localId || m.id == localId);

    if (_loaded) {
      _persisted.add(confirmed);
      _persisted.sort((a, b) => a.rkey.compareTo(b.rkey));
      _enqueueWrite(() => _storage.appendMessage(groupIdHex, confirmed));
    } else {
      _enqueueWrite(() => _storage.appendMessage(groupIdHex, confirmed));
    }
  }

  void _onSendFailed(String localId) {
    final index = _optimistic.indexWhere(
        (m) => m.localId == localId || m.id == localId);
    if (index >= 0) {
      _optimistic[index] =
          _optimistic[index].copyWith(status: MessageStatus.failed);
    }
  }

  void _mergeIntoLoaded(List<Message> incoming) {
    for (final msg in incoming) {
      final existingIdx = _persisted.indexWhere((m) => m.id == msg.id);
      if (existingIdx >= 0) {
        _persisted[existingIdx] = msg;
      } else {
        _persisted.add(msg);
      }

      if (msg.messageId != null) {
        _optimistic.removeWhere((opt) =>
            opt.messageId != null &&
            _bytesEqual(opt.messageId!, msg.messageId!));
      }
    }

    _persisted.sort((a, b) => a.rkey.compareTo(b.rkey));
  }

  void _toggleReactionLocally(
      String messageId, String emoji, String senderDid) {
    final index = _persisted.indexWhere((m) => m.id == messageId);
    if (index < 0) return;

    final msg = _persisted[index];
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

    _persisted[index] = msg.copyWith(reactions: updatedReactions);
  }

  Future<void> _enqueueWrite(Future<void> Function() op) {
    final prev = _pendingWrite ?? Future.value();
    final next = prev.then((_) => op()).catchError((e) {
      moatLog('ConversationRepository: Write error for $groupIdHex: $e');
      _error = 'Unable to save messages: $e';
    });
    _pendingWrite = next;
    return next;
  }

  void dispose() {
    // No-op in plain Dart version (no listeners to remove).
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
