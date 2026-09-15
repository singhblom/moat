import 'dart:typed_data';
import '../models/message.dart';
import '../utils/value_listenable.dart';
import 'blob_service.dart';
import 'debug_log.dart';
import 'message_storage.dart';
import 'send_queue.dart';

/// Owns a conversation's message state, for the app and the headless server.
///
/// Writes are serialized by [_enqueueWrite]. Messages are held in memory only
/// after [loadMessages]; otherwise new messages are appended to storage.
class ConversationRepository {
  final String groupIdHex;
  final Uint8List groupId;
  final MessageStorage _storage;
  final SendQueue? sendQueue;

  List<Message> _persisted = [];
  List<Message> _optimistic = [];
  bool _loaded = false;
  bool _isLoading = false;
  String? _error;

  Future<void>? _pendingWrite;

  /// Stored while [loadMessages] was reading; merged in when it finishes.
  final List<Message> _arrivedWhileLoading = [];

  final SimpleValueNotifier<int> _changes = SimpleValueNotifier(0);

  ConversationRepository({
    required this.groupIdHex,
    required this.groupId,
    required MessageStorage storage,
    this.sendQueue,
  }) : _storage = storage {
    sendQueue?.onSent = _onSendSuccess;
    sendQueue?.onFailed = _onSendFailed;
  }

  /// Bumped when [messages], [isLoading] or [error] may have changed.
  ValueListenable<int> get changes => _changes;

  /// Persisted messages in rkey order, then this device's pending sends.
  List<Message> get messages {
    if (!_loaded) return List.unmodifiable(_optimistic);
    // Skip a pending send whose persisted copy has arrived.
    final pending = _optimistic
        .where((opt) =>
            opt.messageId == null ||
            !_persisted.any((p) =>
                p.messageId != null &&
                _bytesEqual(p.messageId!, opt.messageId!)))
        .toList()
      ..sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return List.unmodifiable([..._persisted, ...pending]);
  }

  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get isLoaded => _loaded;
  bool get isSending => sendQueue?.isProcessing ?? false;
  bool get hasQueuedMessages => sendQueue?.hasQueued ?? false;

  /// Loads persisted messages, dropping stale sending/failed ones.
  Future<void> loadMessages() async {
    _isLoading = true;
    _error = null;
    _notify();

    try {
      // Let queued writes land first.
      await (_pendingWrite ?? Future<void>.value());
      var loaded = await _storage.loadMessages(groupIdHex);
      loaded = loaded
          .where((m) =>
              m.status != MessageStatus.sending &&
              m.status != MessageStatus.failed)
          .toList();
      loaded.sort((a, b) => a.rkey.compareTo(b.rkey));
      _persisted = loaded;
      _loaded = true;
      _mergeIntoLoaded(_arrivedWhileLoading);
      _arrivedWhileLoading.clear();
    } catch (e) {
      _error = e.toString();
    }

    _isLoading = false;
    _notify();
  }

  /// Releases persisted messages from memory.
  void unloadMessages() {
    _persisted = [];
    _loaded = false;
  }

  /// Stores messages delivered by polling.
  Future<void> mergeFromPolling(List<Message> incoming) async {
    if (incoming.isEmpty) return;
    await _store(incoming);
  }

  /// Applies a reaction delivered by polling.
  Future<void> applyReaction(
      List<int> targetMessageId, String emoji, String senderDid) async {
    if (_loaded) {
      final targetHex = targetMessageId
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      final index = _persisted.indexWhere((m) => m.messageIdHex == targetHex);
      if (index < 0) return;

      _persisted[index] = _toggled(_persisted[index], emoji, senderDid);
      _notify();
      await _saveLoaded();
    } else {
      await _enqueueWrite(
        () => _storage.toggleReaction(
            groupIdHex, targetMessageId, emoji, senderDid),
      );
    }
  }

  /// Sends through the queue with an optimistic copy. Returns its localId.
  String sendMessage(String text) {
    final localId = 'local_${DateTime.now().millisecondsSinceEpoch}';

    _optimistic.add(Message(
      id: localId,
      localId: localId,
      groupId: groupId,
      senderDid: '',
      content: text,
      timestamp: DateTime.now(),
      isOwn: true,
      status: MessageStatus.sending,
    ));
    _notify();

    sendQueue?.enqueue(PendingMessage(localId: localId, text: text));
    return localId;
  }

  /// Sends an image with an optimistic copy. Returns its localId.
  String sendImage(Uint8List imageBytes, BlobService blobService) {
    final localId = 'local_img_${DateTime.now().millisecondsSinceEpoch}';

    _optimistic.add(Message(
      id: localId,
      localId: localId,
      groupId: groupId,
      senderDid: '',
      content: '[image]',
      timestamp: DateTime.now(),
      isOwn: true,
      status: MessageStatus.sending,
    ));
    _notify();

    sendQueue?.sendImageDirect(imageBytes, blobService).then((sent) {
      _onSendSuccess(localId, sent);
    }).catchError((_) {
      _onSendFailed(localId);
    });

    return localId;
  }

  /// Sends and waits, without an optimistic copy (headless server).
  Future<Message> sendMessageSync(String text) async {
    final message = await _requireSendQueue().sendDirect(text);
    await _store([message]);
    return message;
  }

  /// Sends an image and waits, without an optimistic copy (headless server).
  Future<Message> sendImageSync(
      Uint8List imageBytes, BlobService blobService) async {
    final message =
        await _requireSendQueue().sendImageDirect(imageBytes, blobService);
    await _store([message]);
    return message;
  }

  /// Sends a reaction, toggling it locally first.
  Future<void> sendReaction(Message targetMessage, String emoji) async {
    if (targetMessage.messageId == null) {
      moatLog('ConversationRepository: Cannot react to message without messageId');
      return;
    }

    _toggleReactionLocally(targetMessage.id, emoji, 'self');

    try {
      await sendQueue?.sendReaction(
        targetMessageId: targetMessage.messageId!,
        emoji: emoji,
      );
      if (_loaded) await _saveLoaded();
    } catch (e) {
      moatLog('ConversationRepository: Failed to send reaction: $e');
      _toggleReactionLocally(targetMessage.id, emoji, 'self');
    }
  }

  /// Retries a failed send.
  void retryMessage(String localId) {
    final index = _optimistic
        .indexWhere((m) => m.localId == localId || m.id == localId);
    if (index >= 0) {
      _optimistic[index] =
          _optimistic[index].copyWith(status: MessageStatus.sending);
      _notify();
    }
    sendQueue?.retry(localId);
  }

  /// Cancels a failed send.
  void cancelMessage(String localId) {
    sendQueue?.cancel(localId);
    _optimistic.removeWhere((m) => m.localId == localId || m.id == localId);
    _notify();
  }

  /// Clears all messages (testing/debugging).
  Future<void> clearMessages() async {
    _persisted = [];
    _optimistic = [];
    _notify();
    await _storage.deleteMessages(groupIdHex);
  }

  void dispose() {
    _changes.dispose();
  }

  void _onSendSuccess(String localId, Message confirmed) {
    _optimistic.removeWhere((m) => m.localId == localId || m.id == localId);
    _store([confirmed]);
    _notify();
  }

  void _onSendFailed(String localId) {
    final index = _optimistic
        .indexWhere((m) => m.localId == localId || m.id == localId);
    if (index >= 0) {
      _optimistic[index] =
          _optimistic[index].copyWith(status: MessageStatus.failed);
    }
    _notify();
  }

  void _notify() => _changes.value = _changes.value + 1;

  SendQueue _requireSendQueue() {
    final queue = sendQueue;
    if (queue == null) {
      throw StateError('ConversationRepository $groupIdHex has no send queue');
    }
    return queue;
  }

  /// Stores new messages: in memory and saved when loaded, appended otherwise.
  Future<void> _store(List<Message> incoming) async {
    if (_loaded) {
      _mergeIntoLoaded(incoming);
      await _saveLoaded();
    } else {
      if (_isLoading) _arrivedWhileLoading.addAll(incoming);
      await _enqueueWrite(() => _storage.appendMessages(groupIdHex, incoming));
    }
  }

  /// Queues a save of a snapshot of the loaded messages.
  Future<void> _saveLoaded() {
    final snapshot = List<Message>.of(_persisted);
    return _enqueueWrite(() => _storage.saveMessages(groupIdHex, snapshot));
  }

  /// Merges into [_persisted] by id, dropping optimistic copies they confirm.
  void _mergeIntoLoaded(List<Message> incoming) {
    if (incoming.isEmpty) return;

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
    _notify();
  }

  void _toggleReactionLocally(
      String messageId, String emoji, String senderDid) {
    final index = _persisted.indexWhere((m) => m.id == messageId);
    if (index < 0) return;

    _persisted[index] = _toggled(_persisted[index], emoji, senderDid);
    _notify();
  }

  static Message _toggled(Message msg, String emoji, String senderDid) {
    final existing = msg.reactions
        .indexWhere((r) => r.emoji == emoji && r.senderDid == senderDid);
    final reactions = existing >= 0
        ? (List<Reaction>.of(msg.reactions)..removeAt(existing))
        : [...msg.reactions, Reaction(emoji: emoji, senderDid: senderDid)];
    return msg.copyWith(reactions: reactions);
  }

  Future<void> _enqueueWrite(Future<void> Function() op) {
    final prev = _pendingWrite ?? Future.value();
    final next = prev.then((_) => op()).catchError((e) {
      moatLog('ConversationRepository: Write error for $groupIdHex: $e');
      _error = 'Unable to save messages: $e';
      _notify();
    });
    _pendingWrite = next;
    return next;
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
