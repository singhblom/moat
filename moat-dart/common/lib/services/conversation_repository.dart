import 'dart:math';
import 'dart:typed_data';
import '../models/message.dart';
import '../utils/value_listenable.dart';
import 'blob_service.dart';
import 'debug_log.dart';
import 'message_storage.dart';
import 'outbox_storage.dart';
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

  /// The source of each unpublished send, by localId. Also persisted, so a
  /// send interrupted by a restart comes back as a retryable failure.
  final Map<String, OutboxEntry> _outbox = {};
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

  /// Loads persisted messages, dropping stale sending/failed ones, and
  /// restores unpublished sends from the outbox.
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
      await _restoreOutbox();
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
    final entry = OutboxEntry(
      messageId: _newMessageId(),
      localId: 'local_${DateTime.now().microsecondsSinceEpoch}',
      timestamp: DateTime.now(),
      text: text,
    );
    _addPending(entry);
    _dispatch(entry);
    return entry.localId;
  }

  /// Sends an image with an optimistic copy. Returns its localId.
  String sendImage(Uint8List imageBytes, BlobService blobService) {
    final entry = OutboxEntry(
      messageId: _newMessageId(),
      localId: 'local_img_${DateTime.now().microsecondsSinceEpoch}',
      timestamp: DateTime.now(),
      image: imageBytes,
    );
    _addPending(entry);
    _dispatch(entry, blobService: blobService);
    return entry.localId;
  }

  /// The pending send with [localId], if it is still unpublished.
  Message? pendingMessage(String localId) {
    for (final m in _optimistic) {
      if (m.localId == localId) return m;
    }
    return null;
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

  /// Retries a failed send by localId or message id hex. An image needs
  /// [blobService] to upload with. Returns whether a send was restarted.
  bool retryMessage(String id, {BlobService? blobService}) {
    final entry = _outbox[id] ??
        _outbox.values.where((e) => e.messageIdHex == id).firstOrNull;
    if (entry == null || entry.sendError == null) return false;
    if (entry.image != null && blobService == null) return false;
    moatLog('ConversationRepository: retry ${entry.messageIdHex.substring(0, 8)}');

    final retried = entry.withError(null);
    _outbox[entry.localId] = retried;
    _enqueueWrite(() => _storage.outbox.put(groupIdHex, retried));
    _replacePending(entry.localId, (m) => m.withSendState(MessageStatus.sending));
    _dispatch(retried, blobService: blobService);
    return true;
  }

  /// Cancels a failed send.
  void cancelMessage(String localId) {
    sendQueue?.cancel(localId);
    final entry = _outbox.remove(localId);
    if (entry != null) {
      _enqueueWrite(() => _storage.outbox.delete(groupIdHex, entry.messageIdHex));
    }
    _optimistic.removeWhere((m) => m.localId == localId || m.id == localId);
    _notify();
  }

  /// Clears all messages (testing/debugging).
  Future<void> clearMessages() async {
    _persisted = [];
    _optimistic = [];
    final entries = _outbox.values.toList();
    _outbox.clear();
    _notify();
    await _storage.deleteMessages(groupIdHex);
    for (final e in entries) {
      await _storage.outbox.delete(groupIdHex, e.messageIdHex);
    }
  }

  void dispose() {
    _changes.dispose();
  }

  void _onSendSuccess(String localId, Message confirmed) {
    _optimistic.removeWhere((m) => m.localId == localId || m.id == localId);
    final entry = _outbox.remove(localId);
    if (entry != null) {
      _enqueueWrite(() => _storage.outbox.delete(groupIdHex, entry.messageIdHex));
    }
    _store([confirmed]);
    _notify();
  }

  void _onSendFailed(String localId, String error) {
    final entry = _outbox[localId];
    if (entry != null) {
      final failed = entry.withError(error);
      _outbox[localId] = failed;
      _enqueueWrite(() => _storage.outbox.put(groupIdHex, failed));
    }
    _replacePending(localId, (m) => m.withSendState(MessageStatus.failed, error));
  }

  static const _interrupted = 'interrupted before it was sent';

  static Uint8List _newMessageId() {
    final random = Random.secure();
    return Uint8List.fromList(List.generate(16, (_) => random.nextInt(256)));
  }

  /// Record a new send: its optimistic row, and its source in the outbox.
  void _addPending(OutboxEntry entry) {
    _outbox[entry.localId] = entry;
    _optimistic.add(_pendingRow(entry, MessageStatus.sending));
    _notify();
    _enqueueWrite(() => _storage.outbox.put(groupIdHex, entry));
  }

  void _dispatch(OutboxEntry entry, {BlobService? blobService}) {
    final queue = sendQueue;
    if (queue == null) {
      _onSendFailed(entry.localId, 'not logged in');
      return;
    }
    if (entry.image != null) {
      queue.sendImage(
        localId: entry.localId,
        messageId: entry.messageId,
        imageBytes: entry.image!,
        blobService: blobService!,
      );
    } else {
      queue.enqueue(PendingMessage(
        localId: entry.localId,
        text: entry.text!,
        messageId: entry.messageId,
      ));
    }
  }

  Message _pendingRow(OutboxEntry entry, MessageStatus status) => Message(
        id: entry.localId,
        localId: entry.localId,
        groupId: groupId,
        senderDid: '',
        content: entry.text ?? '[image]',
        timestamp: entry.timestamp,
        isOwn: true,
        status: status,
        messageId: entry.messageId,
        sendError: entry.sendError,
      );

  void _replacePending(String localId, Message Function(Message) update) {
    final index = _optimistic.indexWhere((m) => m.localId == localId);
    if (index >= 0) _optimistic[index] = update(_optimistic[index]);
    _notify();
  }

  /// Bring back sends left in the outbox by an earlier run. Sends are
  /// in-memory work, so one this run does not know of has nothing working
  /// on it: it comes back failed and retryable. One whose message was
  /// published after all is dropped.
  Future<void> _restoreOutbox() async {
    final published = _persisted.map((m) => m.messageIdHex).nonNulls.toSet();
    for (var entry in await _storage.outbox.load(groupIdHex)) {
      if (_outbox.containsKey(entry.localId)) continue;
      if (published.contains(entry.messageIdHex)) {
        await _storage.outbox.delete(groupIdHex, entry.messageIdHex);
        continue;
      }
      final interrupted = entry.sendError == null;
      if (interrupted) entry = entry.withError(_interrupted);
      // Recorded before any await, so an overlapping load skips it.
      _outbox[entry.localId] = entry;
      _optimistic.add(_pendingRow(entry, MessageStatus.failed));
      if (interrupted) {
        moatLog('ConversationRepository: ${entry.messageIdHex.substring(0, 8)} $_interrupted');
        await _storage.outbox.put(groupIdHex, entry);
      }
    }
  }

  void _notify() => _changes.value = _changes.value + 1;

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

    final held = _persisted.map((m) => m.messageIdHex).nonNulls.toSet();
    for (final msg in incoming) {
      final existingIdx = _persisted.indexWhere((m) => m.id == msg.id);
      if (existingIdx >= 0) {
        _persisted[existingIdx] = msg;
      } else if (MessageStorage.isRepublished(msg, held)) {
        continue;
      } else {
        _persisted.add(msg);
        if (msg.messageIdHex != null) held.add(msg.messageIdHex!);
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
