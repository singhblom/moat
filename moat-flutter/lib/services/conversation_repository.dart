import 'package:flutter/foundation.dart';
import '../models/message.dart';
import 'message_storage.dart';
import 'send_queue.dart';
import 'debug_log.dart';

/// Single owner of all message state for a conversation.
///
/// All reads and writes go through this class. Storage writes are serialized
/// via [_enqueueWrite] so concurrent operations don't race. Replaces
/// [MessagesProvider] — the UI listens to this directly.
///
/// Lifecycle: created lazily by [ConversationManager] on first access.
/// Persisted messages are only loaded into memory when a screen calls
/// [loadMessages]; background polling appends directly to storage without
/// loading the full list, keeping inactive repos near-zero memory cost.
class ConversationRepository extends ChangeNotifier {
  final String groupIdHex;
  final Uint8List groupId;
  final MessageStorage _storage;
  final SendQueue sendQueue;

  List<Message> _persisted = [];
  List<Message> _optimistic = [];
  bool _loaded = false;
  bool _isLoading = false;
  String? _error;

  // Write serialization — chains futures so only one write runs at a time.
  Future<void>? _pendingWrite;

  ConversationRepository({
    required this.groupIdHex,
    required this.groupId,
    required MessageStorage storage,
    required this.sendQueue,
  }) : _storage = storage {
    // Wire SendQueue callbacks back to this repository.
    sendQueue.onSent = _onSendSuccess;
    sendQueue.onFailed = _onSendFailed;
  }

  // ---------------------------------------------------------------------------
  // Public getters
  // ---------------------------------------------------------------------------

  /// The merged view for the UI: persisted + optimistic, sorted by timestamp.
  /// If not loaded, returns only optimistic messages (for the brief period
  /// between screen open and loadMessages completing).
  List<Message> get messages {
    if (!_loaded) return List.unmodifiable(_optimistic);
    final merged = <Message>[];
    merged.addAll(_persisted);
    for (final opt in _optimistic) {
      // If the optimistic message has a messageId and a persisted message
      // shares it, the persisted version wins (echo arrived).
      if (opt.messageId != null &&
          _persisted.any((p) =>
              p.messageId != null &&
              _bytesEqual(p.messageId!, opt.messageId!))) {
        continue;
      }
      merged.add(opt);
    }
    merged.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return List.unmodifiable(merged);
  }

  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get isLoaded => _loaded;
  bool get isSending => sendQueue.isProcessing;
  bool get hasQueuedMessages => sendQueue.hasQueued;

  // ---------------------------------------------------------------------------
  // Load / unload (screen lifecycle)
  // ---------------------------------------------------------------------------

  /// Load persisted messages from disk. Called when the conversation screen
  /// opens. Drops any messages with status [sending] or [failed] — these are
  /// stale optimistic messages from a previous app session.
  Future<void> loadMessages() async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      var loaded = await _storage.loadMessages(groupIdHex);
      // Drop stale sending/failed messages from a previous session.
      loaded = loaded
          .where((m) =>
              m.status != MessageStatus.sending &&
              m.status != MessageStatus.failed)
          .toList();
      loaded.sort((a, b) => a.timestamp.compareTo(b.timestamp));
      _persisted = loaded;
      _loaded = true;
    } catch (e) {
      _error = e.toString();
    }

    _isLoading = false;
    notifyListeners();
  }

  /// Release persisted messages from memory. The repository stays alive in
  /// [ConversationManager] but uses near-zero memory. Called when the screen
  /// closes.
  void unloadMessages() {
    _persisted = [];
    _loaded = false;
    // Don't notify — no UI is listening after unload.
  }

  // ---------------------------------------------------------------------------
  // Polling entry points
  // ---------------------------------------------------------------------------

  /// Called by [ConversationManager] when polling delivers new messages.
  ///
  /// If loaded (screen open): merges into [_persisted] and saves to disk.
  /// If not loaded (background): appends directly to storage without loading
  /// the full message list.
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
      // Apply in-memory and persist.
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
      notifyListeners();
      await _enqueueWrite(() => _storage.saveMessages(groupIdHex, _persisted));
    } else {
      // Not loaded — toggle directly in storage.
      await _enqueueWrite(
        () => _storage.toggleReaction(
            groupIdHex, targetMessageId, emoji, senderDid),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Send flow
  // ---------------------------------------------------------------------------

  /// Called by the UI to send a message. Creates an optimistic message and
  /// enqueues it for sending. Returns the localId for tracking.
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
    notifyListeners();

    sendQueue.enqueue(PendingMessage(localId: localId, text: text));
    return localId;
  }

  /// Called by the UI to send a reaction.
  Future<void> sendReaction(Message targetMessage, String emoji) async {
    if (targetMessage.messageId == null) {
      moatLog('ConversationRepository: Cannot react to message without messageId');
      return;
    }

    // Apply optimistic toggle immediately.
    _toggleReactionLocally(targetMessage.id, emoji, 'self');

    // Delegate actual send to the send queue's service.
    try {
      await sendQueue.sendReaction(
        targetMessageId: targetMessage.messageId!,
        emoji: emoji,
      );
      // Persist the optimistic state.
      if (_loaded) {
        await _enqueueWrite(
            () => _storage.saveMessages(groupIdHex, _persisted));
      }
    } catch (e) {
      moatLog('ConversationRepository: Failed to send reaction: $e');
      // Revert the optimistic toggle.
      _toggleReactionLocally(targetMessage.id, emoji, 'self');
    }
  }

  /// Retry a failed message.
  void retryMessage(String localId) {
    final index = _optimistic.indexWhere(
        (m) => m.localId == localId || m.id == localId);
    if (index >= 0) {
      _optimistic[index] =
          _optimistic[index].copyWith(status: MessageStatus.sending);
      notifyListeners();
    }
    sendQueue.retry(localId);
  }

  /// Cancel a failed message — removes from optimistic list and send queue.
  void cancelMessage(String localId) {
    sendQueue.cancel(localId);
    _optimistic.removeWhere((m) => m.localId == localId || m.id == localId);
    notifyListeners();
  }

  /// Clear all messages (for testing/debugging).
  Future<void> clearMessages() async {
    _persisted = [];
    _optimistic = [];
    notifyListeners();
    await _storage.deleteMessages(groupIdHex);
  }

  // ---------------------------------------------------------------------------
  // SendQueue callbacks
  // ---------------------------------------------------------------------------

  void _onSendSuccess(String localId, Message confirmed) {
    // Update optimistic message with the confirmed data (including messageId).
    final index = _optimistic.indexWhere(
        (m) => m.localId == localId || m.id == localId);
    if (index >= 0) {
      _optimistic[index] = confirmed;
    }

    // If loaded, also add to persisted and remove from optimistic.
    if (_loaded) {
      _persisted.add(confirmed);
      _persisted.sort((a, b) => a.timestamp.compareTo(b.timestamp));
      _optimistic.removeWhere(
          (m) => m.localId == localId || m.id == localId);

      _enqueueWrite(() => _storage.appendMessage(groupIdHex, confirmed));
    } else {
      // Not loaded — persist directly and clear optimistic.
      _optimistic.removeWhere(
          (m) => m.localId == localId || m.id == localId);
      _enqueueWrite(() => _storage.appendMessage(groupIdHex, confirmed));
    }

    notifyListeners();
  }

  void _onSendFailed(String localId) {
    final index = _optimistic.indexWhere(
        (m) => m.localId == localId || m.id == localId);
    if (index >= 0) {
      _optimistic[index] =
          _optimistic[index].copyWith(status: MessageStatus.failed);
    }
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /// Merge incoming messages into the loaded [_persisted] list, deduplicating
  /// by message id. Also removes matching optimistic entries (by messageId).
  void _mergeIntoLoaded(List<Message> incoming) {
    var changed = false;

    for (final msg in incoming) {
      final existingIdx = _persisted.indexWhere((m) => m.id == msg.id);
      if (existingIdx >= 0) {
        _persisted[existingIdx] = msg;
        changed = true;
      } else {
        _persisted.add(msg);
        changed = true;
      }

      // If this message matches an optimistic entry by messageId, remove it.
      if (msg.messageId != null) {
        _optimistic.removeWhere((opt) =>
            opt.messageId != null &&
            _bytesEqual(opt.messageId!, msg.messageId!));
      }
    }

    if (changed) {
      _persisted.sort((a, b) => a.timestamp.compareTo(b.timestamp));
      notifyListeners();
    }
  }

  /// Toggle a reaction on a message in [_persisted] (optimistic local update).
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
    notifyListeners();
  }

  /// Serialize disk writes — chains futures so concurrent callers wait.
  Future<void> _enqueueWrite(Future<void> Function() op) {
    final prev = _pendingWrite ?? Future.value();
    final next = prev.then((_) => op()).catchError((e) {
      moatLog('ConversationRepository: Write error for $groupIdHex: $e');
      _error = 'Unable to save messages: $e';
      notifyListeners();
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
