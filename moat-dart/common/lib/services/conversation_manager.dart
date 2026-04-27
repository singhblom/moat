import 'dart:async';

import '../models/conversation.dart';
import '../models/message.dart';
import 'auth_service.dart';
import 'conversation_repository.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'message_storage.dart';
import 'send_queue.dart';
import 'send_service.dart';
import 'sync_service.dart';

/// Global singleton managing [ConversationRepository] lifecycle.
///
/// Replaces MessagesProvider. Lazily creates repositories on first access.
/// No Flutter dependency — no ChangeNotifier.
class ConversationManager {
  static final ConversationManager instance = ConversationManager._();
  ConversationManager._();

  final Map<String, ConversationRepository> _repos = {};

  MessageStorage? _storage;
  AuthService? _authService;
  DeviceRingService? _ringService;
  SyncService? _syncService;
  Timer? _ringTickTimer;

  DeviceRingService get ringService => _ringService!;
  SyncService get syncService => _syncService!;

  /// Must be called once after authentication, before any repos are created.
  void init({
    required AuthService authService,
    required MessageStorage storage,
    required DeviceRingService ringService,
    required SyncService syncService,
    Duration ringTickInterval = const Duration(seconds: 30),
  }) {
    _authService = authService;
    _storage = storage;
    _ringService = ringService;
    _syncService = syncService;
    _ringTickTimer?.cancel();
    _ringTickTimer = Timer.periodic(ringTickInterval, (_) {
      ringService.tick().catchError((e) {
        moatLog('ConversationManager: ring tick failed: $e');
      });
    });
    // Fire one tick immediately so first-time ring setup doesn't wait.
    ringService.tick().catchError((e) {
      moatLog('ConversationManager: initial ring tick failed: $e');
    });
  }

  /// Get or lazily create a repository for a conversation.
  ConversationRepository getRepository(Conversation conversation) {
    return _repos.putIfAbsent(conversation.groupIdHex, () {
      final sendService = SendService(authService: _authService!);
      final sendQueue = SendQueue(
        sendService: sendService,
        conversation: conversation,
      );
      return ConversationRepository(
        groupIdHex: conversation.groupIdHex,
        groupId: conversation.groupId,
        storage: _storage!,
        sendQueue: sendQueue,
      );
    });
  }

  /// Called by [PollingService] when new messages arrive for a conversation.
  void notify(Conversation conversation, List<Message> messages) {
    getRepository(conversation).mergeFromPolling(messages);
  }

  /// Called by [PollingService] when a reaction event arrives.
  void notifyReaction(Conversation conversation, List<int> targetMessageId,
      String emoji, String senderDid) {
    getRepository(conversation)
        .applyReaction(targetMessageId, emoji, senderDid);
  }

  /// Dispose a single repository.
  void remove(String groupIdHex) {
    _repos.remove(groupIdHex)?.dispose();
  }

  /// Dispose all repositories (e.g., on logout).
  void clear() {
    _ringTickTimer?.cancel();
    _ringTickTimer = null;
    for (final repo in _repos.values) {
      repo.dispose();
    }
    _repos.clear();
  }
}
