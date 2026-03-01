import 'package:moat_dart_common/moat_dart_common.dart' hide ConversationManager, ConversationRepository;
import 'conversation_repository.dart';

/// Global singleton managing [ConversationRepository] lifecycle.
///
/// Replaces [MessageNotifier]. Lazily creates repositories on first access
/// (from either polling or screen navigation) and caches them. Polling always
/// routes through this manager so there is a single writer per conversation.
class ConversationManager {
  static final ConversationManager instance = ConversationManager._();
  ConversationManager._();

  final Map<String, ConversationRepository> _repos = {};

  MessageStorage? _storage;
  AuthService? _authService;

  /// Must be called once after authentication, before any repos are created.
  void init({
    AuthService? authService,
    MessageStorage? storage,
  }) {
    _authService = authService;
    if (storage != null) _storage = storage;
  }

  /// Get or lazily create a repository for a conversation.
  ConversationRepository getRepository(Conversation conversation) {
    return _repos.putIfAbsent(conversation.groupIdHex, () {
      SendQueue? sendQueue;
      if (_authService != null) {
        final sendService = SendService(authService: _authService!);
        sendQueue = SendQueue(
          sendService: sendService,
          conversation: conversation,
        );
      }
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

  /// Dispose a single repository (e.g., when a conversation is deleted).
  void remove(String groupIdHex) {
    _repos.remove(groupIdHex)?.dispose();
  }

  /// Dispose all repositories (e.g., on logout).
  void clear() {
    for (final repo in _repos.values) {
      repo.dispose();
    }
    _repos.clear();
  }
}
