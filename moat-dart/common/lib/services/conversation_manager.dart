import '../models/conversation.dart';
import '../models/message.dart';
import 'auth_service.dart';
import 'conversation_repository.dart';
import 'message_storage.dart';
import 'send_queue.dart';
import 'send_service.dart';

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

  /// Must be called once after authentication, before any repos are created.
  void init({
    required AuthService authService,
    required MessageStorage storage,
  }) {
    _authService = authService;
    _storage = storage;
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
    for (final repo in _repos.values) {
      repo.dispose();
    }
    _repos.clear();
  }
}
