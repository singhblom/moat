import '../models/message.dart';

/// Singleton that routes incoming messages to active MessagesProviders.
///
/// This bridges the gap between PollingService (app-level) and
/// MessagesProvider (per-conversation, created on navigation).
class MessageNotifier {
  static final MessageNotifier instance = MessageNotifier._();
  MessageNotifier._();

  final Map<String, void Function(List<Message>)> _listeners = {};

  /// Register a callback for a specific conversation.
  /// Called by MessagesProvider when it becomes active.
  void register(String groupIdHex, void Function(List<Message>) callback) {
    _listeners[groupIdHex] = callback;
  }

  /// Unregister when leaving a conversation.
  /// Called by MessagesProvider.dispose().
  void unregister(String groupIdHex) {
    _listeners.remove(groupIdHex);
  }

  /// Notify the active provider (if any) of new messages.
  /// Called by PollingService when messages arrive.
  void notify(String groupIdHex, List<Message> messages) {
    _listeners[groupIdHex]?.call(messages);
  }
}
