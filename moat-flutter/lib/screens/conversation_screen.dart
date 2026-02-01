import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../providers/messages_provider.dart';
import '../widgets/message_bubble.dart';

/// Screen showing messages in a conversation
class ConversationScreen extends StatefulWidget {
  final Conversation conversation;

  const ConversationScreen({
    super.key,
    required this.conversation,
  });

  @override
  State<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends State<ConversationScreen> {
  final ScrollController _scrollController = ScrollController();

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  /// Scroll to the bottom of the message list (for use when sending messages)
  // ignore: unused_element
  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final messagesProvider = context.watch<MessagesProvider>();

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.conversation.displayName),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: () => _showConversationInfo(context),
            tooltip: 'Conversation Info',
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: _buildMessageList(context, messagesProvider),
          ),
          _buildInputPlaceholder(context),
        ],
      ),
    );
  }

  Widget _buildMessageList(BuildContext context, MessagesProvider provider) {
    if (provider.isLoading && provider.messages.isEmpty) {
      return const Center(
        child: CircularProgressIndicator(),
      );
    }

    if (provider.error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.error_outline,
              size: 48,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load messages',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              provider.error!,
              style: Theme.of(context).textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    if (provider.messages.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.chat_bubble_outline,
              size: 64,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            const SizedBox(height: 16),
            Text(
              'No messages yet',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              'Messages will appear here when received',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16),
      itemCount: provider.messages.length + 1, // +1 for history boundary
      itemBuilder: (context, index) {
        // History boundary at the top
        if (index == 0) {
          return _buildHistoryBoundary(context, provider.messages);
        }

        final messageIndex = index - 1;
        final message = provider.messages[messageIndex];
        final previousMessage =
            messageIndex > 0 ? provider.messages[messageIndex - 1] : null;

        // Show sender name if this is the first message from this DID in a group
        final showSender = !message.isOwn &&
            (previousMessage == null ||
                previousMessage.senderDid != message.senderDid);

        return MessageBubble(
          message: message,
          showSender: showSender,
          onLongPress: () => _showMessageInfo(context, message),
        );
      },
    );
  }

  Widget _buildHistoryBoundary(BuildContext context, List<Message> messages) {
    if (messages.isEmpty) return const SizedBox.shrink();

    final firstMessage = messages.first;

    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Center(
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(16),
          ),
          child: Text(
            'Messages before ${_formatDate(firstMessage.timestamp)} are on your other devices',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
            textAlign: TextAlign.center,
          ),
        ),
      ),
    );
  }

  Widget _buildInputPlaceholder(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          top: BorderSide(
            color: Theme.of(context).colorScheme.outlineVariant,
          ),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(24),
              ),
              child: Text(
                'Sending messages coming in Step 4',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
              ),
            ),
          ),
          const SizedBox(width: 8),
          IconButton(
            icon: const Icon(Icons.send),
            onPressed: null, // Disabled for now
            color: Theme.of(context).colorScheme.primary,
          ),
        ],
      ),
    );
  }

  void _showConversationInfo(BuildContext context) {
    showModalBottomSheet(
      context: context,
      builder: (context) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Conversation Info',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 16),
            _buildInfoRow(context, 'Name', widget.conversation.displayName),
            _buildInfoRow(context, 'Epoch', widget.conversation.epoch.toString()),
            _buildInfoRow(
              context,
              'Participants',
              widget.conversation.participants.join('\n'),
            ),
            _buildInfoRow(
              context,
              'Created',
              _formatDateTime(widget.conversation.createdAt),
            ),
            _buildInfoRow(
              context,
              'Group ID',
              widget.conversation.groupIdHex,
              isMonospace: true,
            ),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }

  void _showMessageInfo(BuildContext context, Message message) {
    showModalBottomSheet(
      context: context,
      builder: (context) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Message Info',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 16),
            _buildInfoRow(context, 'Sender DID', message.senderDid),
            if (message.senderDeviceId != null)
              _buildInfoRow(context, 'Device', message.senderDeviceId!),
            _buildInfoRow(context, 'Time', _formatDateTime(message.timestamp)),
            _buildInfoRow(context, 'Epoch', message.epoch.toString()),
            _buildInfoRow(context, 'Message ID', message.id, isMonospace: true),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoRow(BuildContext context, String label, String value,
      {bool isMonospace = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(
              label,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    fontFamily: isMonospace ? 'monospace' : null,
                    fontSize: isMonospace ? 12 : null,
                  ),
            ),
          ),
        ],
      ),
    );
  }

  String _formatDate(DateTime time) {
    return '${time.month}/${time.day}/${time.year}';
  }

  String _formatDateTime(DateTime time) {
    return '${time.month}/${time.day}/${time.year} ${time.hour}:${time.minute.toString().padLeft(2, '0')}';
  }
}
