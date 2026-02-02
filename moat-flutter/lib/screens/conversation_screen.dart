import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../providers/auth_provider.dart';
import '../providers/messages_provider.dart';
import '../services/send_service.dart';
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
  final TextEditingController _textController = TextEditingController();
  final FocusNode _focusNode = FocusNode();

  bool _isAtBottom = true;
  int _previousMessageCount = 0;

  /// Cache of DID -> handle for displaying sender names
  final Map<String, String> _handleCache = {};

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);

    // Initialize send service and resolve handles after build
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _initSendService();
      _resolveParticipantHandles();
    });
  }

  /// Resolve handles for all participants in the conversation
  Future<void> _resolveParticipantHandles() async {
    final authProvider = context.read<AuthProvider>();
    final client = authProvider.atprotoClient;

    for (final did in widget.conversation.participants) {
      if (_handleCache.containsKey(did)) continue;
      try {
        final handle = await client.resolveHandle(did);
        if (mounted) {
          setState(() {
            _handleCache[did] = handle;
          });
        }
      } catch (_) {
        // Failed to resolve, will fall back to truncated DID
      }
    }
  }

  /// Get display name for a sender DID
  String _getSenderDisplayName(String did) {
    if (_handleCache.containsKey(did)) {
      return _handleCache[did]!;
    }
    // Fallback: truncate DID
    if (did.startsWith('did:plc:')) {
      final shortId = did.substring(8);
      return shortId.length > 8 ? shortId.substring(0, 8) : shortId;
    }
    return did.isNotEmpty ? did : 'unknown';
  }

  void _initSendService() {
    final authProvider = context.read<AuthProvider>();
    final messagesProvider = context.read<MessagesProvider>();
    final sendService = SendService(authProvider: authProvider);
    messagesProvider.initSendService(sendService);
  }

  @override
  void dispose() {
    _scrollController.removeListener(_onScroll);
    _scrollController.dispose();
    _textController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _onScroll() {
    if (!_scrollController.hasClients) return;

    final atBottom = _scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 50;

    if (atBottom != _isAtBottom) {
      setState(() {
        _isAtBottom = atBottom;
      });
    }
  }

  void _scrollToBottom({bool animated = true}) {
    if (!_scrollController.hasClients) return;

    if (animated) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    } else {
      _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
    }
  }

  Future<void> _sendMessage() async {
    final text = _textController.text.trim();
    if (text.isEmpty) return;

    // Clear input immediately
    _textController.clear();

    // Scroll to bottom to see the sending message
    _scrollToBottom();

    try {
      final messagesProvider = context.read<MessagesProvider>();
      await messagesProvider.sendMessage(text);
      // Scroll again after send completes
      _scrollToBottom();
    } catch (e) {
      // Error is handled by the provider and shown in UI via status
    }
  }

  @override
  Widget build(BuildContext context) {
    final messagesProvider = context.watch<MessagesProvider>();

    // Auto-scroll when new messages arrive and we're at the bottom
    if (messagesProvider.messages.length > _previousMessageCount && _isAtBottom) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _scrollToBottom();
      });
    }
    _previousMessageCount = messagesProvider.messages.length;

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
          _buildMessageInput(context, messagesProvider),
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
              'Send a message to start the conversation',
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
          senderName: showSender ? _getSenderDisplayName(message.senderDid) : null,
          onLongPress: () => _showMessageInfo(context, message),
          onRetry: message.status == MessageStatus.failed
              ? () => provider.retryMessage(message.localId ?? message.id)
              : null,
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

  Widget _buildMessageInput(BuildContext context, MessagesProvider provider) {
    final hasText = _textController.text.trim().isNotEmpty;

    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          top: BorderSide(
            color: Theme.of(context).colorScheme.outlineVariant,
          ),
        ),
      ),
      child: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Expanded(
              child: Container(
                constraints: const BoxConstraints(maxHeight: 120),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(24),
                ),
                child: TextField(
                  controller: _textController,
                  focusNode: _focusNode,
                  maxLines: null,
                  textInputAction: TextInputAction.newline,
                  keyboardType: TextInputType.multiline,
                  textCapitalization: TextCapitalization.sentences,
                  decoration: const InputDecoration(
                    hintText: 'Message',
                    border: InputBorder.none,
                    contentPadding: EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 12,
                    ),
                  ),
                  onChanged: (_) => setState(() {}),
                  onSubmitted: (_) {
                    // Don't send on Enter for multiline - use button
                  },
                ),
              ),
            ),
            const SizedBox(width: 8),
            _buildSendButton(context, hasText, provider.isSending),
          ],
        ),
      ),
    );
  }

  Widget _buildSendButton(BuildContext context, bool hasText, bool isSending) {
    final canSend = hasText && !isSending;

    return IconButton(
      icon: isSending
          ? SizedBox(
              width: 24,
              height: 24,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: Theme.of(context).colorScheme.primary,
              ),
            )
          : Icon(
              Icons.send,
              color: canSend
                  ? Theme.of(context).colorScheme.primary
                  : Theme.of(context).colorScheme.onSurfaceVariant,
            ),
      onPressed: canSend ? _sendMessage : null,
      tooltip: 'Send message',
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
            _buildInfoRow(context, 'Status', message.status.name),
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
