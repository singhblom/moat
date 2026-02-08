import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../providers/auth_provider.dart';
import '../providers/messages_provider.dart';
import '../providers/profile_provider.dart';
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

  /// Currently selected message for reaction/actions (WhatsApp-style overlay)
  Message? _selectedMessage;
  /// Global key for the selected message bubble, used to position the emoji bar
  final Map<String, GlobalKey> _messageKeys = {};

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);

    // Initialize send service and preload profiles after build
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _initSendService();
      _preloadParticipantProfiles();
    });
  }

  /// Preload profiles for all participants in the conversation
  void _preloadParticipantProfiles() {
    final profileProvider = context.read<ProfileProvider>();
    profileProvider.preloadProfiles(widget.conversation.participants);
  }

  /// Get display name for a sender DID
  String _getSenderDisplayName(String did) {
    final profileProvider = context.read<ProfileProvider>();
    final profile = profileProvider.getCachedProfile(did);
    if (profile != null) {
      return profile.displayName ?? profile.handle;
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

    final hasSelection = _selectedMessage != null;

    return Scaffold(
      appBar: AppBar(
        leading: hasSelection
            ? IconButton(
                icon: const Icon(Icons.close),
                onPressed: _clearSelection,
              )
            : null,
        title: hasSelection
            ? null
            : Text(widget.conversation.displayName),
        actions: hasSelection
            ? [
                IconButton(
                  icon: const Icon(Icons.info_outline),
                  onPressed: () {
                    final msg = _selectedMessage!;
                    _clearSelection();
                    _showMessageInfo(context, msg);
                  },
                  tooltip: 'Message Info',
                ),
              ]
            : [
                IconButton(
                  icon: const Icon(Icons.info_outline),
                  onPressed: () => _showConversationInfo(context),
                  tooltip: 'Conversation Info',
                ),
              ],
      ),
      body: Stack(
        children: [
          // Layer 1: The Tiled Background
          Container(
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surface,
              image: DecorationImage(
                image: AssetImage('assets/tile_pattern.png'),
                repeat: ImageRepeat.repeat,
                opacity: 0.1,
                colorFilter: ColorFilter.mode(Theme.of(context).colorScheme.primary, BlendMode.srcIn)
              ),
            ),
          ),

          // Layer 2: Your UI Content
          SafeArea(
            child: Column(
              children: [
                Expanded(
                  child: _buildMessageList(context, messagesProvider),
                ),
                _buildMessageInput(context, messagesProvider),
              ],
            ),
          ),

          // Layer 3: Reaction overlay
          if (hasSelection) _buildReactionOverlay(context, messagesProvider),
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

        // Ensure we have a GlobalKey for this message
        final key = _messageKeys.putIfAbsent(message.id, () => GlobalKey());

        return MessageBubble(
          key: key,
          message: message,
          showSender: showSender,
          senderName: showSender ? _getSenderDisplayName(message.senderDid) : null,
          senderDid: showSender ? message.senderDid : null,
          onLongPress: () => _selectMessage(message),
          onRetry: message.status == MessageStatus.failed
              ? () => provider.retryMessage(message.localId ?? message.id)
              : null,
          onReaction: (emoji) => provider.sendReaction(message, emoji),
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
    final colorScheme = Theme.of(context).colorScheme;

    // 1. Define visual states using modern withValues API
    final bgColor = canSend 
        ? colorScheme.primary 
        : colorScheme.onSurfaceVariant.withValues(alpha: 0.12);
    
    final contentColor = canSend 
        ? colorScheme.onPrimary 
        : colorScheme.onSurfaceVariant;

    return AnimatedContainer(
      duration: const Duration(milliseconds: 250),
      curve: Curves.easeInOutCubic, // A slightly more premium "Material" curve
      decoration: BoxDecoration(
        color: bgColor,
        shape: BoxShape.circle,
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: canSend ? _sendMessage : null,
          customBorder: const CircleBorder(),
          child: Padding(
            padding: const EdgeInsets.all(12.0),
            child: SizedBox(
              width: 24,
              height: 24,
              // 2. AnimatedSwitcher handles the Icon <-> Progress transition
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 200),
                transitionBuilder: (Widget child, Animation<double> animation) {
                  // Combines a fade with a slight scale-up for the entering widget
                  return FadeTransition(
                    opacity: animation,
                    child: ScaleTransition(scale: animation, child: child),
                  );
                },
                child: isSending
                    ? CircularProgressIndicator(
                        key: const ValueKey('loading'), // Key is vital for Switcher
                        strokeWidth: 2.5,
                        color: contentColor,
                      )
                    : Icon(
                        Icons.send,
                        key: const ValueKey('send_icon'),
                        color: contentColor,
                      ),
              ),
            ),
          ),
        ),
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

  void _selectMessage(Message message) {
    setState(() {
      _selectedMessage = message;
    });
  }

  void _clearSelection() {
    setState(() {
      _selectedMessage = null;
    });
  }

  /// Build the floating emoji bar + scrim overlay (WhatsApp-style)
  Widget _buildReactionOverlay(BuildContext context, MessagesProvider provider) {
    const quickEmojis = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
    final message = _selectedMessage!;

    // Find the position of the selected message bubble
    final key = _messageKeys[message.id];
    Offset bubblePosition = Offset.zero;
    Size bubbleSize = Size.zero;
    if (key?.currentContext != null) {
      final renderBox = key!.currentContext!.findRenderObject() as RenderBox;
      bubblePosition = renderBox.localToGlobal(Offset.zero);
      bubbleSize = renderBox.size;
    }

    // Position emoji bar above or below the bubble
    final emojiBarHeight = 56.0;
    final aboveBubble = bubblePosition.dy - emojiBarHeight - 8;
    final belowBubble = bubblePosition.dy + bubbleSize.height + 8;
    // Show above if there's room, otherwise below
    final showAbove = aboveBubble > MediaQuery.of(context).padding.top + kToolbarHeight;
    final emojiBarTop = showAbove ? aboveBubble : belowBubble;

    // Horizontal position: align with bubble
    final isOwn = message.isOwn;
    final screenWidth = MediaQuery.of(context).size.width;
    final emojiBarWidth = 280.0;

    double emojiBarLeft;
    if (isOwn) {
      // Right-align with bubble
      emojiBarLeft = (bubblePosition.dx + bubbleSize.width - emojiBarWidth)
          .clamp(8.0, screenWidth - emojiBarWidth - 8);
    } else {
      // Left-align with bubble
      emojiBarLeft = bubblePosition.dx.clamp(8.0, screenWidth - emojiBarWidth - 8);
    }

    return Stack(
      children: [
        // Scrim: tap to dismiss
        Positioned.fill(
          child: GestureDetector(
            onTap: _clearSelection,
            child: Container(
              color: Colors.black.withValues(alpha: 0.3),
            ),
          ),
        ),
        // Emoji bar
        if (message.messageId != null)
          Positioned(
            top: emojiBarTop,
            left: emojiBarLeft,
            child: Material(
              elevation: 8,
              borderRadius: BorderRadius.circular(28),
              color: Theme.of(context).colorScheme.surfaceContainerHigh,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: quickEmojis.map((emoji) {
                    return InkWell(
                      borderRadius: BorderRadius.circular(20),
                      onTap: () {
                        _clearSelection();
                        provider.sendReaction(message, emoji);
                      },
                      child: Padding(
                        padding: const EdgeInsets.all(8),
                        child: Text(emoji, style: const TextStyle(fontSize: 24, fontFamily: 'NotoColorEmoji')),
                      ),
                    );
                  }).toList(),
                ),
              ),
            ),
          ),
      ],
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
