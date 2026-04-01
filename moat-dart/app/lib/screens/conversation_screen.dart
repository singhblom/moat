import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:image_picker/image_picker.dart';
import 'package:moat_dart_common/moat_dart_common.dart' hide ConversationRepository;
import '../providers/auth_provider.dart';
import '../providers/conversations_provider.dart';
import '../providers/profile_provider.dart';
import '../utils/display_name.dart';
import '../services/conversation_repository.dart';
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

  /// Optimistic image bytes keyed by localId — shown immediately after send.
  final Map<String, Uint8List> _pendingImageBytes = {};
  /// Cached blob futures keyed by contentHash hex — avoids redundant fetches.
  final Map<String, Future<Uint8List>> _blobFutures = {};

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);

    // Preload profiles after build
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _preloadParticipantProfiles();
    });
  }

  /// Preload profiles for all participants in the conversation
  void _preloadParticipantProfiles() {
    final profileProvider = context.read<ProfileProvider>();
    profileProvider.preloadProfiles(widget.conversation.participants);
  }

  String _resolveDidDisplayName(String did) =>
      resolveDidDisplayName(context.read<ProfileProvider>(), did);

  String _resolveConversationDisplayName() =>
      widget.conversation.resolveDisplayName(_resolveDidDisplayName);

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

  /// Returns the image future for a message with an [ImageAttachment], or null.
  ///
  /// For just-sent messages, returns a pre-resolved future from local bytes.
  /// For received messages, fetches and decrypts via [BlobService] (cached).
  Future<Uint8List>? _resolveImageFuture(BuildContext context, Message message) {
    final att = message.attachment;
    if (att is! ImageAttachment) return null;

    // Own optimistic message — bytes are already in memory.
    if (message.localId != null && _pendingImageBytes.containsKey(message.localId)) {
      return Future.value(_pendingImageBytes[message.localId!]);
    }

    // Received (or confirmed) — fetch via BlobService, cache by contentHash.
    final hexHash = att.contentHash
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return _blobFutures[hexHash] ??= context.read<BlobService>().fetchAndDecrypt(
          uri: att.uri,
          key: att.key,
          ciphertextHash: att.ciphertextHash,
          contentHash: att.contentHash,
        ).catchError((e) {
          // Remove from cache so next rebuild can retry (possibly with a
          // different URI for the same content hash).
          _blobFutures.remove(hexHash);
          throw e;
        });
  }

  Future<void> _pickImage() async {
    final picker = ImagePicker();
    final file = await picker.pickImage(source: ImageSource.gallery, imageQuality: 85);
    if (file == null || !mounted) return;

    final bytes = await file.readAsBytes();
    if (!mounted) return;

    final blobService = context.read<BlobService>();
    final repo = context.read<ConversationRepository>();
    final localId = repo.sendImage(bytes, blobService);

    setState(() {
      _pendingImageBytes[localId] = bytes;
    });
    _scrollToBottom();
  }

  Future<void> _sendMessage() async {
    final text = _textController.text.trim();
    if (text.isEmpty) return;

    // Clear input immediately
    _textController.clear();

    // Scroll to bottom to see the sending message
    _scrollToBottom();

    final repo = context.read<ConversationRepository>();
    repo.sendMessage(text);
    // Scroll again after optimistic message is added
    _scrollToBottom();
  }

  @override
  Widget build(BuildContext context) {
    final repo = context.watch<ConversationRepository>();

    // Auto-scroll when new messages arrive and we're at the bottom
    if (repo.messages.length > _previousMessageCount && _isAtBottom) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _scrollToBottom();
      });
    }
    _previousMessageCount = repo.messages.length;

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
            : Text(_resolveConversationDisplayName()),
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
                  child: _buildMessageList(context, repo),
                ),
                _buildMessageInput(context, repo),
              ],
            ),
          ),

          // Layer 3: Reaction overlay
          if (hasSelection) _buildReactionOverlay(context, repo),
        ],
      ),
    );
  }

  Widget _buildMessageList(BuildContext context, ConversationRepository provider) {
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

        final imageFuture = _resolveImageFuture(context, message);

        return MessageBubble(
          key: key,
          message: message,
          showSender: showSender,
          senderName: showSender ? _resolveDidDisplayName(message.senderDid) : null,
          senderDid: showSender ? message.senderDid : null,
          onLongPress: () => _selectMessage(message),
          onRetry: message.status == MessageStatus.failed
              ? () => provider.retryMessage(message.localId ?? message.id)
              : null,
          onReaction: (emoji) => provider.sendReaction(message, emoji),
          imageFuture: imageFuture,
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

  Widget _buildMessageInput(BuildContext context, ConversationRepository provider) {
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
                  decoration: InputDecoration(
                    hintText: 'Message',
                    border: InputBorder.none,
                    contentPadding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 12,
                    ),
                    suffixIcon: AnimatedOpacity(
                      opacity: hasText ? 0.0 : 1.0,
                      duration: const Duration(milliseconds: 200),
                      child: IgnorePointer(
                        ignoring: hasText,
                        child: IconButton(
                          icon: const Icon(Icons.image_outlined),
                          onPressed: _pickImage,
                          tooltip: 'Send image',
                        ),
                      ),
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
            _buildInfoRow(context, 'Name', _resolveConversationDisplayName()),
            _buildInfoRow(context, 'Epoch', widget.conversation.epoch.toString()),
            _buildInfoRow(
              context,
              'Participants',
              widget.conversation.participants.join('\n'),
            ),
            const SizedBox(height: 8),
            FilledButton.icon(
              icon: const Icon(Icons.person_add),
              label: const Text('Add member'),
              onPressed: () {
                Navigator.pop(context);
                _showAddMemberDialog();
              },
            ),
            const SizedBox(height: 8),
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

  void _showAddMemberDialog() {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Add member'),
        content: TextField(
          controller: controller,
          decoration: const InputDecoration(
            hintText: 'handle.bsky.social',
            labelText: 'Handle',
          ),
          autofocus: true,
          onSubmitted: (_) => _doAddMember(dialogContext, controller.text),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => _doAddMember(dialogContext, controller.text),
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }

  Future<void> _doAddMember(BuildContext dialogContext, String handle) async {
    final trimmed = handle.trim();
    if (trimmed.isEmpty) return;
    Navigator.pop(dialogContext);
    try {
      final authService = context.read<AuthProvider>().service;
      final convsService = context.read<ConversationsProvider>().service;
      await addMemberToConversation(
        memberHandle: trimmed,
        groupId: widget.conversation.groupId,
        authService: authService,
        convsService: convsService,
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Added $trimmed')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to add member: $e')),
        );
      }
    }
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
  Widget _buildReactionOverlay(BuildContext context, ConversationRepository provider) {
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
