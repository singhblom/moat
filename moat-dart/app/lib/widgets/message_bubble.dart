import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart';
import 'avatar_widget.dart';

/// A message bubble widget for displaying a single message
class MessageBubble extends StatelessWidget {
  final Message message;
  final bool showSender;
  final String? senderName;
  final String? senderDid;
  final VoidCallback? onLongPress;
  final VoidCallback? onRetry;
  final void Function(String emoji)? onReaction;
  /// Pre-resolved or in-flight future for image bytes. Non-null for image messages.
  final Future<Uint8List>? imageFuture;

  const MessageBubble({
    super.key,
    required this.message,
    this.showSender = false,
    this.senderName,
    this.senderDid,
    this.onLongPress,
    this.onRetry,
    this.onReaction,
    this.imageFuture,
  });

  @override
  Widget build(BuildContext context) {
    final isOwn = message.isOwn;
    final theme = Theme.of(context);

    return Padding(
      padding: EdgeInsets.only(
        left: isOwn ? 48 : 0,
        right: isOwn ? 0 : 48,
        bottom: 4,
        top: showSender ? 8 : 0,
      ),
      child: Column(
        crossAxisAlignment:
            isOwn ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          if (showSender && senderName != null)
            Padding(
              padding: const EdgeInsets.only(left: 12, bottom: 4),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (senderDid != null) ...[
                    AvatarWidget(
                      did: senderDid!,
                      size: 20,
                    ),
                    const SizedBox(width: 6),
                  ],
                  Text(
                    senderName!,
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          GestureDetector(
            onLongPress: onLongPress,
            onTap: message.status == MessageStatus.failed ? onRetry : null,
            child: message.attachment is ImageAttachment
                ? _buildImageBubble(theme, isOwn, message.attachment as ImageAttachment)
                : _buildTextBubble(theme, isOwn),
          ),
          if (message.reactions.isNotEmpty)
            Transform.translate(
              offset: const Offset(0, -6),
              child: Padding(
                padding: EdgeInsets.only(
                  left: isOwn ? 0 : 8,
                  right: isOwn ? 8 : 0,
                ),
                child: _buildReactionBubble(theme),
              ),
            ),
        ],
      ),
    );
  }

  BorderRadius _bubbleRadius(bool isOwn) => BorderRadius.only(
        topLeft: Radius.circular(isOwn ? 18 : 4),
        topRight: Radius.circular(isOwn ? 4 : 18),
        bottomLeft: const Radius.circular(18),
        bottomRight: const Radius.circular(18),
      );

  Widget _buildTextBubble(ThemeData theme, bool isOwn) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: BoxDecoration(
        color: _getBubbleColor(theme, isOwn),
        borderRadius: _bubbleRadius(isOwn),
      ),
      child: Wrap(
        alignment: WrapAlignment.end,
        crossAxisAlignment: WrapCrossAlignment.end,
        spacing: 8,
        runSpacing: 4,
        children: [
          Text(
            message.content,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: isOwn
                  ? theme.colorScheme.onPrimary
                  : theme.colorScheme.onSurface,
            ),
          ),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                _formatTime(message.timestamp),
                style: theme.textTheme.labelSmall?.copyWith(
                  color: isOwn
                      ? theme.colorScheme.onPrimary.withValues(alpha: 0.7)
                      : theme.colorScheme.onSurfaceVariant,
                ),
              ),
              if (isOwn) ...[
                const SizedBox(width: 4),
                _buildStatusIndicator(theme),
              ],
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildImageBubble(
      ThemeData theme, bool isOwn, ImageAttachment att) {
    final radius = _bubbleRadius(isOwn);
    final aspectRatio = (att.width != null && att.height != null && att.height! > 0)
        ? att.width! / att.height!
        : 4.0 / 3.0;

    return Container(
      constraints: const BoxConstraints(maxWidth: 260, minWidth: 120),
      decoration: BoxDecoration(
        color: _getBubbleColor(theme, isOwn),
        borderRadius: radius,
      ),
      child: ClipRRect(
        borderRadius: radius,
        child: Stack(
          fit: StackFit.passthrough,
          children: [
            AspectRatio(
              aspectRatio: aspectRatio,
              child: imageFuture == null
                  ? _buildImagePlaceholder(theme)
                  : FutureBuilder<Uint8List>(
                      future: imageFuture,
                      builder: (context, snap) {
                        if (snap.hasData) {
                          return Image.memory(snap.data!, fit: BoxFit.cover);
                        }
                        if (snap.hasError) {
                          return _buildBrokenImage(theme);
                        }
                        return _buildImagePlaceholder(theme);
                      },
                    ),
            ),
            Positioned(
              bottom: 6,
              right: 8,
              child: _buildTimestampOverlay(theme, isOwn),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildImagePlaceholder(ThemeData theme) {
    return Container(
      color: theme.colorScheme.surfaceContainerHighest,
      child: Center(
        child: CircularProgressIndicator(
          strokeWidth: 2,
          color: theme.colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }

  Widget _buildBrokenImage(ThemeData theme) {
    return Container(
      color: theme.colorScheme.surfaceContainerHighest,
      child: Center(
        child: Icon(
          Icons.broken_image_outlined,
          color: theme.colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }

  Widget _buildTimestampOverlay(ThemeData theme, bool isOwn) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: Colors.black54,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            _formatTime(message.timestamp),
            style: theme.textTheme.labelSmall?.copyWith(
              color: Colors.white,
              fontSize: 11,
            ),
          ),
          if (isOwn) ...[
            const SizedBox(width: 3),
            _buildStatusIndicatorOverlay(),
          ],
        ],
      ),
    );
  }

  Widget _buildStatusIndicatorOverlay() {
    switch (message.status) {
      case MessageStatus.sending:
        return const Icon(Icons.access_time, size: 12, color: Colors.white70);
      case MessageStatus.sent:
        return const Icon(Icons.done_all, size: 12, color: Colors.white70);
      case MessageStatus.failed:
        return const Icon(Icons.error_outline, size: 12, color: Colors.white70);
    }
  }

  Widget _buildReactionBubble(ThemeData theme) {
    // Aggregate reactions by emoji
    final counts = <String, int>{};
    for (final r in message.reactions) {
      counts[r.emoji] = (counts[r.emoji] ?? 0) + 1;
    }

    final entries = counts.entries.toList();

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.85),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: theme.colorScheme.surface.withValues(alpha: 0.6),
          width: 2,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          for (int i = 0; i < entries.length; i++) ...[
            if (i > 0) const SizedBox(width: 6),
            GestureDetector(
              onTap: onReaction != null
                  ? () => onReaction!(entries[i].key)
                  : null,
              child: Text(
                entries[i].value > 1
                    ? '${entries[i].key} ${entries[i].value}'
                    : entries[i].key,
                style: theme.textTheme.labelSmall?.copyWith(
                  fontFamily: 'NotoColorEmoji',
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Color _getBubbleColor(ThemeData theme, bool isOwn) {
    if (message.status == MessageStatus.failed) {
      return theme.colorScheme.errorContainer;
    }
    if (isOwn) {
      return theme.colorScheme.primary;
    }
    return theme.colorScheme.surfaceContainerHighest;
  }

  Widget _buildStatusIndicator(ThemeData theme) {
    final color = message.status == MessageStatus.failed
        ? theme.colorScheme.onErrorContainer
        : theme.colorScheme.onPrimary.withValues(alpha: 0.7);

    switch (message.status) {
      case MessageStatus.sending:
        // Single gray checkmark (clock icon for sending)
        return Icon(
          Icons.access_time,
          size: 14,
          color: color,
        );

      case MessageStatus.sent:
        // Double checkmarks
        return Icon(
          Icons.done_all,
          size: 14,
          color: color,
        );

      case MessageStatus.failed:
        // Error icon with retry hint
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.error_outline,
              size: 14,
              color: theme.colorScheme.onErrorContainer,
            ),
            const SizedBox(width: 4),
            Text(
              'Tap to retry',
              style: theme.textTheme.labelSmall?.copyWith(
                color: theme.colorScheme.onErrorContainer,
                fontSize: 10,
              ),
            ),
          ],
        );
    }
  }

  String _formatTime(DateTime time) {
    final hour = time.hour;
    final minute = time.minute.toString().padLeft(2, '0');
    final period = hour >= 12 ? 'PM' : 'AM';
    final displayHour = hour == 0 ? 12 : (hour > 12 ? hour - 12 : hour);
    return '$displayHour:$minute $period';
  }
}
