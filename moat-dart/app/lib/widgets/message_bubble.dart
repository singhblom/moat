import 'package:flutter/material.dart';
import '../models/message.dart';
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

  const MessageBubble({
    super.key,
    required this.message,
    this.showSender = false,
    this.senderName,
    this.senderDid,
    this.onLongPress,
    this.onRetry,
    this.onReaction,
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
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              decoration: BoxDecoration(
                color: _getBubbleColor(theme, isOwn),
                borderRadius: BorderRadius.only(
                  topLeft: Radius.circular(isOwn ? 18 : 4),
                  topRight: Radius.circular(isOwn ? 4 : 18),
                  bottomLeft: const Radius.circular(18),
                  bottomRight: const Radius.circular(18),
                ),
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
            ),
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
