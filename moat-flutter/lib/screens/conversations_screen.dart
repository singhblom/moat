import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/conversation.dart';
import '../providers/auth_provider.dart';
import '../providers/conversations_provider.dart';
import '../providers/watch_list_provider.dart';
import '../services/conversation_manager.dart';
import '../services/conversation_repository.dart';
import '../widgets/avatar_widget.dart';
import 'conversation_screen.dart';
import 'new_conversation_screen.dart';
import 'watch_list_screen.dart';

class ConversationsScreen extends StatelessWidget {
  const ConversationsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthProvider>();
    final conversations = context.watch<ConversationsProvider>();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Moat'),
        actions: [
          // Watch list button with badge
          _WatchListButton(),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: conversations.isLoading
                ? null
                : () => conversations.refresh(),
            tooltip: 'Refresh',
          ),
          PopupMenuButton<String>(
            onSelected: (value) async {
              if (value == 'logout') {
                await auth.logout();
              }
            },
            itemBuilder: (context) => [
              PopupMenuItem(
                enabled: false,
                child: Text(
                  auth.handle ?? auth.did ?? 'Unknown',
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onSurface,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              const PopupMenuDivider(),
              const PopupMenuItem(
                value: 'logout',
                child: Row(
                  children: [
                    Icon(Icons.logout),
                    SizedBox(width: 8),
                    Text('Sign Out'),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
      body: _buildBody(context, conversations),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          Navigator.of(context).push(
            MaterialPageRoute(
              builder: (context) => const NewConversationScreen(),
            ),
          );
        },
        tooltip: 'New Conversation',
        child: const Icon(Icons.add),
      ),
    );
  }

  Widget _buildBody(BuildContext context, ConversationsProvider provider) {
    if (provider.isLoading && provider.conversations.isEmpty) {
      return const Center(
        child: CircularProgressIndicator(),
      );
    }

    if (provider.conversations.isEmpty) {
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
              'No conversations yet',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              'Start a new conversation to begin messaging',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: provider.refresh,
      child: ListView.builder(
        itemCount: provider.conversations.length,
        itemBuilder: (context, index) {
          final conversation = provider.conversations[index];
          return _ConversationTile(conversation: conversation);
        },
      ),
    );
  }
}

class _ConversationTile extends StatelessWidget {
  final Conversation conversation;

  const _ConversationTile({required this.conversation});

  @override
  Widget build(BuildContext context) {
    // Use avatar for 1:1 chats, initials for group chats
    final Widget leadingWidget;
    if (conversation.participants.length == 1) {
      leadingWidget = AvatarWidget(
        did: conversation.participants.first,
        size: 48,
        fallbackText: conversation.displayName.isNotEmpty
            ? conversation.displayName[0].toUpperCase()
            : '?',
      );
    } else {
      leadingWidget = CircleAvatar(
        backgroundColor: Theme.of(context).colorScheme.primaryContainer,
        child: Text(
          conversation.displayName.isNotEmpty
              ? conversation.displayName[0].toUpperCase()
              : '?',
          style: TextStyle(
            color: Theme.of(context).colorScheme.onPrimaryContainer,
          ),
        ),
      );
    }

    return ListTile(
      leading: leadingWidget,
      title: Text(
        conversation.displayName,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: conversation.lastMessagePreview != null
          ? Text(
              conversation.lastMessagePreview!,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            )
          : null,
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (conversation.lastMessageAt != null)
            Text(
              _formatTime(conversation.lastMessageAt!),
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: conversation.unreadCount > 0
                        ? Theme.of(context).colorScheme.primary
                        : Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          if (conversation.unreadCount > 0)
            Container(
              margin: const EdgeInsets.only(top: 4),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                conversation.unreadCount.toString(),
                style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: Theme.of(context).colorScheme.onPrimary,
                    ),
              ),
            ),
        ],
      ),
      onTap: () {
        // Navigate to conversation detail
        final conversationsProvider = context.read<ConversationsProvider>();

        final repo = ConversationManager.instance.getRepository(conversation);
        repo.loadMessages();

        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (context) => ChangeNotifierProvider<ConversationRepository>.value(
              value: repo,
              child: ConversationScreen(conversation: conversation),
            ),
          ),
        ).then((_) {
          // Unload persisted messages when leaving the screen.
          repo.unloadMessages();
        });

        // Mark as read when opening
        conversationsProvider.markAsRead(conversation.groupId);
      },
    );
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final diff = now.difference(time);

    if (diff.inDays > 7) {
      return '${time.month}/${time.day}';
    } else if (diff.inDays > 0) {
      return '${diff.inDays}d';
    } else if (diff.inHours > 0) {
      return '${diff.inHours}h';
    } else if (diff.inMinutes > 0) {
      return '${diff.inMinutes}m';
    } else {
      return 'now';
    }
  }
}

class _WatchListButton extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final watchList = context.watch<WatchListProvider>();
    final count = watchList.entries.length;

    return IconButton(
      icon: Badge(
        isLabelVisible: count > 0,
        label: Text(count.toString()),
        child: const Icon(Icons.visibility_outlined),
      ),
      onPressed: () {
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (context) => const WatchListScreen(),
          ),
        );
      },
      tooltip: 'Watch List',
    );
  }
}
