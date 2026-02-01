import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../providers/auth_provider.dart';
import '../providers/conversations_provider.dart';
import '../providers/watch_list_provider.dart';
import '../src/rust/api/simple.dart';
import 'atproto_client.dart';
import 'message_storage.dart';
import 'secure_storage.dart';
import 'debug_log.dart';

/// Service that polls for events from watched DIDs and processes invites
class PollingService {
  final AuthProvider _authProvider;
  final ConversationsProvider _conversationsProvider;
  final WatchListProvider _watchListProvider;
  final SecureStorageService _secureStorage;
  final MessageStorage _messageStorage;

  Timer? _pollTimer;
  bool _isPolling = false;

  /// Callback when a new conversation is received
  VoidCallback? onNewConversation;

  /// Callback when new messages arrive
  void Function(String groupIdHex, List<Message> messages)? onNewMessages;

  PollingService({
    required AuthProvider authProvider,
    required ConversationsProvider conversationsProvider,
    required WatchListProvider watchListProvider,
    SecureStorageService? secureStorage,
    MessageStorage? messageStorage,
  })  : _authProvider = authProvider,
        _conversationsProvider = conversationsProvider,
        _watchListProvider = watchListProvider,
        _secureStorage = secureStorage ?? SecureStorageService(),
        _messageStorage = messageStorage ?? MessageStorage();

  /// Start polling for events (every 5 seconds)
  void startPolling() {
    stopPolling();
    _pollTimer = Timer.periodic(const Duration(seconds: 5), (_) => poll());
    // Do an immediate poll
    poll();
  }

  /// Stop polling
  void stopPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  /// Perform a single poll cycle
  Future<void> poll() async {
    if (_isPolling) return;
    if (!_authProvider.isAuthenticated) return;

    _isPolling = true;

    try {
      // Poll our own DID for incoming welcome messages from other devices
      await _pollOwnDid();
      // Poll watched DIDs for invites
      await _pollWatchedDids();
      // Poll for messages from existing conversations
      await _pollConversationMessages();
    } catch (e) {
      moatLog('Polling error: $e');
    } finally {
      _isPolling = false;
    }
  }

  /// Poll our own DID for incoming welcome messages (multi-device sync)
  Future<void> _pollOwnDid() async {
    final myDid = _authProvider.did;
    if (myDid == null) return;

    final client = _authProvider.atprotoClient;

    try {
      // Get last seen rkey for our own DID
      final lastRkey = await _secureStorage.getLastRkey(myDid);

      moatLog('PollingService: Polling own DID $myDid (afterRkey: $lastRkey)');

      // Fetch new events from our own PDS
      final events = await client.fetchEvents(myDid, afterRkey: lastRkey);

      moatLog('PollingService: Found ${events.length} events from own DID');

      if (events.isEmpty) return;

      // Track max rkey for pagination
      String? maxRkey = lastRkey;

      for (final event in events) {
        moatLog('PollingService: Processing own DID event rkey=${event.rkey}, ${event.ciphertext.length} bytes');

        // Update max rkey
        if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
          maxRkey = event.rkey;
        }

        // Try to decrypt as stealth-encrypted welcome
        final welcomeBytes =
            await _authProvider.tryDecryptStealthPayload(event.ciphertext);

        if (welcomeBytes != null) {
          moatLog('PollingService: Decrypted welcome from own DID (multi-device sync)');
          // This is a welcome from another device in the same account,
          // or from someone who invited us
          await _processWelcome(welcomeBytes, myDid);

          // Notify listeners
          onNewConversation?.call();
        } else {
          moatLog('PollingService: Could not decrypt own DID event ${event.rkey} as stealth welcome');
        }
      }

      // Save last rkey for pagination
      if (maxRkey != null) {
        await _secureStorage.saveLastRkey(myDid, maxRkey);
      }
    } catch (e, stack) {
      moatLog('PollingService: Error polling own DID: $e');
      moatLog('PollingService: Stack trace: $stack');
    }
  }

  /// Poll events from watched DIDs and try to process as invites
  Future<void> _pollWatchedDids() async {
    final watchedDids = _watchListProvider.dids;
    if (watchedDids.isEmpty) {
      moatLog('PollingService: No watched DIDs');
      return;
    }

    moatLog('PollingService: Polling ${watchedDids.length} watched DIDs');
    final client = _authProvider.atprotoClient;

    for (final did in watchedDids) {
      try {
        // Get last seen rkey for this DID
        final lastRkey = await _secureStorage.getLastRkey(did);
        moatLog('PollingService: Fetching events from $did (afterRkey: $lastRkey)');

        // Fetch new events
        final events = await client.fetchEvents(did, afterRkey: lastRkey);
        moatLog('PollingService: Found ${events.length} events from $did');

        if (events.isEmpty) continue;

        // Track max rkey for pagination
        String? maxRkey = lastRkey;

        for (final event in events) {
          moatLog('PollingService: Processing event ${event.rkey}');

          // Update max rkey
          if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
            maxRkey = event.rkey;
          }

          // Try to decrypt as stealth-encrypted welcome
          final welcomeBytes =
              await _authProvider.tryDecryptStealthPayload(event.ciphertext);

          if (welcomeBytes != null) {
            moatLog('PollingService: Successfully decrypted welcome from $did');
            // Success! This is an invite for us
            await _processWelcome(welcomeBytes, did);

            // Remove from watch list since we successfully joined
            await _watchListProvider.removeDid(did);

            // Notify listeners
            onNewConversation?.call();

            // Don't process more events from this DID - we've joined
            break;
          } else {
            moatLog('PollingService: Could not decrypt event ${event.rkey} as welcome');
          }
        }

        // Save last rkey for pagination
        if (maxRkey != null) {
          await _secureStorage.saveLastRkey(did, maxRkey);
        }
      } catch (e, stack) {
        moatLog('PollingService: Error polling DID $did: $e');
        moatLog('PollingService: Stack trace: $stack');
        // Continue with other DIDs
      }
    }
  }

  /// Poll for messages from all conversation participants
  Future<void> _pollConversationMessages() async {
    final conversations = _conversationsProvider.conversations;
    if (conversations.isEmpty) {
      return;
    }

    moatLog('PollingService: Polling messages for ${conversations.length} conversations');
    final client = _authProvider.atprotoClient;
    final myDid = _authProvider.did;
    final session = _authProvider.moatSession;

    if (myDid == null || session == null) return;

    // Collect all unique participant DIDs across all conversations
    final allParticipantDids = <String>{};
    for (final conv in conversations) {
      allParticipantDids.addAll(conv.participants);
    }

    // Also include our own DID to get messages we sent from other devices
    allParticipantDids.add(myDid);

    moatLog('PollingService: Polling ${allParticipantDids.length} unique DIDs for messages');

    // Load tag map once
    final tagMap = await _secureStorage.loadTagMap();

    for (final did in allParticipantDids) {
      try {
        // Use a different rkey namespace for message polling vs welcome polling
        final messageRkeyKey = 'msg_$did';
        final lastRkey = await _secureStorage.getLastRkey(messageRkeyKey);

        final events = await client.fetchEvents(did, afterRkey: lastRkey);
        if (events.isEmpty) continue;

        moatLog('PollingService: Found ${events.length} events from $did for message processing');

        String? maxRkey = lastRkey;

        for (final event in events) {
          // Update max rkey
          if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
            maxRkey = event.rkey;
          }

          // Try to route this event via tag lookup
          final tagHex = event.tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
          final groupIdHex = tagMap[tagHex];

          if (groupIdHex == null) {
            // Unknown tag - could be stealth invite (already handled), old epoch, or not for us
            continue;
          }

          // Find the conversation
          final conversation = conversations.where((c) => c.groupIdHex == groupIdHex).firstOrNull;
          if (conversation == null) {
            moatLog('PollingService: Found tag for unknown conversation $groupIdHex');
            continue;
          }

          // Try to decrypt the event
          await _processConversationEvent(event, conversation, did, session);
        }

        // Save last rkey for this DID
        if (maxRkey != null) {
          await _secureStorage.saveLastRkey(messageRkeyKey, maxRkey);
        }
      } catch (e, stack) {
        moatLog('PollingService: Error polling messages from $did: $e');
        moatLog('PollingService: Stack: $stack');
      }
    }
  }

  /// Process a single event for a conversation
  Future<void> _processConversationEvent(
    EventRecord event,
    Conversation conversation,
    String senderDid,
    MoatSessionHandle session,
  ) async {
    try {
      // Decrypt the event
      final result = await session.decryptEvent(
        groupId: conversation.groupId,
        ciphertext: event.ciphertext,
      );

      // Save updated MLS state
      await _authProvider.saveMlsState();

      // Handle by event kind
      switch (result.event.kind) {
        case EventKindDto.message:
          // Unpad and decode text
          final plaintext = unpad(padded: result.event.payload);
          final text = utf8.decode(plaintext);

          // Extract sender DID from device ID
          final messageSenderDid = _extractDidFromDeviceId(result.event.senderDeviceId);
          final isOwn = messageSenderDid == _authProvider.did;

          final message = Message(
            id: '${conversation.groupIdHex}_${event.rkey}',
            groupId: conversation.groupId,
            senderDid: messageSenderDid,
            senderDeviceId: result.event.senderDeviceId,
            content: text,
            timestamp: event.createdAt,
            isOwn: isOwn,
            epoch: result.event.epoch.toInt(),
          );

          moatLog('PollingService: Decrypted message: "${text.substring(0, text.length > 20 ? 20 : text.length)}..."');

          // Save message to storage
          await _messageStorage.appendMessage(conversation.groupIdHex, message);

          // Update conversation metadata
          await _conversationsProvider.updateLastMessage(
            conversation.groupId,
            preview: text.length > 50 ? '${text.substring(0, 50)}...' : text,
            timestamp: event.createdAt,
            incrementUnread: !isOwn, // Don't increment for our own messages
          );

          // Notify listeners
          onNewMessages?.call(conversation.groupIdHex, [message]);

        case EventKindDto.commit:
          // Epoch advanced - update conversation and tag map
          final newEpoch = result.event.epoch.toInt();
          moatLog('PollingService: Commit received for ${conversation.groupIdHex}, new epoch: $newEpoch');

          // Update conversation epoch
          await _conversationsProvider.updateConversation(
            conversation.groupId,
            epoch: newEpoch,
          );

          // Derive and register new tag for this epoch
          final newTag = deriveTag(groupId: conversation.groupId, epoch: BigInt.from(newEpoch));
          await _authProvider.registerTag(newTag, conversation.groupId);

        case EventKindDto.welcome:
        case EventKindDto.checkpoint:
          // Not displayable, state already updated
          break;
      }
    } catch (e) {
      moatLog('PollingService: Failed to decrypt event ${event.rkey} for ${conversation.groupIdHex}: $e');
      // Continue with other events - this could be a duplicate or epoch mismatch
    }
  }

  /// Extract DID from device ID (format: "did:plc:xxx/device-name")
  String _extractDidFromDeviceId(String? deviceId) {
    if (deviceId == null) return 'unknown';
    final slashIndex = deviceId.indexOf('/');
    if (slashIndex > 0) {
      return deviceId.substring(0, slashIndex);
    }
    return deviceId;
  }

  /// Process a decrypted Welcome message
  Future<void> _processWelcome(Uint8List welcomeBytes, String senderDid) async {
    // Join the group
    final groupId = await _authProvider.processWelcome(welcomeBytes);

    // Derive and register epoch 1 tag
    final tag = _authProvider.deriveConversationTag(groupId, 1);
    await _authProvider.registerTag(tag, groupId);

    // Get all DIDs in the group to find the other participant(s)
    final groupDids = await _authProvider.getGroupDids(groupId);
    final myDid = _authProvider.did;

    // Filter out our own DID to get the other participant(s)
    final otherDids = groupDids.where((did) => did != myDid).toList();

    // Use the first other participant as the display name, or fall back to sender
    final participantDid = otherDids.isNotEmpty ? otherDids.first : senderDid;

    // Resolve participant handle
    String displayName;
    try {
      displayName = await _authProvider.atprotoClient.resolveHandle(participantDid);
    } catch (_) {
      displayName = participantDid;
    }

    moatLog('PollingService: Joined group with participants: $groupDids, display: $displayName');

    // Create conversation
    final groupIdHex =
        groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    final conversation = Conversation(
      groupId: groupId,
      displayName: displayName,
      participants: otherDids.isNotEmpty ? otherDids : [senderDid],
      epoch: 1,
      keyBundleRef: 'key_bundle_$groupIdHex',
      createdAt: DateTime.now(),
    );

    // Save conversation
    await _conversationsProvider.saveConversation(conversation);
  }

  /// Dispose the service
  void dispose() {
    stopPolling();
  }
}
