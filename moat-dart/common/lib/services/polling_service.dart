import 'dart:async';
import 'dart:typed_data';
import '../models/conversation.dart';
import '../models/message.dart';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'watch_list_service.dart';
import '../rust/api/simple.dart';
import '../utils/message_payload.dart';
import 'atproto_client.dart';
import 'conversation_manager.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'secure_storage.dart';
import 'debug_log.dart';
import '../utils/welcome_envelope.dart';

/// Stats returned by a single poll cycle.
class PollStats {
  final int newMessages;
  final int newConversations;

  const PollStats({required this.newMessages, required this.newConversations});
}

/// Service that polls for events from watched DIDs and processes invites.
/// No Flutter dependency — uses AuthService, ConversationsService, WatchListService.
class PollingService {
  final AuthService _authService;
  final ConversationsService _conversationsService;
  final WatchListService _watchListService;
  final SecureStorageService _secureStorage;
  final DeviceRingService _ringService;

  Timer? _pollTimer;
  bool _isPolling = false;

  /// Callback when a new conversation is received.
  void Function()? onNewConversation;

  /// Callback when messages arrive for a conversation.
  /// Defaults to [ConversationManager.instance.notify] if not set.
  void Function(Conversation, List<Message>)? onMessages;

  /// Callback when a reaction arrives for a conversation.
  /// Defaults to [ConversationManager.instance.notifyReaction] if not set.
  void Function(Conversation, List<int>, String, String)? onReaction;

  PollingService({
    required AuthService authService,
    required ConversationsService conversationsService,
    required WatchListService watchListService,
    required SecureStorageService secureStorage,
    required DeviceRingService ringService,
  })  : _authService = authService,
        _conversationsService = conversationsService,
        _watchListService = watchListService,
        _secureStorage = secureStorage,
        _ringService = ringService;

  /// Start polling periodically.
  void startPolling({Duration interval = const Duration(seconds: 5)}) {
    stopPolling();
    if (interval.inSeconds == 0) return;
    _pollTimer = Timer.periodic(interval, (_) => poll());
    poll();
  }

  /// Stop polling.
  void stopPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  /// Perform a single poll cycle (fire-and-forget).
  Future<void> poll() async {
    await pollOnce();
  }

  /// Perform a single poll cycle and return stats.
  /// Used by the HTTP server's POST /poll endpoint.
  Future<PollStats> pollOnce() async {
    if (_isPolling) return const PollStats(newMessages: 0, newConversations: 0);
    if (!_authService.isAuthenticated) {
      return const PollStats(newMessages: 0, newConversations: 0);
    }

    _isPolling = true;

    var newMessages = 0;
    var newConversations = 0;

    try {
      newConversations += await _pollOwnDid();
      newConversations += await _pollWatchedDids();
      newMessages += await _pollConversationMessages();
    } catch (e) {
      moatLog('Polling error: $e');
    } finally {
      _isPolling = false;
    }

    return PollStats(newMessages: newMessages, newConversations: newConversations);
  }

  /// Poll our own DID for incoming welcome messages.
  Future<int> _pollOwnDid() async {
    final myDid = _authService.did;
    if (myDid == null) return 0;

    final client = _authService.atprotoClient;
    var newConvs = 0;

    // Events up to this rkey have already been processed by the ring driver's
    // tick() (e.g. coord-group Welcomes).  Skip welcome processing for those
    // but still advance the polling cursor past them.
    final ringCursor = _ringService.ownEventsCursor();

    try {
      final lastRkey = await _secureStorage.getLastRkey(myDid);
      moatLog('PollingService: Polling own DID $myDid (afterRkey: $lastRkey)');

      final events = await client.fetchEvents(myDid, afterRkey: lastRkey);
      moatLog('PollingService: Found ${events.length} events from own DID');

      if (events.isEmpty) return 0;

      String? maxRkey = lastRkey;

      for (final event in events) {
        moatLog('PollingService: Processing own DID event rkey=${event.rkey}');

        if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
          maxRkey = event.rkey;
        }

        // Skip events the ring driver already consumed (coord-group Welcomes).
        if (ringCursor != null && event.rkey.compareTo(ringCursor) <= 0) {
          moatLog('PollingService: Skipping own DID event (ring cursor=$ringCursor)');
          continue;
        }

        final welcomeBytes =
            await _authService.tryDecryptStealthPayload(event.ciphertext);

        if (welcomeBytes != null) {
          moatLog('PollingService: Decrypted welcome from own DID');
          try {
            await _processWelcome(welcomeBytes, myDid);
            onNewConversation?.call();
            newConvs++;
          } catch (e, stack) {
            moatLog('PollingService: _processWelcome failed for own DID event rkey=${event.rkey}: $e');
            moatLog('PollingService: Stack trace: $stack');
          }
        }
      }

      if (maxRkey != null) {
        await _secureStorage.saveLastRkey(myDid, maxRkey);
      }
    } catch (e, stack) {
      moatLog('PollingService: Error polling own DID: $e');
      moatLog('PollingService: Stack trace: $stack');
    }

    return newConvs;
  }

  /// Poll events from watched DIDs and try to process as invites.
  Future<int> _pollWatchedDids() async {
    final watchedDids = _watchListService.dids;
    if (watchedDids.isEmpty) {
      moatLog('PollingService: No watched DIDs');
      return 0;
    }

    moatLog('PollingService: Polling ${watchedDids.length} watched DIDs');
    final client = _authService.atprotoClient;
    var newConvs = 0;

    for (final did in watchedDids) {
      try {
        final lastRkey = await _secureStorage.getLastRkey(did);
        moatLog('PollingService: Fetching events from $did (afterRkey: $lastRkey)');

        final events = await client.fetchEvents(did, afterRkey: lastRkey);
        moatLog('PollingService: Found ${events.length} events from $did');

        if (events.isEmpty) continue;

        String? maxRkey = lastRkey;

        for (final event in events) {
          moatLog('PollingService: Processing event ${event.rkey}');

          if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
            maxRkey = event.rkey;
          }

          final welcomeBytes =
              await _authService.tryDecryptStealthPayload(event.ciphertext);

          if (welcomeBytes != null) {
            moatLog('PollingService: Successfully decrypted welcome from $did');
            await _processWelcome(welcomeBytes, did);
            await _watchListService.removeDid(did);
            onNewConversation?.call();
            newConvs++;
            break;
          }
        }

        if (maxRkey != null) {
          await _secureStorage.saveLastRkey(did, maxRkey);
        }
      } catch (e, stack) {
        moatLog('PollingService: Error polling DID $did: $e');
        moatLog('PollingService: Stack trace: $stack');
      }
    }

    return newConvs;
  }

  /// Poll for messages from all conversation participants.
  Future<int> _pollConversationMessages() async {
    final conversations = _conversationsService.conversations;

    moatLog('PollingService: Polling messages for ${conversations.length} conversations');
    final client = _authService.atprotoClient;
    final myDid = _authService.did;
    final session = _authService.moatSession;

    if (myDid == null || session == null) return 0;

    final allParticipantDids = <String>{};
    for (final conv in conversations) {
      allParticipantDids.addAll(conv.participants);
    }
    // Always include own DID so coord-group events on our own PDS records are
    // routed to handleCoordMsg even when there are no user conversations yet.
    allParticipantDids.add(myDid);

    moatLog('PollingService: Polling ${allParticipantDids.length} unique DIDs for messages');

    var tagMap = await _secureStorage.loadTagMap();
    var newMsgs = 0;

    var ringGroupId = await _ringService.ringGroupId();
    var ringGroupIdHex = ringGroupId != null
        ? ringGroupId!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()
        : null;

    for (final did in allParticipantDids) {
      try {
        final messageRkeyKey = 'msg_$did';
        final lastRkey = await _secureStorage.getLastRkey(messageRkeyKey);

        final events = await client.fetchEvents(did, afterRkey: lastRkey);
        if (events.isEmpty) continue;

        moatLog('PollingService: Found ${events.length} events from $did for message processing');

        String? maxRkey = lastRkey;

        for (final event in events) {
          if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
            maxRkey = event.rkey;
          }

          final tagHex = event.tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
          final groupIdHex = tagMap[tagHex];

          if (groupIdHex == null) {
            moatLog('PollingService: event ${event.rkey} tag=$tagHex not in tagMap (map size=${tagMap.length})');
            continue;
          }

          session.markTagSeen(tag: Uint8List.fromList(event.tag));

          if (ringGroupIdHex != null && groupIdHex == ringGroupIdHex) {
            moatLog('PollingService: dispatching ring event rkey=${event.rkey} to _processRingEvent');
            await _processRingEvent(event, ringGroupId!, session);
            continue;
          }

          final conversation = conversations
              .where((c) => c.groupIdHex == groupIdHex)
              .firstOrNull;
          if (conversation == null) {
            // Not a user conversation and not the ring group — try as a
            // coord-group event (Hello, RingInfo, RingWelcome from the ring
            // driver's DeviceCoord MLS group).
            final coordGroupId = _hexToBytes(groupIdHex);
            await _processCoordEvent(event, coordGroupId, session);
            // Refresh tagMap: processing a coord event (e.g. RingWelcome)
            // may have registered new group tags (ring group). Remaining
            // events in this batch may match those tags.
            tagMap = await _secureStorage.loadTagMap();
            ringGroupId = await _ringService.ringGroupId();
            ringGroupIdHex = ringGroupId != null
                ? ringGroupId!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()
                : null;
            moatLog('PollingService: tagMap refreshed after coord event: size=${tagMap.length} ringGroupId=${ringGroupIdHex ?? "none"}');
            continue;
          }

          final processed = await _processConversationEvent(
              event, conversation, did, session);
          if (processed) newMsgs++;
        }

        if (maxRkey != null) {
          await _secureStorage.saveLastRkey(messageRkeyKey, maxRkey);
        }
      } catch (e, stack) {
        moatLog('PollingService: Error polling messages from $did: $e');
        moatLog('PollingService: Stack: $stack');
      }
    }

    return newMsgs;
  }

  /// Process a single event for a conversation. Returns true if a message was stored.
  Future<bool> _processConversationEvent(
    EventRecord event,
    Conversation conversation,
    String senderDid,
    MoatSessionHandle session,
  ) async {
    try {
      final result = await session.decryptEvent(
        groupId: conversation.groupId,
        ciphertext: event.ciphertext,
      );

      await _authService.saveMlsState();

      switch (result.event.kind) {
        case EventKindDto.message:
          final payload = Uint8List.fromList(result.event.payload);
          final text = renderMessagePreview(payload);
          final msgSenderDid = result.sender?.did ?? 'unknown';
          final senderDeviceName = result.sender?.deviceName;
          final isOwn = msgSenderDid == _authService.did;

          final message = Message(
            id: '${conversation.groupIdHex}_${event.rkey}',
            groupId: conversation.groupId,
            senderDid: msgSenderDid,
            senderDeviceId: senderDeviceName,
            content: text,
            timestamp: event.createdAt,
            isOwn: isOwn,
            epoch: result.event.epoch.toInt(),
            messageId: result.event.messageId != null
                ? Uint8List.fromList(result.event.messageId!)
                : null,
            attachment: parseAttachment(payload),
          );

          moatLog('PollingService: Decrypted message: "${text.substring(0, text.length > 20 ? 20 : text.length)}..."');

          (onMessages ?? ConversationManager.instance.notify)(conversation, [message]);

          await _conversationsService.updateLastMessage(
            conversation.groupId,
            preview: text.length > 50 ? '${text.substring(0, 50)}...' : text,
            timestamp: event.createdAt,
            incrementUnread: !isOwn,
          );

          return true;

        case EventKindDto.commit:
          final newEpoch = result.event.epoch.toInt();
          moatLog('PollingService: Commit received for ${conversation.groupIdHex}, new epoch: $newEpoch');

          // Check if member list changed (e.g. new member added).
          final groupDids = await _authService.getGroupDids(conversation.groupId);
          final myDid = _authService.did;
          final otherDids = groupDids.where((did) => did != myDid).toList();
          final currentParticipants = List<String>.from(conversation.participants);
          final membersChanged = otherDids.length != currentParticipants.length ||
              !otherDids.every((did) => currentParticipants.contains(did));

          if (membersChanged) {
            conversation.participants
              ..clear()
              ..addAll(otherDids);
            moatLog('PollingService: Member list changed, new participants: $otherDids');
          }

          await _conversationsService.updateConversation(
            conversation.groupId,
            epoch: newEpoch,
          );
          if (membersChanged) {
            await _conversationsService.saveConversation(conversation);
            // Fetch Drawbridge configs for new members.
            for (final did in otherDids) {
              if (!currentParticipants.contains(did)) {
                try {
                  final urls = await _authService.atprotoClient.fetchDrawbridgeConfig(did);
                  DrawbridgeService.instance.cacheDrawbridgeConfig(did, urls);
                } catch (_) {}
              }
            }
          }

          await _authService.populateConversationTags(conversation.groupId);
          // Update Drawbridge watched tags.
          final session = _authService.moatSession;
          if (session != null) {
            final tags = session.populateCandidateTags(groupId: conversation.groupId);
            DrawbridgeService.instance.addTags(
              tags.map((t) => Uint8List.fromList(t)).toList(),
            );
          }
          return false;

        case EventKindDto.reaction:
          final rp = result.event.reactionPayload();
          if (rp != null) {
            final reactSenderDid = result.sender?.did ?? 'unknown';
            moatLog('PollingService: Reaction "${rp.emoji}" from $reactSenderDid');
            (onReaction ?? ConversationManager.instance.notifyReaction)(
              conversation,
              rp.targetMessageId,
              rp.emoji,
              reactSenderDid,
            );
          }
          return false;

        case EventKindDto.welcome:
        case EventKindDto.checkpoint:
        case EventKindDto.coord:
        case EventKindDto.syncApp:
        case EventKindDto.unknown:
          return false;
      }
    } catch (e) {
      moatLog('PollingService: Failed to decrypt event ${event.rkey} for ${conversation.groupIdHex}: $e');
      return false;
    }
  }

  /// Decrypt a ring-group event and dispatch coord messages to [DeviceRingService].
  Future<void> _processRingEvent(
    EventRecord event,
    Uint8List ringGroupId,
    MoatSessionHandle session,
  ) async {
    try {
      final result = await session.decryptEvent(
        groupId: ringGroupId,
        ciphertext: event.ciphertext,
      );
      await _authService.saveMlsState();

      if (result.event.kind == EventKindDto.coord) {
        await _ringService.handleCoordMsg(
          groupId: ringGroupId,
          payload: Uint8List.fromList(result.event.payload),
        );
      } else if (result.event.kind == EventKindDto.commit) {
        // Ring epoch advanced — refresh tag map for the new epoch.
        await _authService.populateConversationTags(ringGroupId);
      }
    } catch (e) {
      moatLog('PollingService: Failed to decrypt ring event ${event.rkey}: $e');
    }
  }

  /// Decrypt a coord-group event and dispatch it to [DeviceRingService.handleCoordMsg].
  ///
  /// Called for events whose tag maps to a group that is neither a user
  /// conversation nor the ring group — i.e. a DeviceCoord MLS group.
  Future<void> _processCoordEvent(
    EventRecord event,
    Uint8List coordGroupId,
    MoatSessionHandle session,
  ) async {
    try {
      final result = await session.decryptEvent(
        groupId: coordGroupId,
        ciphertext: event.ciphertext,
      );
      await _authService.saveMlsState();

      if (result.event.kind == EventKindDto.coord) {
        await _ringService.handleCoordMsg(
          groupId: coordGroupId,
          payload: Uint8List.fromList(result.event.payload),
        );
      }
    } catch (e) {
      moatLog('PollingService: Failed to decrypt coord event ${event.rkey}: $e');
    }
  }

  /// Decode a hex string into bytes.
  static Uint8List _hexToBytes(String hex) {
    final len = hex.length;
    final result = Uint8List(len ~/ 2);
    for (var i = 0; i < len; i += 2) {
      result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
    }
    return result;
  }

  /// Process a decrypted Welcome message.
  ///
  /// Handles both raw MLS Welcome bytes and the envelope format used by the
  /// Rust CLI's add-member flow (`[MWE1][4-byte len BE][welcome][hints_json]`).
  Future<void> _processWelcome(Uint8List data, String senderDid) async {
    final welcomeBytes = decodeWelcomeEnvelope(data);
    final groupId = await _authService.processWelcome(welcomeBytes);

    final session = _authService.moatSession;
    final epoch = session != null
        ? (await session.getGroupEpoch(groupId: groupId))?.toInt() ?? 1
        : 1;

    moatLog('PollingService: Joined group at epoch $epoch');

    await _authService.populateConversationTags(groupId);

    final groupDids = await _authService.getGroupDids(groupId);
    final myDid = _authService.did;

    final otherDids = groupDids.where((did) => did != myDid).toList();

    moatLog('PollingService: Joined group with participants: $groupDids');

    // If all members share our DID this is a device-coordination group, not a
    // user conversation — skip conversation creation.  Processing the Welcome
    // consumed this device's key-package init key, so replenish immediately so
    // the ring creator can add us using a fresh key package.
    if (otherDids.isEmpty) {
      moatLog('PollingService: Joined group is a coord group (all same DID), replenishing key package');
      try {
        await _authService.replenishKeyPackage();
      } catch (e) {
        moatLog('PollingService: replenishKeyPackage failed after coord Welcome: $e');
      }
      return;
    }

    final groupIdHex =
        groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    // Leave displayName null — the UI resolves it from participant profiles.
    final conversation = Conversation(
      groupId: groupId,
      participants: otherDids.isNotEmpty ? otherDids : [senderDid],
      epoch: epoch,
      keyBundleRef: 'key_bundle_$groupIdHex',
      createdAt: DateTime.now(),
    );

    await _conversationsService.saveConversation(conversation);

    // Register tags on own Drawbridge and fetch partner config.
    final db = DrawbridgeService.instance;
    if (session != null) {
      final tags = session.populateCandidateTags(groupId: groupId);
      db.addTags(tags.map((t) => Uint8List.fromList(t)).toList());
    }

    for (final did in otherDids) {
      try {
        final urls = await _authService.atprotoClient.fetchDrawbridgeConfig(did);
        db.cacheDrawbridgeConfig(did, urls);
      } catch (e) {
        moatLog('PollingService: Failed to fetch drawbridge config for $did: $e');
      }
    }
  }

  void dispose() {
    stopPolling();
  }

}
