import 'dart:async';
import 'dart:typed_data';
import '../models/conversation.dart';
import '../models/message.dart';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'watch_list_service.dart';
import '../rust/api/simple.dart';
import '../utils/message_payload.dart';
import '../utils/platform_int64.dart';
import 'atproto_client.dart';
import 'conversation_manager.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'secure_storage.dart';
import 'debug_log.dart';

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

  /// Callback fired at the start of every poll cycle, for state that needs
  /// a clock the services themselves don't have — today, expiring an
  /// unanswered sync request.
  void Function()? onPollTick;

  /// Callback for any `ring.msg` a sibling published — a request for
  /// history, or an offer of it.
  ///
  /// The device name *and id* both come from the sender's MLS leaf
  /// credential, not from the payload: that authentication is the whole
  /// reason this lane is the ring rather than the stealth one. Unset means
  /// the host doesn't support these and the message is dropped.
  Future<void> Function(
    Uint8List payload,
    String deviceName,
    Uint8List deviceId,
  )? onRingMessage;

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
    // Runs before the early returns: a sync request whose rendezvous has
    // expired must be reported as failed even while polling is suppressed
    // or the device is logged out mid-request.
    onPollTick?.call();
    if (_isPolling) return const PollStats(newMessages: 0, newConversations: 0);
    if (!_authService.isAuthenticated) {
      return const PollStats(newMessages: 0, newConversations: 0);
    }

    _isPolling = true;

    var newMessages = 0;
    var newConversations = 0;

    try {
      await _refreshDrawbridgeConfigs();
      unawaited(_authService.publishDrawbridgeRecord());
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

  /// Re-read the relay lists of every conversation's members and this user
  /// that are missing or older than [DrawbridgeService.configTtl].
  Future<void> _refreshDrawbridgeConfigs() async {
    final dids = <String>{
      if (_authService.did != null) _authService.did!,
      for (final conv in _conversationsService.conversations) ...conv.participants,
    };
    final db = DrawbridgeService.instance;
    await db.refreshDrawbridgeConfigs(
        _authService.atprotoClient, db.staleConfigDids(dids));
  }

  /// Poll our own DID for incoming welcome messages.
  Future<int> _pollOwnDid() async {
    final myDid = _authService.did;
    if (myDid == null) return 0;

    final client = _authService.atprotoClient;
    var newConvs = 0;

    // Events up to this rkey have already been processed by the ring driver's
    // tick() (the same-user key-package-lane SiblingMsg payloads). Skip
    // welcome processing for those but still advance the polling cursor
    // past them.
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

        // Skip events the ring driver already consumed (SiblingMsg payloads).
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
    // Always include own DID so ring-group events on our own PDS records
    // are routed to _processRingEvent even when there are no user
    // conversations yet.
    allParticipantDids.add(myDid);

    moatLog('PollingService: Polling ${allParticipantDids.length} unique DIDs for messages');

    final ringGroupId = await _ringService.ringGroupId();
    final ringGroupIdHex =
        ringGroupId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    await _prepareSession(session);

    // Fetch every DID first; the inbox orders events across them by rkey.
    final cursors = <String, String>{};
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
          session.inboxPush(
            event: InboxEventDto(
              sourceDid: did,
              rkey: event.rkey,
              authorDid: did,
              tag: event.tag,
              ciphertext: event.ciphertext,
              createdAtMs: toPlatformInt64(event.createdAt.millisecondsSinceEpoch),
            ),
          );
        }
        if (maxRkey != null) cursors[messageRkeyKey] = maxRkey;
      } catch (e, stack) {
        moatLog('PollingService: Error polling messages from $did: $e');
        moatLog('PollingService: Stack: $stack');
      }
    }

    // Processing a commit or Welcome generates tags, waking parked events.
    final tagMap = await _secureStorage.loadTagMap();
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    var newMsgs = 0;
    for (var event = session.inboxPopReady(); event != null; event = session.inboxPopReady()) {
      if (await _processInboxEvent(event, tagMap, ringGroupId, ringGroupIdHex, myDid, session, nowMs)) {
        newMsgs++;
      }
    }

    final expired = session.inboxExpire(nowMs: toPlatformInt64(nowMs));
    if (expired > 0) {
      moatLog('PollingService: dropped $expired parked event(s) that never became readable');
    }
    await _secureStorage.saveParkedEvents(session.exportParkedEvents());

    // Move cursors only once their events are processed or parked.
    for (final entry in cursors.entries) {
      await _secureStorage.saveLastRkey(entry.key, entry.value);
    }

    return newMsgs;
  }

  /// The session [_prepareSession] last ran for.
  MoatSessionHandle? _preparedSession;

  /// Before a session's first poll: populate every group's candidate tags and
  /// restore parked events. Mirrors moat-cli's `load_conversations_sync`.
  Future<void> _prepareSession(MoatSessionHandle session) async {
    if (identical(_preparedSession, session)) return;
    _preparedSession = session;

    final groupIds = [
      for (final conv in _conversationsService.conversations) conv.groupId,
      if (await _ringService.ringGroupId() case final ringId?) ringId,
    ];
    for (final groupId in groupIds) {
      try {
        await _authService.populateConversationTags(groupId);
      } catch (e) {
        moatLog('PollingService: could not populate tags for a group: $e');
      }
    }

    final bytes = await _secureStorage.loadParkedEvents();
    if (bytes == null) return;
    try {
      session.importParkedEvents(bytes: bytes);
    } catch (e) {
      moatLog('PollingService: could not restore parked events: $e');
    }
  }

  /// Process an inbox event, or park it. Returns true if a message was stored.
  Future<bool> _processInboxEvent(
    InboxEventDto event,
    Map<String, String> tagMap,
    Uint8List? ringGroupId,
    String? ringGroupIdHex,
    String myDid,
    MoatSessionHandle session,
    int nowMs,
  ) async {
    final tagHex = event.tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    // The persisted tag map covers groups not repopulated since a restart.
    final groupId = session.groupForTag(tag: event.tag);
    final groupIdHex = groupId != null
        ? groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join()
        : tagMap[tagHex];

    if (groupIdHex == null) {
      // A stealth payload this device published never decrypts here.
      if (event.sourceDid != myDid) {
        session.inboxPark(event: event, nowMs: toPlatformInt64(nowMs));
      }
      return false;
    }

    final record = EventRecord(
      uri: '',
      rkey: event.rkey,
      tag: event.tag,
      ciphertext: event.ciphertext,
      createdAt: DateTime.fromMillisecondsSinceEpoch(
        platformInt64ToInt(event.createdAtMs),
        isUtc: true,
      ),
    );

    if (ringGroupId != null && groupIdHex == ringGroupIdHex) {
      moatLog('PollingService: dispatching ring event rkey=${event.rkey} to _processRingEvent');
      await _processRingEvent(record, ringGroupId, session);
      await _advanceScanWindow(event.tag, groupIdHex, tagMap, session);
      return false;
    }

    final conversation = _conversationsService.conversations
        .where((c) => c.groupIdHex == groupIdHex)
        .firstOrNull;
    if (conversation == null) {
      moatLog('PollingService: event ${event.rkey} tag=$tagHex matched an unknown group $groupIdHex — dropped');
      return false;
    }

    final stored = await _processConversationEvent(record, conversation, event.sourceDid, session);
    await _advanceScanWindow(event.tag, groupIdHex, tagMap, session);
    return stored;
  }

  /// Slide the tag window past a matched event and register the new tags,
  /// including in [tagMap] for later events in this poll.
  Future<void> _advanceScanWindow(
    List<int> tag,
    String groupIdHex,
    Map<String, String> tagMap,
    MoatSessionHandle session,
  ) async {
    final newTags = session
        .advanceScanWindow(tag: Uint8List.fromList(tag))
        .map((t) => Uint8List.fromList(t))
        .toList();
    if (newTags.isEmpty) return;
    for (final t in newTags) {
      tagMap[t.map((b) => b.toRadixString(16).padLeft(2, '0')).join()] = groupIdHex;
    }
    await _authService.registerTags(newTags, groupIdHex);
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
            await DrawbridgeService.instance.refreshDrawbridgeConfigs(
                _authService.atprotoClient,
                otherDids.where((did) => !currentParticipants.contains(did)));
          }

          await _authService.populateConversationTags(conversation.groupId);
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
        // Ring application traffic never appears in a user conversation —
        // it is handled in `_processRingEvent`.
        case EventKindDto.ringMsg:
        case EventKindDto.unknown:
          return false;
      }
    } catch (e) {
      moatLog('PollingService: Failed to decrypt event ${event.rkey} for ${conversation.groupIdHex}: $e');
      return false;
    }
  }

  /// Decrypt a ring-group event: membership/epoch commits, plus the
  /// `ring.msg` application lane a sibling uses to ask for history.
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

      if (result.event.kind == EventKindDto.commit) {
        // Ring epoch advanced — refresh tag map for the new epoch.
        await _authService.populateConversationTags(ringGroupId);
        return;
      }

      if (result.event.kind == EventKindDto.ringMsg) {
        // The sender's identity is whatever MLS says it is; the payload
        // declares no device of its own.
        final senderDid = result.sender?.did;
        if (senderDid != _authService.did) {
          moatLog('PollingService: ignoring a ring message whose sender is not us');
          return;
        }
        final handler = onRingMessage;
        final sender = result.sender;
        if (handler == null) return;
        if (sender == null) {
          moatLog('PollingService: ignoring a ring message MLS could not attribute');
          return;
        }
        await handler(
          Uint8List.fromList(result.event.payload),
          sender.deviceName.isEmpty ? 'an unnamed device' : sender.deviceName,
          Uint8List.fromList(sender.deviceId),
        );
      }
    } catch (e) {
      moatLog('PollingService: Failed to decrypt ring event ${event.rkey}: $e');
    }
  }

  /// Process a decrypted Welcome message (raw MLS Welcome bytes).
  Future<void> _processWelcome(Uint8List data, String senderDid) async {
    final groupId = await _authService.processWelcome(data);

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

    // A group where all members share our DID cannot legitimately arrive
    // via this cross-user stealth path: ring membership changes ride the
    // pairing channel or direct MLS adds. Processing the Welcome already
    // consumed this device's key-package init key, so replenish, but don't
    // surface a conversation.
    if (otherDids.isEmpty) {
      moatLog('PollingService: same-DID Welcome via stealth is unexpected (replenishing key only)');
      try {
        await _authService.replenishKeyPackage();
      } catch (e) {
        moatLog('PollingService: replenishKeyPackage failed after same-DID Welcome: $e');
      }
      return;
    }

    final groupIdHex =
        groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    // Leave displayName null — the UI resolves it from participant profiles.
    final conversation = Conversation(
      groupId: groupId,
      participants: otherDids.isNotEmpty ? otherDids : [senderDid],
      keyBundleRef: 'key_bundle_$groupIdHex',
      createdAt: DateTime.now(),
    );

    await _conversationsService.saveConversation(conversation);

    // Fetch the Drawbridges of the members and of our own other devices.
    await DrawbridgeService.instance.refreshDrawbridgeConfigs(
        _authService.atprotoClient,
        [...otherDids, if (_authService.did != null) _authService.did!]);
  }

  void dispose() {
    stopPolling();
  }

}
