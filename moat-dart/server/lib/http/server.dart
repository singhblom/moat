import 'dart:convert';
import 'dart:typed_data';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// JSON content type header.
const _jsonHeaders = {'content-type': 'application/json'};

/// Helper to convert a hex string to bytes.
Uint8List _hexToBytes(String hex) {
  final len = hex.length;
  final result = Uint8List(len ~/ 2);
  for (var i = 0; i < len; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

/// Serialize a `PairingUiStateDto` the same way moat-core's `#[serde(tag =
/// "phase", rename_all = "snake_case")]` does on the Rust side, so
/// `GET /pair/status` matches moat-cli's wire shape exactly regardless of
/// which host answered it. `ring_id` is base64, mirroring the
/// `#[serde_as(as = "Base64")]` on the Rust struct field.
Map<String, dynamic> _pairingUiStateJson(PairingUiStateDto state) {
  return state.when(
    idle: () => {'phase': 'idle'},
    showingCode: (code, uri) => {'phase': 'showing_code', 'code': code, 'uri': uri},
    awaitingPeer: () => {'phase': 'awaiting_peer'},
    awaitingApproval: (deviceName, did) =>
        {'phase': 'awaiting_approval', 'device_name': deviceName, 'did': did},
    done: (ringId) => {'phase': 'done', 'ring_id': base64Encode(ringId)},
    failed: (reason) => {'phase': 'failed', 'reason': reason},
  );
}

Map<String, dynamic> _syncRequestUiStateJson(SyncRequestUiStateDto state) {
  return state.when(
    idle: () => {'phase': 'idle'},
    awaitingPeer: () => {'phase': 'awaiting_peer'},
    awaitingApproval: (deviceName) =>
        {'phase': 'awaiting_approval', 'device_name': deviceName},
    active: () => {'phase': 'active'},
    complete: (tally, deviceName) => {
      'phase': 'complete',
      'tally': {
        'messages': tally.messages.toInt(),
        'conversations': tally.conversations.toInt(),
        'sent_messages': tally.sentMessages.toInt(),
        'sent_conversations': tally.sentConversations.toInt(),
      },
      'device_name': deviceName,
    },
    failed: (reason) => {'phase': 'failed', 'reason': _syncFailureJson(reason)},
  );
}

String _hexBytes(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Serialize a `SyncFailureDto` the way `moat_core::SyncFailure` does —
/// a tagged object, so callers match on `kind` rather than parsing prose.
Map<String, dynamic> _syncFailureJson(SyncFailureDto reason) {
  return reason.when(
    noAnswer: () => {'kind': 'no_answer'},
    requestExpired: () => {'kind': 'request_expired'},
    declined: () => {'kind': 'declined'},
    channelClosed: (detail) => {'kind': 'channel_closed', 'detail': detail},
    publishFailed: (detail) => {'kind': 'publish_failed', 'detail': detail},
  );
}

/// Shared response for `/pair/approve`, `/pair/reject`, `/pair/cancel`:
/// `{"ok": true}` on success, or a 500 with the failure reason if the
/// session landed in `Failed` as a result of the call (mirrors moat-cli's
/// `app_err`-wrapped `Result<()>` handlers — a *reported* failure, not
/// silently swallowed into a 200).
Response _pairResultResponse(PairingService pairingService) {
  final uiState = pairingService.state.value;
  if (uiState is PairingUiStateDto_Failed) {
    return Response(500,
        body: jsonEncode({'error': uiState.reason}), headers: _jsonHeaders);
  }
  return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
}

/// Build the Shelf router with all moat-cli-compatible endpoints.
Handler buildRouter({
  required AuthService authService,
  required ConversationsService convsService,
  required WatchListService watchListService,
  required PollingService pollingService,
  required BlobService blobService,
  required DeviceRingService ringService,
  required SyncService syncService,
  required PairingService pairingService,
  required SyncRequestService syncRequestService,
  MessageStorage? messageStorage,
}) {
  final router = Router();

  // POST /login
  router.post('/login', (Request request) async {
    try {
      final body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final handle = body['handle'] as String;
      final password = body['password'] as String;
      final deviceName = (body['device_name'] as String?) ?? 'dart-server';

      await authService.login(handle, password, deviceName: deviceName);

      // Initialize services after login.
      await convsService.init();
      await watchListService.init();

      moatLog('Server: Login successful for $handle');

      return Response.ok(
        jsonEncode({'ok': true, 'did': authService.did, 'handle': authService.handle}),
        headers: _jsonHeaders,
      );
    } catch (e) {
      moatLog('Server: Login error: $e');
      return Response(401,
          body: jsonEncode({'error': e.toString()}),
          headers: _jsonHeaders);
    }
  });

  // GET /status
  router.get('/status', (Request request) {
    return Response.ok(
      jsonEncode({
        'logged_in': authService.isAuthenticated,
        'handle': authService.handle,
        'did': authService.did,
        'drawbridge_connected': DrawbridgeService.instance.isOwnConnected,
      }),
      headers: _jsonHeaders,
    );
  });

  // GET /conversations
  router.get('/conversations', (Request request) {
    final convs = convsService.conversations.map((c) => {
          'id': c.groupIdHex,
          'name': c.resolveDisplayName((did) => did),
          'participant_dids': c.participants,
          'is_member': c.isMember,
          'epoch': c.epoch,
          'unread': c.unreadCount,
        }).toList();
    return Response.ok(jsonEncode(convs), headers: _jsonHeaders);
  });

  // POST /conversations — start a conversation with a recipient
  router.post('/conversations', (Request request) async {
    if (!authService.isAuthenticated) {
      return Response(401,
          body: jsonEncode({'error': 'not logged in'}), headers: _jsonHeaders);
    }

    try {
      final body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final recipientHandle = body['recipient_handle'] as String;

      moatLog('Server: Starting conversation with $recipientHandle');

      final conversation = await startConversation(
        recipientHandle: recipientHandle,
        authService: authService,
        convsService: convsService,
      );

      moatLog('Server: Conversation ${conversation.groupIdHex} created');

      return Response.ok(
        jsonEncode({'group_id': conversation.groupIdHex}),
        headers: _jsonHeaders,
      );
    } catch (e) {
      moatLog('Server: Error starting conversation: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /conversations/:group_id/members — add a member to an existing group
  router.post('/conversations/<groupId>/members',
      (Request request, String groupId) async {
    if (!authService.isAuthenticated) {
      return Response(401,
          body: jsonEncode({'error': 'not logged in'}), headers: _jsonHeaders);
    }

    try {
      final body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final handle = body['handle'] as String;
      final groupIdBytes = _hexToBytes(groupId);

      moatLog('Server: Adding $handle to group $groupId');

      await addMemberToConversation(
        memberHandle: handle,
        groupId: groupIdBytes,
        authService: authService,
        convsService: convsService,
      );

      moatLog('Server: Added $handle to group $groupId');

      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: Error adding member: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // GET /conversations/:group_id/messages
  router.get('/conversations/<groupId>/messages', (Request request, String groupId) async {
    final groupIdBytes = _hexToBytes(groupId);
    final conv = convsService.findByGroupId(groupIdBytes);

    List<Map<String, dynamic>> messages;
    if (conv != null) {
      final repo = ConversationManager.instance.getRepository(conv);
      await repo.loadMessages();
      messages = repo.messages.map((m) => {
            'from': m.senderDeviceId ?? m.senderDid,
            'content': m.content,
            'timestamp': m.timestamp.toIso8601String(),
            'is_own': m.isOwn,
            'sender_did': m.senderDid,
            'message_id': m.messageIdHex,
            'attachment': m.attachment?.toJson(),
            'reactions': m.reactions
                .map((r) => {'emoji': r.emoji, 'sender_did': r.senderDid})
                .toList(),
            'status': m.status.name,
            if (m.sendError != null) 'send_error': m.sendError,
          }).toList();
    } else if (messageStorage != null) {
      // Conversation not yet registered locally (e.g. synced history before
      // polling fetched the Welcome). Load directly from MessageStorage so
      // get_messages works even before the MLS Welcome is processed.

      // This is too much logic for the server and should probably go in a service.
      final stored = await messageStorage.loadMessages(groupId);
      messages = stored.map((m) => {
            'from': m.senderDeviceId ?? m.senderDid,
            'content': m.content,
            'timestamp': m.timestamp.toIso8601String(),
            'is_own': m.isOwn,
            'sender_did': m.senderDid,
            'message_id': m.messageIdHex,
            'attachment': m.attachment?.toJson(),
            'reactions': m.reactions
                .map((r) => {'emoji': r.emoji, 'sender_did': r.senderDid})
                .toList(),
          }).toList();
      // Return [] when empty (mirrors Rust's api_set_active_conversation fallback).
    } else {
      return Response.notFound(
          jsonEncode({'error': 'conversation not found'}),
          headers: _jsonHeaders);
    }

    return Response.ok(jsonEncode(messages), headers: _jsonHeaders);
  });

  // POST /conversations/:group_id/messages
  router.post('/conversations/<groupId>/messages',
      (Request request, String groupId) async {
    if (!authService.isAuthenticated) {
      return Response(401,
          body: jsonEncode({'error': 'not logged in'}), headers: _jsonHeaders);
    }

    try {
      final body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final text = body['text'] as String;

      final groupIdBytes = _hexToBytes(groupId);
      final conv = convsService.findByGroupId(groupIdBytes);
      if (conv == null) {
        return Response.notFound(
            jsonEncode({'error': 'conversation not found'}),
            headers: _jsonHeaders);
      }
      if (!conv.isMember) {
        return Response(409,
            body: jsonEncode(
                {'error': 'waiting to be connected to this conversation'}),
            headers: _jsonHeaders);
      }

      // Returns once the send is under way, as moat-cli does; the
      // outcome shows as the message's `status`.
      final repo = ConversationManager.instance.getRepository(conv);
      final localId = repo.sendMessage(text);

      return Response.ok(
        jsonEncode({'message_id': repo.pendingMessage(localId)?.messageIdHex}),
        headers: _jsonHeaders,
      );
    } catch (e) {
      moatLog('Server: Error sending message: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /conversations/:group_id/messages/image — send an image
  router.post('/conversations/<groupId>/messages/image',
      (Request request, String groupId) async {
    if (!authService.isAuthenticated) {
      return Response(401,
          body: jsonEncode({'error': 'not logged in'}), headers: _jsonHeaders);
    }

    try {
      final imageBytes = Uint8List.fromList(await request.read().expand((b) => b).toList());
      if (imageBytes.isEmpty) {
        return Response(400,
            body: jsonEncode({'error': 'empty body'}), headers: _jsonHeaders);
      }

      final groupIdBytes = _hexToBytes(groupId);
      final conv = convsService.findByGroupId(groupIdBytes);
      if (conv == null) {
        return Response.notFound(
            jsonEncode({'error': 'conversation not found'}),
            headers: _jsonHeaders);
      }

      final repo = ConversationManager.instance.getRepository(conv);
      final localId = repo.sendImage(imageBytes, blobService);

      return Response.ok(
        jsonEncode({'message_id': repo.pendingMessage(localId)?.messageIdHex}),
        headers: _jsonHeaders,
      );
    } catch (e) {
      moatLog('Server: Error sending image: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /conversations/:group_id/messages/:message_id/reactions
  router.post(
      '/conversations/<groupId>/messages/<messageId>/reactions',
      (Request request, String groupId, String messageId) async {
    if (!authService.isAuthenticated) {
      return Response(401,
          body: jsonEncode({'error': 'not logged in'}), headers: _jsonHeaders);
    }

    try {
      final body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final emoji = body['emoji'] as String;

      final groupIdBytes = _hexToBytes(groupId);
      final conv = convsService.findByGroupId(groupIdBytes);
      if (conv == null) {
        return Response.notFound(
            jsonEncode({'error': 'conversation not found'}),
            headers: _jsonHeaders);
      }

      final repo = ConversationManager.instance.getRepository(conv);
      await repo.loadMessages();

      // Find the target message.
      final targetMsg = repo.messages.firstWhere(
        (m) => m.messageIdHex == messageId,
        orElse: () => throw StateError('message not found: $messageId'),
      );

      await repo.sendReaction(targetMsg, emoji);

      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: Error sending reaction: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /conversations/:group_id/messages/:message_id/retry
  router.post('/conversations/<groupId>/messages/<messageId>/retry',
      (Request request, String groupId, String messageId) async {
    final conv = convsService.findByGroupId(_hexToBytes(groupId));
    if (conv == null) {
      return Response.notFound(
          jsonEncode({'error': 'conversation not found'}),
          headers: _jsonHeaders);
    }
    final repo = ConversationManager.instance.getRepository(conv);
    await repo.loadMessages();
    if (!repo.retryMessage(messageId, blobService: blobService)) {
      return Response(400,
          body: jsonEncode({'error': 'this message cannot be retried'}),
          headers: _jsonHeaders);
    }
    return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
  });

  // POST /watch — add a handle to watch list
  router.post('/watch', (Request request) async {
    if (!authService.isAuthenticated) {
      return Response(401,
          body: jsonEncode({'error': 'not logged in'}), headers: _jsonHeaders);
    }

    try {
      final body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final handle = body['handle'] as String;

      await watchListService.addHandle(handle);

      if (watchListService.error != null) {
        return Response(400,
            body: jsonEncode({'error': watchListService.error}),
            headers: _jsonHeaders);
      }

      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: Error adding watch: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /poll — trigger a single poll cycle
  router.post('/poll', (Request request) async {
    final stats = await pollingService.pollOnce();
    return Response.ok(
      jsonEncode({
        'new_messages': stats.newMessages,
        'new_conversations': stats.newConversations,
      }),
      headers: _jsonHeaders,
    );
  });

  // POST /poll/:seconds — set auto-poll interval
  router.post('/poll/<seconds>', (Request request, String seconds) {
    final secs = int.tryParse(seconds) ?? 0;
    pollingService.stopPolling();
    if (secs > 0) {
      pollingService.startPolling(interval: Duration(seconds: secs));
      moatLog('Server: Auto-poll set to every ${secs}s');
    } else {
      moatLog('Server: Auto-poll disabled');
    }
    return Response.ok(jsonEncode({'ok': true, 'interval': secs}),
        headers: _jsonHeaders);
  });

  // GET /conversations/:group_id/messages/:message_id/image — fetch decrypted image
  router.get(
      '/conversations/<groupId>/messages/<messageId>/image',
      (Request request, String groupId, String messageId) async {
    if (!authService.isAuthenticated) {
      return Response(401,
          body: jsonEncode({'error': 'not logged in'}), headers: _jsonHeaders);
    }

    try {
      final groupIdBytes = _hexToBytes(groupId);
      final conv = convsService.findByGroupId(groupIdBytes);
      if (conv == null) {
        return Response.notFound(
            jsonEncode({'error': 'conversation not found'}),
            headers: _jsonHeaders);
      }

      final repo = ConversationManager.instance.getRepository(conv);
      await repo.loadMessages();

      final msg = repo.messages.firstWhere(
        (m) => m.messageIdHex == messageId,
        orElse: () => throw StateError('message not found'),
      );

      final att = msg.attachment;
      if (att == null || att is! ImageAttachment) {
        return Response(400,
            body: jsonEncode({'error': 'not an image message'}),
            headers: _jsonHeaders);
      }

      final plaintext = await blobService.fetchAndDecrypt(
        uri: att.uri,
        key: att.key,
        ciphertextHash: att.ciphertextHash,
        contentHash: att.contentHash,
      );

      final mime = att.mime ?? 'application/octet-stream';
      return Response.ok(plaintext, headers: {'content-type': mime});
    } catch (e) {
      moatLog('Server: Error fetching image: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /ring-tick — drive one ring coordination tick
  router.post('/ring-tick', (Request request) async {
    try {
      await ringService.tick();
      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: ring-tick error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // GET /ring-status — current ring group id, coord group count, and this
  // device's own MLS view of ring membership (0 if not in a ring) — lets a
  // bystander sibling's convergence (or lack of it) after another device's
  // pairing be observed at all, matching moat-cli's `/ring-status`.
  router.get('/ring-status', (Request request) async {
    final ringId = await ringService.ringGroupId();
    final ringIdHex = ringId == null
        ? null
        : ringId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    var ringMemberCount = 0;
    var ringDevices = <Map<String, dynamic>>[];
    final session = authService.moatSession;
    if (ringId != null && session != null) {
      try {
        final creds = await session.getGroupMemberCredentials(groupId: ringId);
        ringMemberCount = creds.length;
        // Names come from the ring's own MLS leaf credentials, so this
        // list is exactly "who can read your messages" rather than a
        // self-reported roster. Matches moat-cli's `/ring-status`.
        final myDeviceId = session.deviceId();
        final myDeviceIdHex = _hexBytes(myDeviceId);
        ringDevices = [
          for (final c in creds)
            {
              'device_id': _hexBytes(c.deviceId),
              'device_name': c.deviceName,
              'is_self': _hexBytes(c.deviceId) == myDeviceIdHex,
            }
        ];
      } catch (e) {
        moatLog('Server: ring-status getGroupMemberCredentials failed: $e');
      }
    }
    return Response.ok(
      jsonEncode({
        'ring_group_id': ringIdHex,
        'coord_group_count': ringService.coordGroupCount(),
        'ring_member_count': ringMemberCount,
        'devices': ringDevices,
      }),
      headers: _jsonHeaders,
    );
  });

  // POST /pair/new — new device requests a pairing code.
  router.post('/pair/new', (Request request) async {
    try {
      final code = await pairingService.startEnroll();
      return Response.ok(jsonEncode({'code': code}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: pair/new error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /pair/confirm — existing device enters a pairing code. No longer
  // implies approval of the resulting Enroll — see /pair/approve.
  router.post('/pair/confirm', (Request request) async {
    try {
      final body = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final code = body['code'] as String;
      await pairingService.confirmCode(code);
      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: pair/confirm error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /pair/approve — existing device: approve the pending Enroll
  // `pairingService.state` reports as `awaiting_approval`. No host,
  // including this headless server, auto-approves anymore.
  router.post('/pair/approve', (Request request) async {
    try {
      await pairingService.approvePending();
    } catch (e) {
      moatLog('Server: pair/approve error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
    return _pairResultResponse(pairingService);
  });

  // POST /pair/reject — existing device: decline the pending Enroll.
  router.post('/pair/reject', (Request request) async {
    try {
      await pairingService.rejectPending();
    } catch (e) {
      moatLog('Server: pair/reject error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
    return _pairResultResponse(pairingService);
  });

  // POST /pair/cancel — either role: abort an in-flight pairing before it
  // reaches a terminal state.
  router.post('/pair/cancel', (Request request) async {
    try {
      await pairingService.cancel();
    } catch (e) {
      moatLog('Server: pair/cancel error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
    return _pairResultResponse(pairingService);
  });

  // GET /pair/status — the serialized `PairingUiStateDto` verbatim, e.g.
  // `{"phase":"showing_code","code":"...","uri":"..."}` or
  // `{"phase":"failed","reason":"..."}` — matching moat-cli's
  // `/pair/status` exactly. No host-specific shape on top.
  router.get('/pair/status', (Request request) async {
    return Response.ok(
      jsonEncode(_pairingUiStateJson(pairingService.state.value)),
      headers: _jsonHeaders,
    );
  });

  // POST /sync/start — trigger a ring tick (offerer fires sync offer internally)
  router.post('/sync/start', (Request request) async {
    try {
      await ringService.tick();
      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: sync/start error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /sync/request — ask this user's other devices for history this
  // one is missing. A sibling's user must accept (`POST /sync/accept`);
  // no host answers automatically, matching pairing's approval rule.
  router.post('/sync/request', (Request request) async {
    try {
      await syncRequestService.requestSync();
      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: sync/request error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /sync/offer — send history to a sibling that lacks it. This call
  // is the human approval; the target joins without prompting.
  router.post('/sync/offer', (Request request) async {
    try {
      final body =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final deviceId = _hexToBytes(body['device_id'] as String);
      await syncRequestService.offerSync(deviceId);
      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: sync/offer error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /sync/accept — send this device's history to the sibling that
  // asked for it.
  router.post('/sync/accept', (Request request) async {
    try {
      await syncRequestService.accept();
      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: sync/accept error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // POST /sync/decline — refuse a sibling's request. Local only: the
  // requester keeps waiting for another sibling.
  router.post('/sync/decline', (Request request) async {
    try {
      syncRequestService.decline();
      return Response.ok(jsonEncode({'ok': true}), headers: _jsonHeaders);
    } catch (e) {
      moatLog('Server: sync/decline error: $e');
      return Response(500,
          body: jsonEncode({'error': e.toString()}), headers: _jsonHeaders);
    }
  });

  // GET /sync/status — whether a transfer is running, plus the
  // sync-request projection verbatim, matching moat-cli's shape.
  router.get('/sync/status', (Request request) {
    return Response.ok(
      jsonEncode({
        'active': syncService.isActive,
        'request': _syncRequestUiStateJson(syncRequestService.refresh()),
      }),
      headers: _jsonHeaders,
    );
  });

  // 404 fallback
  router.all('/<ignored|.*>', (Request request) {
    return Response.notFound(
        jsonEncode({'error': 'not found'}), headers: _jsonHeaders);
  });

  return router.call;
}
