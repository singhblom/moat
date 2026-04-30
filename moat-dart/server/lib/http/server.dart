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

/// Build the Shelf router with all moat-cli-compatible endpoints.
Handler buildRouter({
  required AuthService authService,
  required ConversationsService convsService,
  required WatchListService watchListService,
  required PollingService pollingService,
  required BlobService blobService,
  required DeviceRingService ringService,
  required SyncService syncService,
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

      final repo = ConversationManager.instance.getRepository(conv);
      final message = await repo.sendMessageSync(text);

      moatLog('Server: Message sent: ${message.id}');

      return Response.ok(
        jsonEncode({'message_id': message.messageIdHex ?? 'unknown'}),
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
      final message = await repo.sendImageSync(imageBytes, blobService);

      moatLog('Server: Image sent: ${message.id}');

      return Response.ok(
        jsonEncode(message.toJson()),
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

  // GET /ring-status — current ring group id and coord group count
  router.get('/ring-status', (Request request) async {
    final ringId = await ringService.ringGroupId();
    final ringIdHex = ringId == null
        ? null
        : ringId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return Response.ok(
      jsonEncode({
        'ring_group_id': ringIdHex,
        'coord_group_count': ringService.coordGroupCount(),
      }),
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

  // GET /sync/status — whether a sync session is active
  router.get('/sync/status', (Request request) {
    return Response.ok(
      jsonEncode({'active': syncService.isActive}),
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
