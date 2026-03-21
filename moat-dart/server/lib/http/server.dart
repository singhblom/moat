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

      // Initialize ConversationManager.
      // Storage is set up at server start, so just ensure auth is wired.
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
      }),
      headers: _jsonHeaders,
    );
  });

  // GET /conversations
  router.get('/conversations', (Request request) {
    final convs = convsService.conversations.map((c) => {
          'id': c.groupIdHex,
          'name': c.displayName,
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

  // GET /conversations/:group_id/messages
  router.get('/conversations/<groupId>/messages', (Request request, String groupId) async {
    final groupIdBytes = _hexToBytes(groupId);
    final conv = convsService.findByGroupId(groupIdBytes);
    if (conv == null) {
      return Response.notFound(
          jsonEncode({'error': 'conversation not found'}),
          headers: _jsonHeaders);
    }

    final repo = ConversationManager.instance.getRepository(conv);
    await repo.loadMessages();

    final messages = repo.messages.map((m) => {
          'from': m.senderDeviceId ?? m.senderDid,
          'content': m.content,
          'timestamp': m.timestamp.toIso8601String(),
          'is_own': m.isOwn,
          'sender_did': m.senderDid,
          'message_id': m.messageIdHex,
        }).toList();

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

  // 404 fallback
  router.all('/<ignored|.*>', (Request request) {
    return Response.notFound(
        jsonEncode({'error': 'not found'}), headers: _jsonHeaders);
  });

  return router.call;
}
