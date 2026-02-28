import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/conversation.dart';
import 'package:moat_flutter/models/message.dart';
import 'package:moat_flutter/services/conversation_repository.dart';
import 'package:moat_flutter/services/message_storage.dart';
import 'package:moat_flutter/services/send_queue.dart';
import 'package:moat_flutter/services/send_service.dart';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// Fake SendService that returns synthetic messages without crypto or network.
class FakeSendService implements SendService {
  int callCount = 0;
  bool shouldFail = false;

  @override
  Future<Message> sendMessage({
    required Conversation conversation,
    required String text,
    required String localId,
  }) async {
    callCount++;
    if (shouldFail) throw SendException('Mock failure');
    return Message(
      id: '${conversation.groupIdHex}_rkey_$callCount',
      localId: localId,
      groupId: conversation.groupId,
      senderDid: 'did:plc:me',
      content: text,
      timestamp: DateTime.utc(2025, 1, 15, 12, 0, callCount),
      isOwn: true,
      epoch: 0,
      status: MessageStatus.sent,
      messageId: Uint8List.fromList(List.generate(16, (i) => callCount + i)),
    );
  }

  @override
  Future<void> sendReaction({
    required Conversation conversation,
    required List<int> targetMessageId,
    required String emoji,
  }) async {
    if (shouldFail) throw SendException('Mock failure');
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Conversation makeConversation({List<int> groupIdBytes = const [1, 2, 3, 4]}) {
  return Conversation(
    groupId: Uint8List.fromList(groupIdBytes),
    displayName: 'Test',
    participants: ['did:plc:alice', 'did:plc:bob'],
    keyBundleRef: 'test-ref',
    createdAt: DateTime.utc(2025, 1, 1),
  );
}

Message makeMessage({
  String id = 'msg-1',
  List<int> groupIdBytes = const [1, 2, 3, 4],
  String senderDid = 'did:plc:alice',
  String content = 'Hello!',
  DateTime? timestamp,
  bool isOwn = false,
  int epoch = 0,
  MessageStatus status = MessageStatus.sent,
  String? localId,
  List<int>? messageId,
  List<Reaction> reactions = const [],
}) {
  return Message(
    id: id,
    groupId: Uint8List.fromList(groupIdBytes),
    senderDid: senderDid,
    content: content,
    timestamp: timestamp ?? DateTime.utc(2025, 1, 15, 12, 0, 0),
    isOwn: isOwn,
    epoch: epoch,
    status: status,
    localId: localId,
    messageId: messageId != null ? Uint8List.fromList(messageId) : null,
    reactions: reactions,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  late Directory tempDir;
  late MessageStorage storage;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('integration_test_');
    storage = MessageStorage(directory: tempDir);
  });

  tearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  /// Create a ConversationRepository wired to a FakeSendService.
  ConversationRepository makeRepo(
    Conversation conv, {
    FakeSendService? fake,
  }) {
    final f = fake ?? FakeSendService();
    final queue = SendQueue(sendService: f, conversation: conv);
    return ConversationRepository(
      groupIdHex: conv.groupIdHex,
      groupId: conv.groupId,
      storage: storage,
      sendQueue: queue,
    );
  }

  group('full send flow', () {
    test('sendMessage creates optimistic, then confirms on success', () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);
      await repo.loadMessages();

      // Send a message — optimistic appears immediately.
      final localId = repo.sendMessage('Hello');
      expect(repo.messages.length, 1);
      expect(repo.messages.first.status, MessageStatus.sending);
      expect(repo.messages.first.content, 'Hello');

      // Let the queue process (async).
      await Future.delayed(Duration.zero);
      await Future.delayed(Duration.zero);

      // After processing, message should be confirmed.
      expect(repo.messages.length, 1);
      expect(repo.messages.first.status, MessageStatus.sent);
      expect(repo.messages.first.localId, localId);
      expect(repo.messages.first.messageId, isNotNull);

      // Verify persisted to disk.
      final onDisk = await storage.loadMessages(conv.groupIdHex);
      expect(onDisk.length, 1);
      expect(onDisk.first.status, MessageStatus.sent);
    });
  });

  group('send failure + retry', () {
    test('failure marks optimistic as failed, retry recovers', () async {
      final conv = makeConversation();
      final fake = FakeSendService()..shouldFail = true;
      final repo = makeRepo(conv, fake: fake);
      await repo.loadMessages();

      // Send — will fail.
      final localId = repo.sendMessage('Hello');
      await Future.delayed(Duration.zero);
      await Future.delayed(Duration.zero);

      expect(repo.messages.length, 1);
      expect(repo.messages.first.status, MessageStatus.failed);

      // Retry — now succeeds.
      fake.shouldFail = false;
      repo.retryMessage(localId);
      await Future.delayed(Duration.zero);
      await Future.delayed(Duration.zero);

      expect(repo.messages.length, 1);
      expect(repo.messages.first.status, MessageStatus.sent);
    });
  });

  group('polling echo dedup', () {
    test('polling echo with same messageId does not duplicate', () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);
      await repo.loadMessages();

      // Send a message.
      repo.sendMessage('Hello');
      await Future.delayed(Duration.zero);
      await Future.delayed(Duration.zero);

      final sentMsg = repo.messages.first;
      expect(sentMsg.status, MessageStatus.sent);

      // Polling delivers the echo with the same id (same groupIdHex_rkey
      // as SendService produced — both derive from the AT URI rkey).
      final echo = makeMessage(
        id: sentMsg.id,
        content: 'Hello',
        messageId: sentMsg.messageId!.toList(),
        isOwn: true,
      );
      await repo.mergeFromPolling([echo]);

      // Should still have exactly one message (deduped by id).
      expect(repo.messages.length, 1);
    });
  });

  group('background receive (not loaded)', () {
    test('mergeFromPolling appends to storage without loading', () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);

      // Do NOT call loadMessages — repo is in background mode.
      expect(repo.isLoaded, isFalse);

      final msg = makeMessage(
        id: 'msg-1',
        messageId: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
      );
      await repo.mergeFromPolling([msg]);

      // In-memory view is empty (not loaded).
      expect(repo.messages, isEmpty);

      // But storage has the message.
      final onDisk = await storage.loadMessages(conv.groupIdHex);
      expect(onDisk.length, 1);
      expect(onDisk.first.id, 'msg-1');

      // Now load — message appears.
      await repo.loadMessages();
      expect(repo.messages.length, 1);
      expect(repo.messages.first.id, 'msg-1');
    });
  });

  group('load/unload lifecycle', () {
    test('unload clears memory, reload recovers', () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);

      // Load and add messages via polling.
      await repo.loadMessages();
      await repo.mergeFromPolling([
        makeMessage(id: 'msg-1', content: 'First'),
      ]);
      expect(repo.messages.length, 1);

      // Unload — memory cleared.
      repo.unloadMessages();
      expect(repo.messages, isEmpty);
      expect(repo.isLoaded, isFalse);

      // More messages arrive in background.
      await repo.mergeFromPolling([
        makeMessage(
          id: 'msg-2',
          content: 'Second',
          timestamp: DateTime.utc(2025, 1, 15, 13, 0, 0),
        ),
      ]);

      // Reload — both messages present.
      await repo.loadMessages();
      expect(repo.messages.length, 2);
      expect(repo.messages[0].content, 'First');
      expect(repo.messages[1].content, 'Second');
    });
  });

  group('stale cleanup', () {
    test('loadMessages drops sending and failed messages', () async {
      final conv = makeConversation();

      // Pre-populate storage with stale messages.
      await storage.saveMessages(conv.groupIdHex, [
        makeMessage(
            id: 'msg-ok', content: 'Good', status: MessageStatus.sent),
        makeMessage(
          id: 'msg-stuck',
          content: 'Stuck',
          status: MessageStatus.sending,
          localId: 'local_1',
        ),
        makeMessage(
          id: 'msg-bad',
          content: 'Bad',
          status: MessageStatus.failed,
          localId: 'local_2',
        ),
      ]);

      final repo = makeRepo(conv);
      await repo.loadMessages();

      expect(repo.messages.length, 1);
      expect(repo.messages.first.content, 'Good');
    });
  });

  group('reaction roundtrip', () {
    test('applyReaction toggles and persists', () async {
      final conv = makeConversation();
      final msgId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

      // Pre-populate with a message.
      await storage.saveMessages(conv.groupIdHex, [
        makeMessage(id: 'msg-1', messageId: msgId),
      ]);

      final repo = makeRepo(conv);
      await repo.loadMessages();

      // Apply reaction.
      await repo.applyReaction(msgId, '\u{1F44D}', 'did:plc:bob');
      expect(repo.messages.first.reactions.length, 1);
      expect(repo.messages.first.reactions.first.emoji, '\u{1F44D}');

      // Toggle off.
      await repo.applyReaction(msgId, '\u{1F44D}', 'did:plc:bob');
      expect(repo.messages.first.reactions, isEmpty);

      // Verify persistence: unload + reload.
      repo.unloadMessages();
      await repo.loadMessages();
      expect(repo.messages.first.reactions, isEmpty);
    });
  });

  group('concurrent writes', () {
    test('multiple mergeFromPolling calls serialize correctly', () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);
      await repo.loadMessages();

      // Fire multiple merges concurrently (don't await between them).
      final futures = <Future>[];
      for (var i = 0; i < 5; i++) {
        futures.add(repo.mergeFromPolling([
          makeMessage(
            id: 'msg-$i',
            content: 'Message $i',
            timestamp: DateTime.utc(2025, 1, 15, 12, i, 0),
          ),
        ]));
      }
      await Future.wait(futures);

      // All messages present in memory.
      expect(repo.messages.length, 5);

      // All messages present on disk.
      final onDisk = await storage.loadMessages(conv.groupIdHex);
      expect(onDisk.length, 5);
    });
  });

  group('cancel message', () {
    test('cancelMessage removes optimistic and clears queue', () async {
      final conv = makeConversation();
      // Use a fake that always fails so the message stays in queue.
      final fake = FakeSendService()..shouldFail = true;
      final repo = makeRepo(conv, fake: fake);
      await repo.loadMessages();

      final localId = repo.sendMessage('Hello');
      await Future.delayed(Duration.zero);
      await Future.delayed(Duration.zero);

      expect(repo.messages.length, 1);
      expect(repo.messages.first.status, MessageStatus.failed);

      // Cancel it.
      repo.cancelMessage(localId);
      expect(repo.messages, isEmpty);
    });
  });
}
