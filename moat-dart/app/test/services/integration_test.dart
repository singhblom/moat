import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// Fake SendService that returns synthetic messages without crypto or network.
class FakeSendService implements SendService {
  int callCount = 0;
  bool shouldFail = false;

  /// Sends of these texts fail; others follow [shouldFail].
  final Set<String> failTexts = {};

  /// When set, sends wait on it — an attempt still in flight.
  Completer<void>? gate;

  @override
  Future<Message> sendMessage({
    required Conversation conversation,
    required String text,
    required String localId,
    required Uint8List messageId,
  }) async {
    callCount++;
    await gate?.future;
    if (shouldFail || failTexts.contains(text)) throw SendException('Mock failure');
    return Message(
      id: '${conversation.groupIdHex}_rkey_$callCount',
      localId: localId,
      groupId: conversation.groupId,
      senderDid: 'did:plc:me',
      content: text,
      timestamp: DateTime.utc(2025, 1, 15, 12, 0, callCount),
      isOwn: true,
      status: MessageStatus.sent,
      messageId: messageId,
    );
  }

  @override
  Future<Message> sendImage({
    required Conversation conversation,
    required Uint8List imageBytes,
    required String localId,
    required Uint8List messageId,
    required BlobService blobService,
  }) async {
    callCount++;
    await gate?.future;
    if (shouldFail) throw SendException('Mock failure');
    return Message(
      id: '${conversation.groupIdHex}_rkey_img_$callCount',
      messageId: messageId,
      localId: localId,
      groupId: conversation.groupId,
      senderDid: 'did:plc:me',
      content: '[image image/png 1x1]',
      timestamp: DateTime.utc(2025, 1, 15, 12, 0, callCount),
      isOwn: true,
      status: MessageStatus.sent,
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

/// Stands in for the [BlobService] an image retry needs; [FakeSendService]
/// never calls it.
class FakeBlobService implements BlobService {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
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
    storage = MessageStorage(backend: IoDocumentBackend(tempDir));
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

      // Let the queue process and disk writes complete (async).
      await Future<void>.delayed(const Duration(milliseconds: 50));

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

  group('unpublished sends', () {
    Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 50));

    test('a failed send records why and does not hold later sends', () async {
      final conv = makeConversation();
      final fake = FakeSendService()..failTexts.add('first');
      final repo = makeRepo(conv, fake: fake);
      await repo.loadMessages();

      repo.sendMessage('first');
      repo.sendMessage('second');
      await settle();

      final byContent = {for (final m in repo.messages) m.content: m};
      expect(byContent['first']!.status, MessageStatus.failed);
      expect(byContent['first']!.sendError, contains('Mock failure'));
      expect(byContent['second']!.status, MessageStatus.sent);
    });

    // Sends are in-memory work; the outbox is what outlives a restart.
    test('a send interrupted by a restart comes back failed and retries '
        'under the same message id', () async {
      final conv = makeConversation();
      final hung = FakeSendService()..gate = Completer<void>();
      final before = makeRepo(conv, fake: hung);
      await before.loadMessages();
      final messageId = before.pendingMessage(before.sendMessage('hello'))!.messageId;
      await settle();

      // A fresh repository on the same storage: the next run.
      final after = makeRepo(conv);
      await Future.wait([after.loadMessages(), after.loadMessages()]);
      final restored = after.messages.single;
      expect(restored.status, MessageStatus.failed);
      expect(restored.sendError, 'interrupted before it was sent');
      expect(restored.messageId, messageId);
      await after.loadMessages();
      expect(after.messages.length, 1, reason: 'a reload must not restore it twice');

      expect(after.retryMessage(restored.messageIdHex!), isTrue);
      await settle();
      final sent = after.messages.single;
      expect(sent.status, MessageStatus.sent);
      expect(sent.messageId, messageId);
      expect(await storage.outbox.load(conv.groupIdHex), isEmpty);
    });

    test('an interrupted image retries from the kept bytes', () async {
      final conv = makeConversation();
      final hung = FakeSendService()..gate = Completer<void>();
      final before = makeRepo(conv, fake: hung);
      await before.loadMessages();
      before.sendImage(Uint8List.fromList([1, 2, 3]), FakeBlobService());
      await settle();

      final after = makeRepo(conv);
      await after.loadMessages();
      final restored = after.messages.single;
      expect(restored.status, MessageStatus.failed);
      expect(after.retryMessage(restored.localId!), isFalse,
          reason: 'an image cannot be uploaded without a blob service');
      expect(after.retryMessage(restored.localId!, blobService: FakeBlobService()), isTrue);
      await settle();
      expect(after.messages.single.status, MessageStatus.sent);
    });

    // A retry republishes under the same message id, and the first attempt
    // may have landed too.
    test('a republished message id is kept once', () async {
      final conv = makeConversation();
      final first = makeMessage(id: '01020304_a', messageId: List.filled(16, 9));
      final again = makeMessage(id: '01020304_b', messageId: List.filled(16, 9));

      await storage.appendMessages(conv.groupIdHex, [first, again]);
      expect((await storage.loadMessages(conv.groupIdHex)).map((m) => m.id), ['01020304_a']);

      final repo = makeRepo(conv);
      await repo.loadMessages();
      await repo.mergeFromPolling([again]);
      expect(repo.messages.map((m) => m.id), ['01020304_a']);
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

    // A load racing queued appends must not make the next save drop them.
    final m1 = makeMessage(
        id: 'msg-first', timestamp: DateTime.utc(2025, 1, 15, 12, 0, 1));
    final m2 = makeMessage(
        id: 'msg-second', timestamp: DateTime.utc(2025, 1, 15, 12, 0, 2));

    Future<void> expectBothKept(
        Iterable<Message> inMemory, String groupIdHex) async {
      expect(inMemory.map((m) => m.id), containsAll(['msg-first', 'msg-second']));
      final onDisk = await storage.loadMessages(groupIdHex);
      expect(onDisk.map((m) => m.id), containsAll(['msg-first', 'msg-second']));
    }

    test('a load racing a queued merge loses nothing', () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);
      await Future.wait([repo.mergeFromPolling([m1]), repo.loadMessages()]);
      await repo.mergeFromPolling([m2]);
      await expectBothKept(repo.messages, conv.groupIdHex);
    });

    test('a merge that arrives while a load is reading is kept', () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);
      await Future.wait([repo.loadMessages(), repo.mergeFromPolling([m1])]);
      await repo.mergeFromPolling([m2]);
      await expectBothKept(repo.messages, conv.groupIdHex);
    });

    // A server send while loaded must survive the next polled merge.
    test('a message sent while loaded survives the next polled merge',
        () async {
      final conv = makeConversation();
      final repo = makeRepo(conv);
      await repo.loadMessages();
      repo.sendMessage('from the server');
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final sent = repo.messages.single;
      expect(sent.status, MessageStatus.sent);
      await repo.mergeFromPolling([m2]);
      final onDisk = await storage.loadMessages(conv.groupIdHex);
      expect(onDisk.map((m) => m.id), containsAll([sent.id, 'msg-second']));
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
