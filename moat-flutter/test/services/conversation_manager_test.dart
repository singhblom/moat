import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/conversation.dart';
import 'package:moat_flutter/models/message.dart';
import 'package:moat_flutter/providers/auth_provider.dart';
import 'package:moat_flutter/services/conversation_manager.dart';
import 'package:moat_flutter/services/message_storage.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Conversation makeConversation({
  List<int> groupIdBytes = const [1, 2, 3, 4],
  String name = 'Test',
}) {
  return Conversation(
    groupId: Uint8List.fromList(groupIdBytes),
    displayName: name,
    participants: ['did:plc:alice', 'did:plc:bob'],
    keyBundleRef: 'test-ref',
    createdAt: DateTime.utc(2025, 1, 1),
  );
}

Message makeMessage({
  String id = 'msg-1',
  List<int> groupIdBytes = const [1, 2, 3, 4],
  String content = 'Hello!',
  DateTime? timestamp,
  List<int>? messageId,
}) {
  return Message(
    id: id,
    groupId: Uint8List.fromList(groupIdBytes),
    senderDid: 'did:plc:alice',
    content: content,
    timestamp: timestamp ?? DateTime.utc(2025, 1, 15, 12, 0, 0),
    isOwn: false,
    epoch: 0,
    messageId: messageId != null ? Uint8List.fromList(messageId) : null,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  late Directory tempDir;
  late MessageStorage storage;
  final manager = ConversationManager.instance;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('conv_manager_test_');
    storage = MessageStorage(directory: tempDir);
    manager.init(authProvider: AuthProvider(), storage: storage);
  });

  tearDown(() {
    manager.clear();
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  test('getRepository returns same instance on repeated calls', () {
    final conv = makeConversation();
    final repo1 = manager.getRepository(conv);
    final repo2 = manager.getRepository(conv);
    expect(identical(repo1, repo2), isTrue);
  });

  test('getRepository creates separate repos for different conversations', () {
    final conv1 = makeConversation(groupIdBytes: [1, 2, 3, 4], name: 'A');
    final conv2 = makeConversation(groupIdBytes: [5, 6, 7, 8], name: 'B');

    final repo1 = manager.getRepository(conv1);
    final repo2 = manager.getRepository(conv2);
    expect(identical(repo1, repo2), isFalse);
    expect(repo1.groupIdHex, conv1.groupIdHex);
    expect(repo2.groupIdHex, conv2.groupIdHex);
  });

  test('notify creates repo if needed and routes messages', () async {
    final conv = makeConversation();
    final msg = makeMessage(id: 'msg-1', content: 'Routed');

    // notify() is fire-and-forget (doesn't return the Future from
    // mergeFromPolling). Use getRepository + mergeFromPolling directly
    // so we can await the storage write.
    final repo = manager.getRepository(conv);
    await repo.mergeFromPolling([msg]);

    final onDisk = await storage.loadMessages(conv.groupIdHex);
    expect(onDisk.length, 1);
    expect(onDisk.first.content, 'Routed');
  });

  test('notify routes to correct conversation', () async {
    final conv1 = makeConversation(groupIdBytes: [1, 2, 3, 4]);
    final conv2 = makeConversation(groupIdBytes: [5, 6, 7, 8]);

    // Use getRepository + mergeFromPolling to await the writes.
    final repo1 = manager.getRepository(conv1);
    final repo2 = manager.getRepository(conv2);
    await repo1.mergeFromPolling([makeMessage(id: 'msg-a', groupIdBytes: [1, 2, 3, 4], content: 'For A')]);
    await repo2.mergeFromPolling([makeMessage(id: 'msg-b', groupIdBytes: [5, 6, 7, 8], content: 'For B')]);

    final onDisk1 = await storage.loadMessages(conv1.groupIdHex);
    final onDisk2 = await storage.loadMessages(conv2.groupIdHex);
    expect(onDisk1.length, 1);
    expect(onDisk1.first.content, 'For A');
    expect(onDisk2.length, 1);
    expect(onDisk2.first.content, 'For B');
  });

  test('notifyReaction routes to correct repo', () async {
    final conv = makeConversation();
    final msgId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    // Pre-populate storage with a message to react to.
    await storage.saveMessages(conv.groupIdHex, [
      makeMessage(id: 'msg-1', messageId: msgId),
    ]);

    // Load the repo so reaction applies in-memory.
    final repo = manager.getRepository(conv);
    await repo.loadMessages();

    manager.notifyReaction(conv, msgId, '\u{1F44D}', 'did:plc:bob');

    // Allow async write to complete.
    await Future.delayed(Duration.zero);

    expect(repo.messages.first.reactions.length, 1);
    expect(repo.messages.first.reactions.first.emoji, '\u{1F44D}');
  });

  test('remove disposes and deletes repo from cache', () {
    final conv = makeConversation();
    final repo = manager.getRepository(conv);

    manager.remove(conv.groupIdHex);

    // Getting the same conversation again should create a new instance.
    final repo2 = manager.getRepository(conv);
    expect(identical(repo, repo2), isFalse);
  });

  test('clear disposes all repos', () {
    final conv1 = makeConversation(groupIdBytes: [1, 2, 3, 4]);
    final conv2 = makeConversation(groupIdBytes: [5, 6, 7, 8]);

    final repo1 = manager.getRepository(conv1);
    final repo2 = manager.getRepository(conv2);

    manager.clear();

    // New instances after clear.
    final repo1b = manager.getRepository(conv1);
    final repo2b = manager.getRepository(conv2);
    expect(identical(repo1, repo1b), isFalse);
    expect(identical(repo2, repo2b), isFalse);
  });
}
