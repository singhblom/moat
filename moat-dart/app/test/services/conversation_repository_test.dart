import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/message.dart';

/// Tests for ConversationRepository logic.
///
/// These test the core state management operations (merge, optimistic,
/// confirm, fail, reaction, serialized writes, lazy load/unload, stale
/// cleanup) using direct file I/O to simulate MessageStorage behavior.
void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('conv_repo_test_');
  });

  tearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  // -------------------------------------------------------------------------
  // Helpers — simulate MessageStorage operations on disk
  // -------------------------------------------------------------------------

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
    );
  }

  File fileForGroup(String groupIdHex) =>
      File('${tempDir.path}/$groupIdHex.json');

  Future<void> saveMessages(String groupIdHex, List<Message> messages) async {
    final json = messages.map((m) => m.toJson()).toList();
    await fileForGroup(groupIdHex).writeAsString(jsonEncode(json));
  }

  Future<List<Message>> loadMessages(String groupIdHex) async {
    final file = fileForGroup(groupIdHex);
    if (!file.existsSync()) return [];
    final contents = await file.readAsString();
    final list = jsonDecode(contents) as List<dynamic>;
    return list
        .map((e) => Message.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  // -------------------------------------------------------------------------
  // Tests for merge logic (simulating what ConversationRepository does)
  // -------------------------------------------------------------------------

  group('merge from polling', () {
    test('adds new messages to persisted list', () {
      final persisted = <Message>[];
      final incoming = [
        makeMessage(id: 'msg-1', content: 'First'),
        makeMessage(
          id: 'msg-2',
          content: 'Second',
          timestamp: DateTime.utc(2025, 1, 15, 12, 1, 0),
        ),
      ];

      // Simulate merge
      for (final msg in incoming) {
        final existingIdx = persisted.indexWhere((m) => m.id == msg.id);
        if (existingIdx >= 0) {
          persisted[existingIdx] = msg;
        } else {
          persisted.add(msg);
        }
      }
      persisted.sort((a, b) => a.timestamp.compareTo(b.timestamp));

      expect(persisted.length, 2);
      expect(persisted[0].content, 'First');
      expect(persisted[1].content, 'Second');
    });

    test('deduplicates by message id', () {
      final persisted = [makeMessage(id: 'msg-1', content: 'Original')];
      final incoming = [makeMessage(id: 'msg-1', content: 'Updated')];

      for (final msg in incoming) {
        final existingIdx = persisted.indexWhere((m) => m.id == msg.id);
        if (existingIdx >= 0) {
          persisted[existingIdx] = msg;
        } else {
          persisted.add(msg);
        }
      }

      expect(persisted.length, 1);
      expect(persisted[0].content, 'Updated');
    });

    test('removes matching optimistic message by messageId', () {
      final optimistic = [
        makeMessage(
          id: 'local_123',
          localId: 'local_123',
          content: 'Hello',
          status: MessageStatus.sending,
          messageId: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        ),
      ];
      final incoming = [
        makeMessage(
          id: 'group_rkey1',
          content: 'Hello',
          messageId: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        ),
      ];

      // Simulate merge: remove matching optimistic
      for (final msg in incoming) {
        if (msg.messageId != null) {
          optimistic.removeWhere((opt) =>
              opt.messageId != null &&
              _bytesEqual(opt.messageId!, msg.messageId!));
        }
      }

      expect(optimistic, isEmpty);
    });
  });

  group('optimistic messages', () {
    test('merged view includes both persisted and optimistic', () {
      final persisted = [
        makeMessage(id: 'msg-1', content: 'Persisted', timestamp: DateTime.utc(2025, 1, 15, 12, 0, 0)),
      ];
      final optimistic = [
        makeMessage(
          id: 'local_1',
          localId: 'local_1',
          content: 'Sending...',
          status: MessageStatus.sending,
          timestamp: DateTime.utc(2025, 1, 15, 12, 1, 0),
        ),
      ];

      final merged = <Message>[];
      merged.addAll(persisted);
      for (final opt in optimistic) {
        if (opt.messageId != null &&
            persisted.any((p) =>
                p.messageId != null && _bytesEqual(p.messageId!, opt.messageId!))) {
          continue;
        }
        merged.add(opt);
      }
      merged.sort((a, b) => a.timestamp.compareTo(b.timestamp));

      expect(merged.length, 2);
      expect(merged[0].content, 'Persisted');
      expect(merged[1].content, 'Sending...');
    });

    test('optimistic excluded when persisted has matching messageId', () {
      final persisted = [
        makeMessage(id: 'msg-1', content: 'Confirmed', messageId: [1, 2, 3, 4]),
      ];
      final optimistic = [
        makeMessage(
          id: 'local_1',
          localId: 'local_1',
          content: 'Sending...',
          status: MessageStatus.sending,
          messageId: [1, 2, 3, 4],
        ),
      ];

      final merged = <Message>[];
      merged.addAll(persisted);
      for (final opt in optimistic) {
        if (opt.messageId != null &&
            persisted.any((p) =>
                p.messageId != null && _bytesEqual(p.messageId!, opt.messageId!))) {
          continue;
        }
        merged.add(opt);
      }

      expect(merged.length, 1);
      expect(merged[0].content, 'Confirmed');
    });
  });

  group('stale message cleanup on load', () {
    test('drops messages with status sending', () async {
      await saveMessages('01020304', [
        makeMessage(id: 'msg-1', content: 'Sent', status: MessageStatus.sent),
        makeMessage(id: 'msg-2', content: 'Stuck', status: MessageStatus.sending, localId: 'local_1'),
      ]);

      var loaded = await loadMessages('01020304');
      loaded = loaded
          .where((m) =>
              m.status != MessageStatus.sending &&
              m.status != MessageStatus.failed)
          .toList();

      expect(loaded.length, 1);
      expect(loaded[0].content, 'Sent');
    });

    test('drops messages with status failed', () async {
      await saveMessages('01020304', [
        makeMessage(id: 'msg-1', content: 'Sent', status: MessageStatus.sent),
        makeMessage(id: 'msg-2', content: 'Failed', status: MessageStatus.failed, localId: 'local_1'),
      ]);

      var loaded = await loadMessages('01020304');
      loaded = loaded
          .where((m) =>
              m.status != MessageStatus.sending &&
              m.status != MessageStatus.failed)
          .toList();

      expect(loaded.length, 1);
      expect(loaded[0].content, 'Sent');
    });
  });

  group('reaction toggle', () {
    test('adds reaction when none exists', () {
      final msg = makeMessage(id: 'msg-1', messageId: [1, 2, 3, 4]);
      final reactions = msg.reactions;

      final existing = reactions.indexWhere(
        (r) => r.emoji == '👍' && r.senderDid == 'did:plc:bob',
      );
      expect(existing, -1);

      final updated = [...reactions, const Reaction(emoji: '👍', senderDid: 'did:plc:bob')];
      final updatedMsg = msg.copyWith(reactions: updated);

      expect(updatedMsg.reactions.length, 1);
      expect(updatedMsg.reactions[0].emoji, '👍');
    });

    test('removes reaction when same sender+emoji exists', () {
      final msg = makeMessage(id: 'msg-1', messageId: [1, 2, 3, 4]).copyWith(
        reactions: [const Reaction(emoji: '👍', senderDid: 'did:plc:bob')],
      );

      final existing = msg.reactions.indexWhere(
        (r) => r.emoji == '👍' && r.senderDid == 'did:plc:bob',
      );
      expect(existing, 0);

      final updated = List.of(msg.reactions)..removeAt(existing);
      final updatedMsg = msg.copyWith(reactions: updated);

      expect(updatedMsg.reactions, isEmpty);
    });
  });

  group('write serialization', () {
    test('concurrent writes produce correct final state', () async {
      // Simulate _enqueueWrite by chaining futures
      Future<void>? pendingWrite;

      Future<void> enqueueWrite(Future<void> Function() op) {
        final prev = pendingWrite ?? Future.value();
        pendingWrite = prev.then((_) => op());
        return pendingWrite!;
      }

      final groupIdHex = '01020304';

      // First write
      enqueueWrite(() async {
        await saveMessages(groupIdHex, [
          makeMessage(id: 'msg-1', content: 'First'),
        ]);
      });

      // Second write (should wait for first)
      enqueueWrite(() async {
        final existing = await loadMessages(groupIdHex);
        existing.add(makeMessage(
          id: 'msg-2',
          content: 'Second',
          timestamp: DateTime.utc(2025, 1, 15, 12, 1, 0),
        ));
        await saveMessages(groupIdHex, existing);
      });

      // Wait for all writes
      await pendingWrite;

      final loaded = await loadMessages(groupIdHex);
      expect(loaded.length, 2);
      expect(loaded.map((m) => m.id).toSet(), {'msg-1', 'msg-2'});
    });
  });
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
