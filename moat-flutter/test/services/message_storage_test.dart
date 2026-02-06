import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/message.dart';

/// Tests for message storage JSON format and roundtrip behavior.
///
/// These test the JSON serialization that MessageStorage relies on,
/// using direct file I/O instead of path_provider (which isn't available
/// in unit tests).
void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('msg_storage_test_');
  });

  tearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  Message makeMessage({
    String id = 'msg-1',
    List<int> groupIdBytes = const [1, 2, 3, 4],
    String senderDid = 'did:plc:alice',
    String content = 'Hello!',
    DateTime? timestamp,
    bool isOwn = false,
    int epoch = 0,
    MessageStatus status = MessageStatus.sent,
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

  Future<void> appendMessage(String groupIdHex, Message message) async {
    final messages = await loadMessages(groupIdHex);
    if (messages.any((m) => m.id == message.id)) return;
    messages.add(message);
    messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    await saveMessages(groupIdHex, messages);
  }

  Future<void> appendMessages(
      String groupIdHex, List<Message> newMessages) async {
    if (newMessages.isEmpty) return;
    final messages = await loadMessages(groupIdHex);
    final existingIds = messages.map((m) => m.id).toSet();
    for (final message in newMessages) {
      if (!existingIds.contains(message.id)) {
        messages.add(message);
      }
    }
    messages.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    await saveMessages(groupIdHex, messages);
  }

  group('MessageStorage JSON format', () {
    test('empty directory returns empty list', () async {
      final loaded = await loadMessages('01020304');
      expect(loaded, isEmpty);
    });

    test('save and load single message', () async {
      final msg = makeMessage();
      await saveMessages('01020304', [msg]);

      final loaded = await loadMessages('01020304');
      expect(loaded.length, 1);
      expect(loaded[0].id, 'msg-1');
      expect(loaded[0].content, 'Hello!');
      expect(loaded[0].senderDid, 'did:plc:alice');
    });

    test('save and load multiple messages', () async {
      final msg1 = makeMessage(id: 'msg-1', content: 'First');
      final msg2 = makeMessage(
        id: 'msg-2',
        content: 'Second',
        timestamp: DateTime.utc(2025, 1, 15, 12, 1, 0),
      );
      await saveMessages('01020304', [msg1, msg2]);

      final loaded = await loadMessages('01020304');
      expect(loaded.length, 2);
      expect(loaded[0].content, 'First');
      expect(loaded[1].content, 'Second');
    });

    test('separate files per group', () async {
      await saveMessages('aabb', [makeMessage(id: 'g1-msg', content: 'Group 1')]);
      await saveMessages('ccdd', [makeMessage(id: 'g2-msg', content: 'Group 2')]);

      final group1 = await loadMessages('aabb');
      final group2 = await loadMessages('ccdd');
      expect(group1.length, 1);
      expect(group1[0].content, 'Group 1');
      expect(group2.length, 1);
      expect(group2[0].content, 'Group 2');
    });
  });

  group('append behavior', () {
    test('append adds message', () async {
      await appendMessage('01020304', makeMessage(id: 'msg-1'));
      final loaded = await loadMessages('01020304');
      expect(loaded.length, 1);
    });

    test('append deduplicates by ID', () async {
      await appendMessage('01020304', makeMessage(id: 'msg-1'));
      await appendMessage('01020304', makeMessage(id: 'msg-1'));

      final loaded = await loadMessages('01020304');
      expect(loaded.length, 1);
    });

    test('append sorts by timestamp', () async {
      final late = makeMessage(
        id: 'msg-late',
        timestamp: DateTime.utc(2025, 1, 15, 14, 0, 0),
      );
      final early = makeMessage(
        id: 'msg-early',
        timestamp: DateTime.utc(2025, 1, 15, 10, 0, 0),
      );

      // Append late first, then early
      await appendMessage('01020304', late);
      await appendMessage('01020304', early);

      final loaded = await loadMessages('01020304');
      expect(loaded.length, 2);
      expect(loaded[0].id, 'msg-early');
      expect(loaded[1].id, 'msg-late');
    });

    test('appendMessages batch deduplicates', () async {
      await appendMessage('01020304', makeMessage(id: 'msg-1'));

      await appendMessages('01020304', [
        makeMessage(id: 'msg-1'), // duplicate
        makeMessage(
          id: 'msg-2',
          timestamp: DateTime.utc(2025, 1, 15, 13, 0, 0),
        ),
        makeMessage(
          id: 'msg-3',
          timestamp: DateTime.utc(2025, 1, 15, 14, 0, 0),
        ),
      ]);

      final loaded = await loadMessages('01020304');
      expect(loaded.length, 3);
    });

    test('appendMessages with empty list is no-op', () async {
      await appendMessage('01020304', makeMessage(id: 'msg-1'));
      await appendMessages('01020304', []);

      final loaded = await loadMessages('01020304');
      expect(loaded.length, 1);
    });
  });

  group('delete behavior', () {
    test('delete removes file for group', () async {
      await saveMessages('01020304', [makeMessage()]);
      final file = fileForGroup('01020304');
      expect(file.existsSync(), isTrue);

      await file.delete();
      final loaded = await loadMessages('01020304');
      expect(loaded, isEmpty);
    });
  });
}
