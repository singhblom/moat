import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/conversation.dart';

/// Tests for conversation storage JSON format and roundtrip behavior.
///
/// These test the JSON serialization that ConversationStorage relies on,
/// using direct file I/O instead of path_provider (which isn't available
/// in unit tests).
void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('conv_storage_test_');
  });

  tearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  Conversation makeConversation({
    List<int> groupIdBytes = const [1, 2, 3, 4],
    String displayName = 'Alice',
    List<String> participants = const ['did:plc:alice'],
    String keyBundleRef = 'ref-1',
  }) {
    return Conversation(
      groupId: Uint8List.fromList(groupIdBytes),
      displayName: displayName,
      participants: participants,
      keyBundleRef: keyBundleRef,
      createdAt: DateTime.utc(2025, 1, 15),
    );
  }

  File storageFile() => File('${tempDir.path}/conversations.json');

  Future<void> saveAll(List<Conversation> conversations) async {
    final json = conversations.map((c) => c.toJson()).toList();
    await storageFile().writeAsString(jsonEncode(json));
  }

  Future<List<Conversation>> loadAll() async {
    final file = storageFile();
    if (!file.existsSync()) return [];
    final contents = await file.readAsString();
    final list = jsonDecode(contents) as List<dynamic>;
    return list
        .map((e) => Conversation.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  group('ConversationStorage JSON format', () {
    test('empty file returns empty list', () async {
      final loaded = await loadAll();
      expect(loaded, isEmpty);
    });

    test('save and load single conversation', () async {
      final conv = makeConversation();
      await saveAll([conv]);

      final loaded = await loadAll();
      expect(loaded.length, 1);
      expect(loaded[0].displayName, 'Alice');
      expect(loaded[0].groupId, conv.groupId);
      expect(loaded[0].participants, ['did:plc:alice']);
    });

    test('save and load multiple conversations', () async {
      final conv1 = makeConversation(
        groupIdBytes: [1, 2, 3, 4],
        displayName: 'Alice',
      );
      final conv2 = makeConversation(
        groupIdBytes: [5, 6, 7, 8],
        displayName: 'Bob',
        participants: ['did:plc:bob'],
      );
      await saveAll([conv1, conv2]);

      final loaded = await loadAll();
      expect(loaded.length, 2);
      expect(loaded[0].displayName, 'Alice');
      expect(loaded[1].displayName, 'Bob');
    });

    test('overwrite preserves only latest data', () async {
      await saveAll([makeConversation(displayName: 'Alice')]);
      await saveAll([makeConversation(displayName: 'Bob')]);

      final loaded = await loadAll();
      expect(loaded.length, 1);
      expect(loaded[0].displayName, 'Bob');
    });

    test('conversation with all fields persists correctly', () async {
      final conv = Conversation(
        groupId: Uint8List.fromList([0xCA, 0xFE]),
        displayName: 'Full Test',
        participants: ['did:plc:a', 'did:plc:b'],
        lastMessagePreview: 'Hello!',
        lastMessageAt: DateTime.utc(2025, 6, 1, 14, 30),
        unreadCount: 3,
        epoch: 7,
        keyBundleRef: 'bundle-xyz',
        createdAt: DateTime.utc(2025, 1, 1),
      );
      await saveAll([conv]);

      final loaded = await loadAll();
      expect(loaded[0].lastMessagePreview, 'Hello!');
      expect(loaded[0].lastMessageAt, DateTime.utc(2025, 6, 1, 14, 30));
      expect(loaded[0].unreadCount, 3);
      expect(loaded[0].epoch, 7);
      expect(loaded[0].keyBundleRef, 'bundle-xyz');
    });

    test('add-or-update pattern works', () async {
      final conv1 = makeConversation(
        groupIdBytes: [1, 2, 3, 4],
        displayName: 'Alice',
      );
      await saveAll([conv1]);

      // Simulate "save" (add-or-update by groupId)
      final conversations = await loadAll();
      final updated = Conversation(
        groupId: Uint8List.fromList([1, 2, 3, 4]),
        displayName: 'Alice (updated)',
        participants: ['did:plc:alice'],
        keyBundleRef: 'ref-1',
        createdAt: DateTime.utc(2025, 1, 15),
        unreadCount: 5,
      );
      final index = conversations.indexWhere(
        (c) => _bytesEqual(c.groupId, updated.groupId),
      );
      if (index >= 0) {
        conversations[index] = updated;
      } else {
        conversations.add(updated);
      }
      await saveAll(conversations);

      final loaded = await loadAll();
      expect(loaded.length, 1);
      expect(loaded[0].displayName, 'Alice (updated)');
      expect(loaded[0].unreadCount, 5);
    });

    test('delete by groupId pattern works', () async {
      final conv1 = makeConversation(groupIdBytes: [1, 2], displayName: 'A');
      final conv2 = makeConversation(groupIdBytes: [3, 4], displayName: 'B');
      await saveAll([conv1, conv2]);

      final conversations = await loadAll();
      conversations
          .removeWhere((c) => _bytesEqual(c.groupId, [1, 2]));
      await saveAll(conversations);

      final loaded = await loadAll();
      expect(loaded.length, 1);
      expect(loaded[0].displayName, 'B');
    });

    test('find by groupId pattern works', () async {
      final conv1 = makeConversation(groupIdBytes: [1, 2], displayName: 'A');
      final conv2 = makeConversation(groupIdBytes: [3, 4], displayName: 'B');
      await saveAll([conv1, conv2]);

      final conversations = await loadAll();
      final found = conversations
          .where((c) => _bytesEqual(c.groupId, [3, 4]))
          .firstOrNull;
      expect(found, isNotNull);
      expect(found!.displayName, 'B');

      final notFound = conversations
          .where((c) => _bytesEqual(c.groupId, [9, 9]))
          .firstOrNull;
      expect(notFound, isNull);
    });
  });
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
