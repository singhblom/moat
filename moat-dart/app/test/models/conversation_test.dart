import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/conversation.dart';

void main() {
  group('Conversation', () {
    Conversation makeConversation({
      List<int> groupIdBytes = const [1, 2, 3, 4, 5, 6, 7, 8],
      String displayName = 'Alice',
      List<String> participants = const ['did:plc:alice', 'did:plc:bob'],
      String? lastMessagePreview,
      DateTime? lastMessageAt,
      int unreadCount = 0,
      int epoch = 0,
      String keyBundleRef = 'bundle-ref-1',
      DateTime? createdAt,
    }) {
      return Conversation(
        groupId: Uint8List.fromList(groupIdBytes),
        displayName: displayName,
        participants: participants,
        lastMessagePreview: lastMessagePreview,
        lastMessageAt: lastMessageAt,
        unreadCount: unreadCount,
        epoch: epoch,
        keyBundleRef: keyBundleRef,
        createdAt: createdAt ?? DateTime.utc(2025, 1, 15, 12, 0, 0),
      );
    }

    group('toJson / fromJson roundtrip', () {
      test('basic conversation roundtrips', () {
        final original = makeConversation();
        final restored = Conversation.fromJson(original.toJson());

        expect(restored.groupId, original.groupId);
        expect(restored.displayName, original.displayName);
        expect(restored.participants, original.participants);
        expect(restored.lastMessagePreview, original.lastMessagePreview);
        expect(restored.lastMessageAt, original.lastMessageAt);
        expect(restored.unreadCount, original.unreadCount);
        expect(restored.epoch, original.epoch);
        expect(restored.keyBundleRef, original.keyBundleRef);
        expect(restored.createdAt, original.createdAt);
      });

      test('conversation with all optional fields roundtrips', () {
        final original = makeConversation(
          lastMessagePreview: 'Hey there!',
          lastMessageAt: DateTime.utc(2025, 1, 15, 13, 0, 0),
          unreadCount: 5,
          epoch: 42,
        );
        final restored = Conversation.fromJson(original.toJson());

        expect(restored.lastMessagePreview, 'Hey there!');
        expect(restored.lastMessageAt, DateTime.utc(2025, 1, 15, 13, 0, 0));
        expect(restored.unreadCount, 5);
        expect(restored.epoch, 42);
      });

      test('conversation with null optional fields roundtrips', () {
        final original = makeConversation(
          lastMessagePreview: null,
          lastMessageAt: null,
        );
        final restored = Conversation.fromJson(original.toJson());

        expect(restored.lastMessagePreview, isNull);
        expect(restored.lastMessageAt, isNull);
      });

      test('multiple participants roundtrip', () {
        final original = makeConversation(
          participants: ['did:plc:a', 'did:plc:b', 'did:plc:c'],
        );
        final restored = Conversation.fromJson(original.toJson());
        expect(restored.participants, ['did:plc:a', 'did:plc:b', 'did:plc:c']);
      });

      test('empty participants list roundtrips', () {
        final original = makeConversation(participants: []);
        final restored = Conversation.fromJson(original.toJson());
        expect(restored.participants, isEmpty);
      });

      test('groupId base64-encodes in JSON', () {
        final original =
            makeConversation(groupIdBytes: [0xCA, 0xFE, 0xBA, 0xBE]);
        final json = original.toJson();
        expect(json['groupId'], base64Encode([0xCA, 0xFE, 0xBA, 0xBE]));
      });

      test('survives JSON encode/decode cycle', () {
        final original = makeConversation(
          displayName: 'Unicode: \u{1F600}',
          lastMessagePreview: 'Special chars: <>&"\'',
        );
        final jsonString = jsonEncode(original.toJson());
        final decoded = jsonDecode(jsonString) as Map<String, dynamic>;
        final restored = Conversation.fromJson(decoded);

        expect(restored.displayName, original.displayName);
        expect(restored.lastMessagePreview, original.lastMessagePreview);
      });
    });

    group('fromJson defaults', () {
      test('missing unreadCount defaults to 0', () {
        final json = makeConversation().toJson();
        json.remove('unreadCount');
        final restored = Conversation.fromJson(json);
        expect(restored.unreadCount, 0);
      });

      test('missing epoch defaults to 0', () {
        final json = makeConversation().toJson();
        json.remove('epoch');
        final restored = Conversation.fromJson(json);
        expect(restored.epoch, 0);
      });
    });

    group('groupIdHex', () {
      test('converts bytes to hex string', () {
        final conv =
            makeConversation(groupIdBytes: [0xCA, 0xFE, 0xBA, 0xBE]);
        expect(conv.groupIdHex, 'cafebabe');
      });

      test('zero-pads single-digit hex values', () {
        final conv = makeConversation(groupIdBytes: [0x01, 0x02, 0x0F]);
        expect(conv.groupIdHex, '01020f');
      });
    });
  });
}
