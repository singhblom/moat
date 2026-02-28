import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/message.dart';

void main() {
  group('Message', () {
    Message makeMessage({
      String id = 'group1-rkey1',
      List<int> groupIdBytes = const [1, 2, 3, 4, 5, 6, 7, 8],
      String senderDid = 'did:plc:abc123',
      String? senderDeviceId = 'device-1',
      String content = 'Hello, world!',
      DateTime? timestamp,
      bool isOwn = false,
      int epoch = 0,
      MessageStatus status = MessageStatus.sent,
      String? localId,
    }) {
      return Message(
        id: id,
        groupId: Uint8List.fromList(groupIdBytes),
        senderDid: senderDid,
        senderDeviceId: senderDeviceId,
        content: content,
        timestamp: timestamp ?? DateTime.utc(2025, 1, 15, 12, 30, 0),
        isOwn: isOwn,
        epoch: epoch,
        status: status,
        localId: localId,
      );
    }

    group('toJson / fromJson roundtrip', () {
      test('basic message roundtrips', () {
        final original = makeMessage();
        final json = original.toJson();
        final restored = Message.fromJson(json);

        expect(restored.id, original.id);
        expect(restored.groupId, original.groupId);
        expect(restored.senderDid, original.senderDid);
        expect(restored.senderDeviceId, original.senderDeviceId);
        expect(restored.content, original.content);
        expect(restored.timestamp, original.timestamp);
        expect(restored.isOwn, original.isOwn);
        expect(restored.epoch, original.epoch);
        expect(restored.status, original.status);
        expect(restored.localId, original.localId);
      });

      test('message with null optional fields roundtrips', () {
        final original = makeMessage(senderDeviceId: null, localId: null);
        final restored = Message.fromJson(original.toJson());

        expect(restored.senderDeviceId, isNull);
        expect(restored.localId, isNull);
      });

      test('message with all statuses roundtrips', () {
        for (final status in MessageStatus.values) {
          final original = makeMessage(status: status);
          final restored = Message.fromJson(original.toJson());
          expect(restored.status, status);
        }
      });

      test('message with localId roundtrips', () {
        final original = makeMessage(localId: 'temp-12345');
        final restored = Message.fromJson(original.toJson());
        expect(restored.localId, 'temp-12345');
      });

      test('message with isOwn=true roundtrips', () {
        final original = makeMessage(isOwn: true);
        final restored = Message.fromJson(original.toJson());
        expect(restored.isOwn, true);
      });

      test('message with high epoch roundtrips', () {
        final original = makeMessage(epoch: 999999);
        final restored = Message.fromJson(original.toJson());
        expect(restored.epoch, 999999);
      });

      test('groupId base64-encodes in JSON', () {
        final original = makeMessage(groupIdBytes: [0xDE, 0xAD, 0xBE, 0xEF]);
        final json = original.toJson();
        expect(json['groupId'], base64Encode([0xDE, 0xAD, 0xBE, 0xEF]));
      });

      test('survives JSON encode/decode cycle', () {
        final original = makeMessage(
          content: 'Unicode: \u{1F600} \u{1F4AC}',
          localId: 'local-1',
        );
        final jsonString = jsonEncode(original.toJson());
        final decoded = jsonDecode(jsonString) as Map<String, dynamic>;
        final restored = Message.fromJson(decoded);

        expect(restored.content, original.content);
        expect(restored.localId, original.localId);
      });
    });

    group('_parseStatus', () {
      test('null status defaults to sent', () {
        final json = makeMessage().toJson();
        json.remove('status');
        json['status'] = null;
        final restored = Message.fromJson(json);
        expect(restored.status, MessageStatus.sent);
      });

      test('unknown status defaults to sent', () {
        final json = makeMessage().toJson();
        json['status'] = 'unknown_status';
        final restored = Message.fromJson(json);
        expect(restored.status, MessageStatus.sent);
      });
    });

    group('groupIdHex', () {
      test('converts bytes to hex string', () {
        final msg = makeMessage(groupIdBytes: [0xDE, 0xAD, 0xBE, 0xEF]);
        expect(msg.groupIdHex, 'deadbeef');
      });

      test('zero-pads single-digit hex values', () {
        final msg = makeMessage(groupIdBytes: [0x01, 0x02, 0x0A]);
        expect(msg.groupIdHex, '01020a');
      });
    });

    group('copyWith', () {
      test('copies all fields when none specified', () {
        final original = makeMessage(localId: 'local-1');
        final copy = original.copyWith();

        expect(copy.id, original.id);
        expect(copy.groupId, original.groupId);
        expect(copy.senderDid, original.senderDid);
        expect(copy.content, original.content);
        expect(copy.timestamp, original.timestamp);
        expect(copy.isOwn, original.isOwn);
        expect(copy.epoch, original.epoch);
        expect(copy.status, original.status);
        expect(copy.localId, original.localId);
      });

      test('overrides specified fields', () {
        final original = makeMessage(status: MessageStatus.sending);
        final updated = original.copyWith(
          status: MessageStatus.sent,
          id: 'new-id',
        );

        expect(updated.status, MessageStatus.sent);
        expect(updated.id, 'new-id');
        expect(updated.content, original.content);
      });
    });
  });
}
