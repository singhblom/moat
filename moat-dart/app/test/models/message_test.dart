import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

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

  group('ImageAttachment', () {
    ImageAttachment makeAttachment() => ImageAttachment(
          uri: 'at://did:plc:abc/bafkreixxx',
          key: Uint8List.fromList(List.generate(32, (i) => i)),
          ciphertextHash: Uint8List.fromList(List.generate(32, (i) => i + 1)),
          ciphertextSize: 65536,
          contentHash: Uint8List.fromList(List.generate(32, (i) => i + 2)),
          thumbhash: Uint8List.fromList([1, 2, 3, 4, 5]),
          width: 1920,
          height: 1080,
          mime: 'image/jpeg',
        );

    test('toJson / fromJson roundtrip', () {
      final original = makeAttachment();
      final json = original.toJson();
      final restored = ImageAttachment.fromJson(json);

      expect(restored.uri, original.uri);
      expect(restored.key, original.key);
      expect(restored.ciphertextHash, original.ciphertextHash);
      expect(restored.ciphertextSize, original.ciphertextSize);
      expect(restored.contentHash, original.contentHash);
      expect(restored.thumbhash, original.thumbhash);
      expect(restored.width, original.width);
      expect(restored.height, original.height);
      expect(restored.mime, original.mime);
    });

    test('toJson uses base64 for binary fields', () {
      final attachment = makeAttachment();
      final json = attachment.toJson();
      // Verify these are base64 strings, not arrays
      expect(json['key'], isA<String>());
      expect(json['ciphertextHash'], isA<String>());
      expect(json['contentHash'], isA<String>());
      expect(json['thumbhash'], isA<String>());
    });

    test('survives JSON encode/decode cycle', () {
      final original = makeAttachment();
      final encoded = jsonEncode(original.toJson());
      final restored =
          ImageAttachment.fromJson(jsonDecode(encoded) as Map<String, dynamic>);
      expect(restored.uri, original.uri);
      expect(restored.width, original.width);
    });

    test('copyWith preserves and overrides fields', () {
      final original = makeAttachment();
      final updated = original.copyWith(mime: 'image/png', width: 800);
      expect(updated.mime, 'image/png');
      expect(updated.width, 800);
      expect(updated.uri, original.uri);
      expect(updated.key, original.key);
    });

    test('nullable fields serialize as null', () {
      final attachment = ImageAttachment(
        uri: 'at://did:plc:abc/baf',
        key: Uint8List(32),
        ciphertextHash: Uint8List(32),
        ciphertextSize: 100,
        contentHash: Uint8List(32),
      );
      final json = attachment.toJson();
      expect(json['thumbhash'], isNull);
      expect(json['width'], isNull);
      expect(json['mime'], isNull);
    });
  });

  group('Message with imageAttachment', () {
    test('toJson / fromJson roundtrip with imageAttachment', () {
      final message = Message(
        id: 'group1_rkey1',
        groupId: Uint8List.fromList([1, 2, 3, 4]),
        senderDid: 'did:plc:alice',
        content: '[image image/jpeg 1920x1080]',
        timestamp: DateTime.utc(2025, 1, 15, 12, 0, 0),
        isOwn: false,
        epoch: 1,
        imageAttachment: ImageAttachment(
          uri: 'at://did:plc:alice/bafkrei',
          key: Uint8List.fromList(List.generate(32, (i) => i)),
          ciphertextHash: Uint8List.fromList(List.generate(32, (i) => i + 1)),
          ciphertextSize: 65536,
          contentHash: Uint8List.fromList(List.generate(32, (i) => i + 2)),
          thumbhash: Uint8List.fromList([1, 2, 3]),
          width: 1920,
          height: 1080,
          mime: 'image/jpeg',
        ),
      );

      final json = message.toJson();
      final restored = Message.fromJson(json);

      expect(restored.imageAttachment, isNotNull);
      expect(restored.imageAttachment!.uri, 'at://did:plc:alice/bafkrei');
      expect(restored.imageAttachment!.width, 1920);
      expect(restored.imageAttachment!.mime, 'image/jpeg');
    });

    test('fromJson with no imageAttachment is backward-compatible', () {
      final message = Message(
        id: 'group1_rkey1',
        groupId: Uint8List.fromList([1, 2, 3, 4]),
        senderDid: 'did:plc:alice',
        content: 'Hello',
        timestamp: DateTime.utc(2025, 1, 1),
        isOwn: false,
        epoch: 0,
      );
      final json = message.toJson();
      // Ensure imageAttachment key is null
      expect(json['imageAttachment'], isNull);
      final restored = Message.fromJson(json);
      expect(restored.imageAttachment, isNull);
    });

    test('copyWith preserves imageAttachment when not overridden', () {
      final attachment = ImageAttachment(
        uri: 'at://did/baf',
        key: Uint8List(32),
        ciphertextHash: Uint8List(32),
        ciphertextSize: 1024,
        contentHash: Uint8List(32),
      );
      final message = Message(
        id: 'g_r',
        groupId: Uint8List(4),
        senderDid: 'did:plc:x',
        content: '[image]',
        timestamp: DateTime.now(),
        isOwn: false,
        epoch: 0,
        imageAttachment: attachment,
      );
      final updated = message.copyWith(content: 'updated');
      expect(updated.imageAttachment, same(attachment));
    });
  });
}
