import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

void main() {
  group('encodeImageMessagePayload', () {
    Uint8List thumb = Uint8List.fromList([1, 2, 3, 4]);
    Uint8List key = Uint8List.fromList(List.generate(32, (i) => i));
    Uint8List ciphertextHash = Uint8List.fromList(List.generate(32, (i) => i + 1));
    Uint8List contentHash = Uint8List.fromList(List.generate(32, (i) => i + 2));

    test('produces valid JSON with correct structure', () {
      final payload = encodeImageMessagePayload(
        thumbhash: thumb,
        width: 1920,
        height: 1080,
        mime: 'image/jpeg',
        uri: 'at://did:plc:abc/bafkreixxx',
        key: key,
        ciphertextHash: ciphertextHash,
        ciphertextSize: 65536,
        contentHash: contentHash,
      );

      final decoded = jsonDecode(utf8.decode(payload)) as Map<String, dynamic>;
      expect(decoded['type'], 'image');
      expect(decoded['width'], 1920);
      expect(decoded['height'], 1080);
      expect(decoded['mime'], 'image/jpeg');
      expect(decoded['preview_thumbhash'], isA<String>());
      final ext = decoded['external'] as Map<String, dynamic>;
      expect(ext['uri'], 'at://did:plc:abc/bafkreixxx');
      expect(ext['ciphertext_size'], 65536);
      expect(ext['key'], isA<String>());
      expect(ext['ciphertext_hash'], isA<String>());
      expect(ext['content_hash'], isA<String>());
    });

    test('binary fields are base64 strings (not arrays)', () {
      final payload = encodeImageMessagePayload(
        thumbhash: thumb,
        width: 10,
        height: 10,
        mime: 'image/png',
        uri: 'at://did/cid',
        key: key,
        ciphertextHash: ciphertextHash,
        ciphertextSize: 100,
        contentHash: contentHash,
      );
      final decoded = jsonDecode(utf8.decode(payload)) as Map<String, dynamic>;
      // base64Encode(key) should decode back to the original bytes
      expect(base64Decode(decoded['external']['key'] as String), key);
      expect(base64Decode(decoded['preview_thumbhash'] as String), thumb);
    });

    test('renderMessagePreview shows image metadata', () {
      final payload = encodeImageMessagePayload(
        thumbhash: thumb,
        width: 1920,
        height: 1080,
        mime: 'image/jpeg',
        uri: 'at://did/cid',
        key: key,
        ciphertextHash: ciphertextHash,
        ciphertextSize: 65536,
        contentHash: contentHash,
      );
      final preview = renderMessagePreview(payload);
      expect(preview, '[image image/jpeg 1920x1080]');
    });
  });

  group('parseImageAttachment', () {
    Uint8List key = Uint8List.fromList(List.generate(32, (i) => i));
    Uint8List ciphertextHash = Uint8List.fromList(List.generate(32, (i) => i + 1));
    Uint8List contentHash = Uint8List.fromList(List.generate(32, (i) => i + 2));
    Uint8List thumbhash = Uint8List.fromList([1, 2, 3, 4]);

    test('extracts all fields correctly', () {
      final payload = encodeImageMessagePayload(
        thumbhash: thumbhash,
        width: 800,
        height: 600,
        mime: 'image/png',
        uri: 'at://did:plc:alice/bafkrei',
        key: key,
        ciphertextHash: ciphertextHash,
        ciphertextSize: 32768,
        contentHash: contentHash,
      );

      final attachment = parseImageAttachment(payload);
      expect(attachment, isNotNull);
      expect(attachment!.uri, 'at://did:plc:alice/bafkrei');
      expect(attachment.width, 800);
      expect(attachment.height, 600);
      expect(attachment.mime, 'image/png');
      expect(attachment.ciphertextSize, 32768);
      expect(attachment.key, key);
      expect(attachment.ciphertextHash, ciphertextHash);
      expect(attachment.contentHash, contentHash);
      expect(attachment.thumbhash, thumbhash);
    });

    test('returns null for text messages', () {
      final payload = encodeTextMessagePayload('Hello, world!');
      expect(parseImageAttachment(payload), isNull);
    });

    test('returns null for malformed bytes', () {
      final junk = Uint8List.fromList(utf8.encode('not json'));
      expect(parseImageAttachment(junk), isNull);
    });

    test('roundtrip: encode then parse recovers same data', () {
      final original = ImageAttachment(
        uri: 'at://did:plc:test/bafkrei',
        key: key,
        ciphertextHash: ciphertextHash,
        ciphertextSize: 12345,
        contentHash: contentHash,
        thumbhash: thumbhash,
        width: 640,
        height: 480,
        mime: 'image/jpeg',
      );

      final payload = encodeImageMessagePayload(
        thumbhash: original.thumbhash!,
        width: original.width!,
        height: original.height!,
        mime: original.mime!,
        uri: original.uri,
        key: original.key,
        ciphertextHash: original.ciphertextHash,
        ciphertextSize: original.ciphertextSize,
        contentHash: original.contentHash,
      );

      final parsed = parseImageAttachment(payload)!;
      expect(parsed.uri, original.uri);
      expect(parsed.width, original.width);
      expect(parsed.height, original.height);
      expect(parsed.ciphertextSize, original.ciphertextSize);
      expect(parsed.key, original.key);
      expect(parsed.contentHash, original.contentHash);
    });
  });
}
