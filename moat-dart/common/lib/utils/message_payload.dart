import 'dart:convert';
import 'dart:typed_data';
import '../models/message.dart';

// Canonical values defined in moat-core/src/message.rs
const _shortTextMaxBytes = 240;

Uint8List encodeTextMessagePayload(String text) {
  final textBytes = utf8.encode(text);
  final type = textBytes.length <= _shortTextMaxBytes ? 'short_text' : 'medium_text';
  final payload = jsonEncode({
    'type': type,
    'text': text,
  });
  return Uint8List.fromList(utf8.encode(payload));
}

String renderMessagePreview(Uint8List payload) {
  try {
    final decoded = utf8.decode(payload);
    final dynamic data = jsonDecode(decoded);
    if (data is Map<String, dynamic>) {
      final type = data['type'];
      if (type is String) {
        switch (type) {
          case 'short_text':
          case 'medium_text':
            return (data['text'] as String?) ?? decoded;
          case 'long_text':
            return _renderLongText(data, decoded);
          case 'image':
            return _renderMedia('image', data, decoded);
          case 'video':
            return _renderMedia('video', data, decoded);
          default:
            return decoded;
        }
      }
    }
    return decoded;
  } catch (_) {
    return utf8.decode(payload, allowMalformed: true);
  }
}

/// Encode an image message payload for MLS encryption.
/// All binary fields are standard base64 (RFC 4648), matching moat-core's serde.
Uint8List encodeImageMessagePayload({
  required Uint8List thumbhash,
  required int width,
  required int height,
  required String mime,
  required String uri,
  required Uint8List key,
  required Uint8List ciphertextHash,
  required int ciphertextSize,
  required Uint8List contentHash,
}) {
  final payload = jsonEncode({
    'type': 'image',
    'preview_thumbhash': base64Encode(thumbhash),
    'width': width,
    'height': height,
    'mime': mime,
    'external': {
      'ciphertext_hash': base64Encode(ciphertextHash),
      'ciphertext_size': ciphertextSize,
      'content_hash': base64Encode(contentHash),
      'uri': uri,
      'key': base64Encode(key),
    },
  });
  return Uint8List.fromList(utf8.encode(payload));
}

/// Parse attachment metadata from a decrypted event payload.
/// Returns null if the payload has no attachment or cannot be parsed.
Attachment? parseAttachment(Uint8List payload) {
  try {
    final decoded = utf8.decode(payload);
    final dynamic data = jsonDecode(decoded);
    if (data is! Map<String, dynamic>) return null;

    switch (data['type']) {
      case 'image':
        final ext = data['external'] as Map<String, dynamic>?;
        if (ext == null) return null;
        return ImageAttachment(
          uri: ext['uri'] as String,
          key: base64Decode(ext['key'] as String),
          ciphertextHash: base64Decode(ext['ciphertext_hash'] as String),
          ciphertextSize: (ext['ciphertext_size'] as num).toInt(),
          contentHash: base64Decode(ext['content_hash'] as String),
          thumbhash: data['preview_thumbhash'] != null
              ? base64Decode(data['preview_thumbhash'] as String)
              : null,
          width: (data['width'] as num?)?.toInt(),
          height: (data['height'] as num?)?.toInt(),
          mime: data['mime'] as String?,
        );
      default:
        return null;
    }
  } catch (_) {
    return null;
  }
}

String _renderLongText(Map<String, dynamic> data, String fallback) {
  final preview = data['preview_text'] as String? ?? fallback;
  final mime = data['mime'] as String?;
  final mimeSuffix = mime != null ? ' $mime' : '';
  return '$preview [long text$mimeSuffix]';
}

String _renderMedia(String kind, Map<String, dynamic> data, String fallback) {
  final buffer = StringBuffer('[');
  buffer.write(kind);

  final mime = data['mime'];
  if (mime is String && mime.isNotEmpty) {
    buffer.write(' $mime');
  }

  final width = data['width'];
  final height = data['height'];
  if (width is num && height is num) {
    buffer.write(' ${width.toInt()}x${height.toInt()}');
  }

  if (kind == 'video') {
    final duration = data['duration_ms'];
    if (duration is num) {
      final seconds = duration.toDouble() / 1000.0;
      buffer.write(' ${seconds.toStringAsFixed(1)}s');
    }
  }

  buffer.write(']');
  return buffer.toString();
}
