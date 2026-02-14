import 'dart:convert';
import 'dart:typed_data';

// Canonical values defined in moat-core/src/message.rs
const _shortTextMaxBytes = 240;
const _mediumTextMaxBytes = 900;

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
