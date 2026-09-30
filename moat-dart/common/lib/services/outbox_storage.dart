import 'dart:convert';
import 'dart:typed_data';

import 'debug_log.dart';
import 'document_backend.dart';

/// A send not yet published: what the user sent, and why it last failed.
class OutboxEntry {
  /// The id the message is published under, on every attempt.
  final Uint8List messageId;
  final String localId;
  final DateTime timestamp;

  /// Exactly one of [text] and [image] is set.
  final String? text;
  final Uint8List? image;

  /// Why the last attempt failed; null while one is in flight.
  final String? sendError;

  OutboxEntry({
    required this.messageId,
    required this.localId,
    required this.timestamp,
    this.text,
    this.image,
    this.sendError,
  });

  String get messageIdHex =>
      messageId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  OutboxEntry withError(String? error) => OutboxEntry(
        messageId: messageId,
        localId: localId,
        timestamp: timestamp,
        text: text,
        image: image,
        sendError: error,
      );

  Map<String, dynamic> toJson() => {
        'messageId': base64Encode(messageId),
        'localId': localId,
        'timestamp': timestamp.toIso8601String(),
        'text': text,
        'image': image != null ? base64Encode(image!) : null,
        'sendError': sendError,
      };

  factory OutboxEntry.fromJson(Map<String, dynamic> json) => OutboxEntry(
        messageId: base64Decode(json['messageId'] as String),
        localId: json['localId'] as String,
        timestamp: DateTime.parse(json['timestamp'] as String),
        text: json['text'] as String?,
        image: json['image'] != null ? base64Decode(json['image'] as String) : null,
        sendError: json['sendError'] as String?,
      );
}

/// Unpublished sends, kept so a failed send can be retried — including
/// after a restart. One document per send under `outbox/<groupIdHex>/`.
class OutboxStorage {
  final DocumentBackend _backend;

  OutboxStorage({required DocumentBackend backend}) : _backend = backend;

  String _dir(String groupIdHex) => 'outbox/$groupIdHex';

  Future<List<OutboxEntry>> load(String groupIdHex) async {
    final entries = <OutboxEntry>[];
    for (final path in await _backend.list(_dir(groupIdHex))) {
      try {
        final contents = await _backend.read(path);
        if (contents == null) continue;
        entries.add(OutboxEntry.fromJson(jsonDecode(contents) as Map<String, dynamic>));
      } catch (e) {
        moatLog('OutboxStorage: skipping unreadable entry $path: $e');
      }
    }
    entries.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return entries;
  }

  /// Best effort: a send whose source cannot be kept (e.g. an image over
  /// the web storage quota) still goes out, it just cannot be retried
  /// after a restart.
  Future<void> put(String groupIdHex, OutboxEntry entry) async {
    try {
      await _backend.write(
          '${_dir(groupIdHex)}/${entry.messageIdHex}.json', jsonEncode(entry.toJson()));
    } catch (e) {
      moatLog('OutboxStorage: failed to keep ${entry.messageIdHex} for retry: $e');
    }
  }

  Future<void> delete(String groupIdHex, String messageIdHex) =>
      _backend.delete('${_dir(groupIdHex)}/$messageIdHex.json');
}
