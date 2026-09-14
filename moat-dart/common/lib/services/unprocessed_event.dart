import 'dart:convert';
import 'dart:typed_data';

import 'atproto_client.dart';

/// An event that was fetched but could not be processed yet
class UnprocessedEvent {
  final String sourceDid;
  final EventRecord record;

  final int firstSeenMs;

  int attempts;

  UnprocessedEvent({
    required this.sourceDid,
    required this.record,
    required this.firstSeenMs,
    this.attempts = 0,
  });

  Map<String, dynamic> toJson() => {
        'source_did': sourceDid,
        'uri': record.uri,
        'rkey': record.rkey,
        'tag': base64Encode(record.tag),
        'ciphertext': base64Encode(record.ciphertext),
        'created_at': record.createdAt.toIso8601String(),
        'first_seen_ms': firstSeenMs,
        'attempts': attempts,
      };

  factory UnprocessedEvent.fromJson(Map<String, dynamic> json) => UnprocessedEvent(
        sourceDid: json['source_did'] as String,
        record: EventRecord(
          uri: json['uri'] as String,
          rkey: json['rkey'] as String,
          tag: Uint8List.fromList(base64Decode(json['tag'] as String)),
          ciphertext: Uint8List.fromList(base64Decode(json['ciphertext'] as String)),
          createdAt: DateTime.parse(json['created_at'] as String),
        ),
        firstSeenMs: json['first_seen_ms'] as int,
        attempts: json['attempts'] as int,
      );
}
