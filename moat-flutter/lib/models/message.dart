import 'dart:convert';
import 'dart:typed_data';

/// A message in a conversation
class Message {
  /// Unique ID (groupIdHex + rkey)
  final String id;

  /// Which conversation this message belongs to
  final Uint8List groupId;

  /// DID of sender (for display grouping)
  final String senderDid;

  /// Device that sent the message (for message info)
  final String? senderDeviceId;

  /// Decrypted message text
  final String content;

  /// When the message was sent
  final DateTime timestamp;

  /// Whether this message was sent by us
  final bool isOwn;

  /// MLS epoch when the message was sent
  final int epoch;

  Message({
    required this.id,
    required this.groupId,
    required this.senderDid,
    this.senderDeviceId,
    required this.content,
    required this.timestamp,
    required this.isOwn,
    required this.epoch,
  });

  /// Group ID as hex string
  String get groupIdHex =>
      groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  Map<String, dynamic> toJson() => {
        'id': id,
        'groupId': base64Encode(groupId),
        'senderDid': senderDid,
        'senderDeviceId': senderDeviceId,
        'content': content,
        'timestamp': timestamp.toIso8601String(),
        'isOwn': isOwn,
        'epoch': epoch,
      };

  factory Message.fromJson(Map<String, dynamic> json) => Message(
        id: json['id'] as String,
        groupId: base64Decode(json['groupId'] as String),
        senderDid: json['senderDid'] as String,
        senderDeviceId: json['senderDeviceId'] as String?,
        content: json['content'] as String,
        timestamp: DateTime.parse(json['timestamp'] as String),
        isOwn: json['isOwn'] as bool,
        epoch: json['epoch'] as int,
      );
}
