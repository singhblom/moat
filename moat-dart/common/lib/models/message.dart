import 'dart:convert';
import 'dart:typed_data';

/// Status of a message being sent
enum MessageStatus {
  /// Message is being encrypted and published
  sending,

  /// Message was successfully published to PDS
  sent,

  /// Message failed to send (network error, etc.)
  failed,
}

/// A single emoji reaction on a message
class Reaction {
  final String emoji;
  final String senderDid;

  const Reaction({required this.emoji, required this.senderDid});

  Map<String, dynamic> toJson() => {
        'emoji': emoji,
        'senderDid': senderDid,
      };

  factory Reaction.fromJson(Map<String, dynamic> json) => Reaction(
        emoji: json['emoji'] as String,
        senderDid: json['senderDid'] as String,
      );
}

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

  /// Status of the message (for sent messages)
  final MessageStatus status;

  /// Temporary local ID for pending messages (before rkey is assigned)
  final String? localId;

  /// Unique message identifier from MLS (16 bytes, for reaction targeting)
  final Uint8List? messageId;

  /// Emoji reactions on this message
  final List<Reaction> reactions;

  Message({
    required this.id,
    required this.groupId,
    required this.senderDid,
    this.senderDeviceId,
    required this.content,
    required this.timestamp,
    required this.isOwn,
    required this.epoch,
    this.status = MessageStatus.sent,
    this.localId,
    this.messageId,
    this.reactions = const [],
  });

  /// Group ID as hex string
  String get groupIdHex =>
      groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Message ID as hex string (for display/debugging)
  String? get messageIdHex => messageId
      ?.map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  Map<String, dynamic> toJson() => {
        'id': id,
        'groupId': base64Encode(groupId),
        'senderDid': senderDid,
        'senderDeviceId': senderDeviceId,
        'content': content,
        'timestamp': timestamp.toIso8601String(),
        'isOwn': isOwn,
        'epoch': epoch,
        'status': status.name,
        'localId': localId,
        'messageId': messageId != null ? base64Encode(messageId!) : null,
        'reactions': reactions.map((r) => r.toJson()).toList(),
      };

  /// Create a copy with updated fields
  Message copyWith({
    String? id,
    Uint8List? groupId,
    String? senderDid,
    String? senderDeviceId,
    String? content,
    DateTime? timestamp,
    bool? isOwn,
    int? epoch,
    MessageStatus? status,
    String? localId,
    Uint8List? messageId,
    List<Reaction>? reactions,
  }) =>
      Message(
        id: id ?? this.id,
        groupId: groupId ?? this.groupId,
        senderDid: senderDid ?? this.senderDid,
        senderDeviceId: senderDeviceId ?? this.senderDeviceId,
        content: content ?? this.content,
        timestamp: timestamp ?? this.timestamp,
        isOwn: isOwn ?? this.isOwn,
        epoch: epoch ?? this.epoch,
        status: status ?? this.status,
        localId: localId ?? this.localId,
        messageId: messageId ?? this.messageId,
        reactions: reactions ?? this.reactions,
      );

  factory Message.fromJson(Map<String, dynamic> json) => Message(
        id: json['id'] as String,
        groupId: base64Decode(json['groupId'] as String),
        senderDid: json['senderDid'] as String,
        senderDeviceId: json['senderDeviceId'] as String?,
        content: json['content'] as String,
        timestamp: DateTime.parse(json['timestamp'] as String),
        isOwn: json['isOwn'] as bool,
        epoch: json['epoch'] as int,
        status: _parseStatus(json['status'] as String?),
        localId: json['localId'] as String?,
        messageId: json['messageId'] != null
            ? base64Decode(json['messageId'] as String)
            : null,
        reactions: (json['reactions'] as List<dynamic>?)
                ?.map((r) => Reaction.fromJson(r as Map<String, dynamic>))
                .toList() ??
            const [],
      );

  static MessageStatus _parseStatus(String? status) {
    if (status == null) return MessageStatus.sent;
    return MessageStatus.values.firstWhere(
      (e) => e.name == status,
      orElse: () => MessageStatus.sent,
    );
  }
}
