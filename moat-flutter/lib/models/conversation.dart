import 'dart:convert';
import 'dart:typed_data';

/// A conversation with one or more participants
class Conversation {
  /// Unique conversation ID (MLS group ID)
  final Uint8List groupId;

  /// Display name (derived from participants or user-set)
  String displayName;

  /// Participant DIDs
  final List<String> participants;

  /// Last message preview (decrypted text, for display)
  String? lastMessagePreview;

  /// Last message timestamp
  DateTime? lastMessageAt;

  /// Unread message count
  int unreadCount;

  /// Current MLS epoch
  int epoch;

  /// MLS key bundle for this conversation (stored separately in secure storage)
  /// This is just a reference key, actual bundle is in secure storage
  final String keyBundleRef;

  /// Creation timestamp
  final DateTime createdAt;

  Conversation({
    required this.groupId,
    required this.displayName,
    required this.participants,
    this.lastMessagePreview,
    this.lastMessageAt,
    this.unreadCount = 0,
    this.epoch = 0,
    required this.keyBundleRef,
    required this.createdAt,
  });

  /// Group ID as hex string (for display/storage keys)
  String get groupIdHex =>
      groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  Map<String, dynamic> toJson() => {
        'groupId': base64Encode(groupId),
        'displayName': displayName,
        'participants': participants,
        'lastMessagePreview': lastMessagePreview,
        'lastMessageAt': lastMessageAt?.toIso8601String(),
        'unreadCount': unreadCount,
        'epoch': epoch,
        'keyBundleRef': keyBundleRef,
        'createdAt': createdAt.toIso8601String(),
      };

  factory Conversation.fromJson(Map<String, dynamic> json) => Conversation(
        groupId: base64Decode(json['groupId'] as String),
        displayName: json['displayName'] as String,
        participants: (json['participants'] as List<dynamic>)
            .map((e) => e as String)
            .toList(),
        lastMessagePreview: json['lastMessagePreview'] as String?,
        lastMessageAt: json['lastMessageAt'] != null
            ? DateTime.parse(json['lastMessageAt'] as String)
            : null,
        unreadCount: json['unreadCount'] as int? ?? 0,
        epoch: json['epoch'] as int? ?? 0,
        keyBundleRef: json['keyBundleRef'] as String,
        createdAt: DateTime.parse(json['createdAt'] as String),
      );
}
