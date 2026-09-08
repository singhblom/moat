import 'dart:convert';
import 'dart:typed_data';

/// A conversation with one or more participants
class Conversation {
  /// Unique conversation ID (MLS group ID)
  final Uint8List groupId;

  /// Display name (user-set override). When null, the UI resolves a name
  /// dynamically from participant profiles.
  String? displayName;

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

  /// Whether this device is an MLS member of the group.
  ///
  /// `false` for a conversation whose history arrived by sync before the
  /// fan-out `Add` that puts us in the group: the messages are readable,
  /// but there is no local MLS group to encrypt a reply to, so the
  /// composer stays closed until the `Add` lands.
  ///
  /// Defaults to `true` — every other way a conversation comes into
  /// existence goes through joining or creating its group.
  bool isMember;

  Conversation({
    required this.groupId,
    this.displayName,
    required this.participants,
    this.lastMessagePreview,
    this.lastMessageAt,
    this.unreadCount = 0,
    this.epoch = 0,
    required this.keyBundleRef,
    required this.createdAt,
    this.isMember = true,
  });

  /// Resolve a display name for this conversation.
  ///
  /// Returns [displayName] when explicitly set, otherwise builds a name from
  /// participants using [resolveDid] (e.g. profile lookup). Callers supply the
  /// resolver so the model stays independent of any caching/network layer.
  String resolveDisplayName(String Function(String did) resolveDid) {
    if (displayName != null) return displayName!;
    if (participants.isEmpty) return 'unknown';
    return participants.map(resolveDid).join(', ');
  }

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
        'isMember': isMember,
      };

  factory Conversation.fromJson(Map<String, dynamic> json) => Conversation(
        groupId: base64Decode(json['groupId'] as String),
        displayName: json['displayName'] as String?,
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
        // Absent in records written before read-only conversations
        // existed, and every one of those was a group we had joined.
        isMember: json['isMember'] as bool? ?? true,
      );
}
