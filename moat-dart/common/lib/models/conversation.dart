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

  /// Drawbridge hints received from partner devices.
  /// Keyed by (partnerDid, deviceIdHex) — one hint per partner leaf node.
  final List<StoredDrawbridgeHint> partnerDrawbridgeHints;

  /// Our own ticket (hex) registered on our relay for this conversation
  String? ownDrawbridgeTicketHex;

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
    List<StoredDrawbridgeHint>? partnerDrawbridgeHints,
    this.ownDrawbridgeTicketHex,
  }) : partnerDrawbridgeHints = partnerDrawbridgeHints ?? [];

  /// Group ID as hex string (for display/storage keys)
  String get groupIdHex =>
      groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Add or update a partner Drawbridge hint (keyed by partnerDid + deviceIdHex).
  void upsertPartnerHint(StoredDrawbridgeHint hint) {
    partnerDrawbridgeHints.removeWhere(
      (h) => h.partnerDid == hint.partnerDid && h.deviceIdHex == hint.deviceIdHex,
    );
    partnerDrawbridgeHints.add(hint);
  }

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
        if (partnerDrawbridgeHints.isNotEmpty)
          'partnerDrawbridgeHints':
              partnerDrawbridgeHints.map((h) => h.toJson()).toList(),
        if (ownDrawbridgeTicketHex != null)
          'ownDrawbridgeTicketHex': ownDrawbridgeTicketHex,
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
        partnerDrawbridgeHints: (json['partnerDrawbridgeHints'] as List<dynamic>?)
                ?.map((e) =>
                    StoredDrawbridgeHint.fromJson(e as Map<String, dynamic>))
                .toList() ??
            [],
        ownDrawbridgeTicketHex: json['ownDrawbridgeTicketHex'] as String?,
      );
}

/// Persisted hint from a conversation partner's device.
class StoredDrawbridgeHint {
  final String url;
  final String deviceIdHex;
  final String ticketHex;
  final String partnerDid;

  StoredDrawbridgeHint({
    required this.url,
    required this.deviceIdHex,
    required this.ticketHex,
    required this.partnerDid,
  });

  Map<String, dynamic> toJson() => {
        'url': url,
        'deviceIdHex': deviceIdHex,
        'ticketHex': ticketHex,
        'partnerDid': partnerDid,
      };

  factory StoredDrawbridgeHint.fromJson(Map<String, dynamic> json) =>
      StoredDrawbridgeHint(
        url: json['url'] as String,
        deviceIdHex: json['deviceIdHex'] as String,
        ticketHex: json['ticketHex'] as String,
        partnerDid: json['partnerDid'] as String,
      );
}
