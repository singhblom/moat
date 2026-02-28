/// Bluesky profile data fetched from the API
class BlueskyProfile {
  final String did;
  final String handle;
  final String? displayName;
  final String? avatarUrl;
  final DateTime fetchedAt;

  BlueskyProfile({
    required this.did,
    required this.handle,
    this.displayName,
    this.avatarUrl,
    required this.fetchedAt,
  });

  /// Check if cached data is stale (older than 30 minutes)
  bool get isStale => DateTime.now().difference(fetchedAt).inMinutes >= 30;

  Map<String, dynamic> toJson() => {
        'did': did,
        'handle': handle,
        'displayName': displayName,
        'avatarUrl': avatarUrl,
        'fetchedAt': fetchedAt.toIso8601String(),
      };

  factory BlueskyProfile.fromJson(Map<String, dynamic> json) => BlueskyProfile(
        did: json['did'] as String,
        handle: json['handle'] as String,
        displayName: json['displayName'] as String?,
        avatarUrl: json['avatarUrl'] as String?,
        fetchedAt: json['fetchedAt'] != null
            ? DateTime.parse(json['fetchedAt'] as String)
            : DateTime.now(),
      );

  /// Create from Bluesky API response
  factory BlueskyProfile.fromApiResponse(Map<String, dynamic> json) =>
      BlueskyProfile(
        did: json['did'] as String,
        handle: json['handle'] as String,
        displayName: json['displayName'] as String?,
        avatarUrl: json['avatar'] as String?,
        fetchedAt: DateTime.now(),
      );
}
