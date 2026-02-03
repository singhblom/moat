import 'package:flutter/foundation.dart';
import '../models/bluesky_profile.dart';
import '../services/profile_cache_service.dart';
import '../services/atproto_client.dart';

/// Provider for profile data with reactive updates
class ProfileProvider extends ChangeNotifier {
  final ProfileCacheService _cacheService;

  /// Track which DIDs are currently loading
  final Set<String> _loadingDids = {};

  ProfileProvider({required AtprotoClient atprotoClient})
      : _cacheService = ProfileCacheService(client: atprotoClient);

  Future<void> init() async {
    await _cacheService.init();
    notifyListeners();
  }

  /// Check if a profile is currently loading
  bool isLoading(String did) => _loadingDids.contains(did);

  /// Get a cached profile (returns null if not cached, triggers fetch)
  BlueskyProfile? getCachedProfile(String did) {
    final profile = _cacheService.cache[did];
    if (profile == null && !_loadingDids.contains(did)) {
      // Trigger background fetch
      _fetchInBackground(did);
    }
    return profile;
  }

  /// Get profile with await (for imperative code)
  Future<BlueskyProfile?> getProfile(String did) async {
    return await _cacheService.getProfile(did);
  }

  /// Preload profiles for a list of DIDs (call when entering a screen)
  Future<void> preloadProfiles(List<String> dids) async {
    final toLoad = dids
        .where((d) =>
            !_cacheService.cache.containsKey(d) && !_loadingDids.contains(d))
        .toList();

    if (toLoad.isEmpty) return;

    for (final did in toLoad) {
      _loadingDids.add(did);
    }
    notifyListeners();

    try {
      await _cacheService.getProfiles(toLoad);
    } finally {
      for (final did in toLoad) {
        _loadingDids.remove(did);
      }
      notifyListeners();
    }
  }

  void _fetchInBackground(String did) {
    _loadingDids.add(did);
    notifyListeners();

    _cacheService.getProfile(did).then((_) {
      _loadingDids.remove(did);
      notifyListeners();
    });
  }
}
