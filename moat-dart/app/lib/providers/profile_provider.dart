import 'package:flutter/foundation.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// Provider for profile data with reactive updates.
/// Thin [ChangeNotifier] wrapper around [ProfileCacheService].
class ProfileProvider extends ChangeNotifier {
  final ProfileCacheService _cacheService;

  /// Track which DIDs are currently loading.
  final Set<String> _loadingDids = {};

  ProfileProvider({required ProfileCacheService cacheService})
      : _cacheService = cacheService;

  Future<void> init() async {
    await _cacheService.init();
    notifyListeners();
  }

  bool isLoading(String did) => _loadingDids.contains(did);

  BlueskyProfile? getCachedProfile(String did) {
    final profile = _cacheService.cache[did];
    if (profile == null && !_loadingDids.contains(did)) {
      _fetchInBackground(did);
    }
    return profile;
  }

  Future<BlueskyProfile?> getProfile(String did) async {
    return await _cacheService.getProfile(did);
  }

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

    _cacheService.getProfile(did).then((_) {
      _loadingDids.remove(did);
      notifyListeners();
    });
  }
}
