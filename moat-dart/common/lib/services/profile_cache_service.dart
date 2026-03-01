import 'dart:convert';
import '../models/bluesky_profile.dart';
import 'atproto_client.dart';
import 'debug_log.dart';
import 'document_backend.dart';

/// App-wide cache for Bluesky profile data.
/// Uses a constructor-injected [DocumentBackend] — no path_provider dependency.
class ProfileCacheService {
  static const _path = 'profile_cache.json';
  static const _maxCacheAgeHours = 24;

  final AtprotoClient _client;
  final DocumentBackend _backend;

  final Map<String, BlueskyProfile> cache = {};
  final Map<String, Future<BlueskyProfile?>> _pendingFetches = {};

  ProfileCacheService({
    required AtprotoClient client,
    required DocumentBackend backend,
  })  : _client = client,
        _backend = backend;

  /// Initialize and load cached profiles from storage.
  Future<void> init() async {
    await _loadFromDisk();
  }

  Future<BlueskyProfile?> getProfile(String did) async {
    final cached = cache[did];
    if (cached != null && !cached.isStale) {
      return cached;
    }

    if (_pendingFetches.containsKey(did)) {
      return _pendingFetches[did];
    }

    final future = _fetchProfile(did);
    _pendingFetches[did] = future;

    try {
      final profile = await future;
      return profile;
    } finally {
      _pendingFetches.remove(did);
    }
  }

  Future<Map<String, BlueskyProfile>> getProfiles(List<String> dids) async {
    final results = <String, BlueskyProfile>{};
    final toFetch = <String>[];

    for (final did in dids) {
      final cached = cache[did];
      if (cached != null && !cached.isStale) {
        results[did] = cached;
      } else {
        toFetch.add(did);
      }
    }

    if (toFetch.isNotEmpty) {
      final fetched = await _fetchProfiles(toFetch);
      results.addAll(fetched);
    }

    return results;
  }

  Future<void> clearCache() async {
    cache.clear();
    await _backend.delete(_path);
  }

  Future<BlueskyProfile?> _fetchProfile(String did) async {
    try {
      final profile = await _client.getProfile(did);
      if (profile != null) {
        cache[did] = profile;
        await _saveToDisk();
      }
      return profile;
    } catch (e) {
      moatLog('ProfileCacheService: Failed to fetch profile for $did: $e');
      return cache[did];
    }
  }

  Future<Map<String, BlueskyProfile>> _fetchProfiles(List<String> dids) async {
    try {
      final profiles = await _client.getProfiles(dids);
      for (final profile in profiles) {
        cache[profile.did] = profile;
      }
      await _saveToDisk();
      return {for (final p in profiles) p.did: p};
    } catch (e) {
      moatLog('ProfileCacheService: Failed to fetch profiles: $e');
      return {
        for (final did in dids)
          if (cache.containsKey(did)) did: cache[did]!
      };
    }
  }

  Future<void> _loadFromDisk() async {
    try {
      final contents = await _backend.read(_path);
      if (contents == null) return;

      final json = jsonDecode(contents) as Map<String, dynamic>;
      for (final entry in json.entries) {
        final profile =
            BlueskyProfile.fromJson(entry.value as Map<String, dynamic>);
        if (DateTime.now().difference(profile.fetchedAt).inHours <
            _maxCacheAgeHours) {
          cache[entry.key] = profile;
        }
      }
      moatLog('ProfileCacheService: Loaded ${cache.length} profiles from cache');
    } catch (e) {
      moatLog('ProfileCacheService: Failed to load profile cache: $e');
    }
  }

  Future<void> _saveToDisk() async {
    try {
      final json = {for (final e in cache.entries) e.key: e.value.toJson()};
      await _backend.write(_path, jsonEncode(json));
    } catch (e) {
      moatLog('ProfileCacheService: Failed to save profile cache: $e');
    }
  }
}
