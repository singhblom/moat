import 'dart:convert';
import 'dart:io';
import '../models/bluesky_profile.dart';
import 'atproto_client.dart';
import 'debug_log.dart';

/// App-wide cache for Bluesky profile data.
/// Uses a constructor-injected [Directory] — no path_provider dependency.
class ProfileCacheService {
  static const _cacheFileName = 'profile_cache.json';
  static const _maxCacheAgeHours = 24;

  final AtprotoClient _client;
  final Directory _directory;

  final Map<String, BlueskyProfile> cache = {};
  final Map<String, Future<BlueskyProfile?>> _pendingFetches = {};

  File? _cacheFile;

  ProfileCacheService({
    required AtprotoClient client,
    required Directory directory,
  })  : _client = client,
        _directory = directory;

  /// Initialize and load cached profiles from disk.
  Future<void> init() async {
    await _directory.create(recursive: true);
    _cacheFile = File('${_directory.path}/$_cacheFileName');
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
    if (_cacheFile != null && await _cacheFile!.exists()) {
      await _cacheFile!.delete();
    }
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
    if (_cacheFile == null) return;

    try {
      if (await _cacheFile!.exists()) {
        final contents = await _cacheFile!.readAsString();
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
      }
    } catch (e) {
      moatLog('ProfileCacheService: Failed to load profile cache: $e');
    }
  }

  Future<void> _saveToDisk() async {
    if (_cacheFile == null) return;

    try {
      final json = {for (final e in cache.entries) e.key: e.value.toJson()};
      await _cacheFile!.writeAsString(jsonEncode(json));
    } catch (e) {
      moatLog('ProfileCacheService: Failed to save profile cache: $e');
    }
  }
}
