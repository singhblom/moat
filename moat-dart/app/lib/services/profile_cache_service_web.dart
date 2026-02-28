import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web/web.dart' as web;
import '../models/bluesky_profile.dart';
import 'atproto_client.dart';

/// Web localStorage-based cache for Bluesky profile data
class ProfileCacheService {
  static const _key = 'moat_profile_cache';
  static const _maxCacheAgeHours = 24;

  final AtprotoClient _client;

  /// In-memory cache: DID -> BlueskyProfile
  final Map<String, BlueskyProfile> cache = {};

  /// Pending fetch requests to avoid duplicate API calls
  final Map<String, Future<BlueskyProfile?>> _pendingFetches = {};

  ProfileCacheService({required AtprotoClient client}) : _client = client;

  /// Initialize and load cached profiles from localStorage
  Future<void> init() async {
    await _loadFromStorage();
  }

  /// Get profile for a DID (returns cached if available, fetches if not)
  Future<BlueskyProfile?> getProfile(String did) async {
    // Check in-memory cache first
    final cached = cache[did];
    if (cached != null && !cached.isStale) {
      return cached;
    }

    // Check if already fetching
    if (_pendingFetches.containsKey(did)) {
      return _pendingFetches[did];
    }

    // Fetch from API
    final future = _fetchProfile(did);
    _pendingFetches[did] = future;

    try {
      final profile = await future;
      return profile;
    } finally {
      _pendingFetches.remove(did);
    }
  }

  /// Get profiles for multiple DIDs (uses bulk API when possible)
  Future<Map<String, BlueskyProfile>> getProfiles(List<String> dids) async {
    final results = <String, BlueskyProfile>{};
    final toFetch = <String>[];

    // Check cache first
    for (final did in dids) {
      final cached = cache[did];
      if (cached != null && !cached.isStale) {
        results[did] = cached;
      } else {
        toFetch.add(did);
      }
    }

    // Bulk fetch remaining
    if (toFetch.isNotEmpty) {
      final fetched = await _fetchProfiles(toFetch);
      results.addAll(fetched);
    }

    return results;
  }

  /// Clear all cached data
  Future<void> clearCache() async {
    cache.clear();
    web.window.localStorage.removeItem(_key);
  }

  Future<BlueskyProfile?> _fetchProfile(String did) async {
    try {
      final profile = await _client.getProfile(did);
      if (profile != null) {
        cache[did] = profile;
        await _saveToStorage();
      }
      return profile;
    } catch (e) {
      debugPrint('Failed to fetch profile for $did: $e');
      // Return stale cache if fetch fails
      return cache[did];
    }
  }

  Future<Map<String, BlueskyProfile>> _fetchProfiles(
      List<String> dids) async {
    try {
      final profiles = await _client.getProfiles(dids);
      for (final profile in profiles) {
        cache[profile.did] = profile;
      }
      await _saveToStorage();
      return {for (final p in profiles) p.did: p};
    } catch (e) {
      debugPrint('Failed to fetch profiles: $e');
      // Return whatever we have cached
      return {
        for (final did in dids)
          if (cache.containsKey(did)) did: cache[did]!
      };
    }
  }

  Future<void> _loadFromStorage() async {
    try {
      final contents = web.window.localStorage.getItem(_key);
      if (contents == null) return;

      final json = jsonDecode(contents) as Map<String, dynamic>;
      for (final entry in json.entries) {
        final profile =
            BlueskyProfile.fromJson(entry.value as Map<String, dynamic>);
        // Only load if not too old
        if (DateTime.now().difference(profile.fetchedAt).inHours <
            _maxCacheAgeHours) {
          cache[entry.key] = profile;
        }
      }
      debugPrint('Loaded ${cache.length} profiles from cache');
    } catch (e) {
      debugPrint('Failed to load profile cache: $e');
    }
  }

  Future<void> _saveToStorage() async {
    try {
      final json = {for (final e in cache.entries) e.key: e.value.toJson()};
      web.window.localStorage.setItem(_key, jsonEncode(json));
    } catch (e) {
      debugPrint('Failed to save profile cache: $e');
    }
  }
}
