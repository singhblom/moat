import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/bluesky_profile.dart';

void main() {
  group('BlueskyProfile', () {
    BlueskyProfile makeProfile({
      String did = 'did:plc:abc123',
      String handle = 'alice.bsky.social',
      String? displayName = 'Alice',
      String? avatarUrl = 'https://cdn.bsky.app/avatar.jpg',
      DateTime? fetchedAt,
    }) {
      return BlueskyProfile(
        did: did,
        handle: handle,
        displayName: displayName,
        avatarUrl: avatarUrl,
        fetchedAt: fetchedAt ?? DateTime.utc(2025, 1, 15, 12, 0, 0),
      );
    }

    group('toJson / fromJson roundtrip', () {
      test('basic profile roundtrips', () {
        final original = makeProfile();
        final restored = BlueskyProfile.fromJson(original.toJson());

        expect(restored.did, original.did);
        expect(restored.handle, original.handle);
        expect(restored.displayName, original.displayName);
        expect(restored.avatarUrl, original.avatarUrl);
        expect(restored.fetchedAt, original.fetchedAt);
      });

      test('profile with null optional fields roundtrips', () {
        final original = makeProfile(displayName: null, avatarUrl: null);
        final restored = BlueskyProfile.fromJson(original.toJson());

        expect(restored.displayName, isNull);
        expect(restored.avatarUrl, isNull);
      });

      test('survives JSON encode/decode cycle', () {
        final original = makeProfile(displayName: 'Name with \u{1F600}');
        final jsonString = jsonEncode(original.toJson());
        final decoded = jsonDecode(jsonString) as Map<String, dynamic>;
        final restored = BlueskyProfile.fromJson(decoded);

        expect(restored.displayName, original.displayName);
      });
    });

    group('fromJson edge cases', () {
      test('missing fetchedAt uses current time', () {
        final json = makeProfile().toJson();
        json.remove('fetchedAt');
        json['fetchedAt'] = null;
        final before = DateTime.now();
        final restored = BlueskyProfile.fromJson(json);
        final after = DateTime.now();

        expect(restored.fetchedAt.isAfter(before.subtract(Duration(seconds: 1))), isTrue);
        expect(restored.fetchedAt.isBefore(after.add(Duration(seconds: 1))), isTrue);
      });
    });

    group('fromApiResponse', () {
      test('maps API fields correctly', () {
        final apiJson = {
          'did': 'did:plc:xyz',
          'handle': 'bob.bsky.social',
          'displayName': 'Bob',
          'avatar': 'https://cdn.bsky.app/bob-avatar.jpg',
        };
        final before = DateTime.now();
        final profile = BlueskyProfile.fromApiResponse(apiJson);
        final after = DateTime.now();

        expect(profile.did, 'did:plc:xyz');
        expect(profile.handle, 'bob.bsky.social');
        expect(profile.displayName, 'Bob');
        expect(profile.avatarUrl, 'https://cdn.bsky.app/bob-avatar.jpg');
        expect(profile.fetchedAt.isAfter(before.subtract(Duration(seconds: 1))), isTrue);
        expect(profile.fetchedAt.isBefore(after.add(Duration(seconds: 1))), isTrue);
      });

      test('handles null displayName and avatar from API', () {
        final apiJson = {
          'did': 'did:plc:xyz',
          'handle': 'bob.bsky.social',
          'displayName': null,
          'avatar': null,
        };
        final profile = BlueskyProfile.fromApiResponse(apiJson);

        expect(profile.displayName, isNull);
        expect(profile.avatarUrl, isNull);
      });
    });

    group('isStale', () {
      test('profile fetched just now is not stale', () {
        final profile = makeProfile(fetchedAt: DateTime.now());
        expect(profile.isStale, isFalse);
      });

      test('profile fetched 31 minutes ago is stale', () {
        final profile = makeProfile(
          fetchedAt: DateTime.now().subtract(Duration(minutes: 31)),
        );
        expect(profile.isStale, isTrue);
      });

      test('profile fetched 29 minutes ago is not stale', () {
        final profile = makeProfile(
          fetchedAt: DateTime.now().subtract(Duration(minutes: 29)),
        );
        expect(profile.isStale, isFalse);
      });
    });
  });
}
