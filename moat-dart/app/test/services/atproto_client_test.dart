/// Tests for AtprotoClient auto-refresh behavior and ATProto wire format.
///
/// Verifies that:
/// - Authenticated requests automatically refresh the access token
///   when the PDS returns a 401 / "Token has expired" error, then retry.
/// - Byte fields are serialized as ATProto IPLD `{"$bytes": "<base64>"}` objects.
/// - Byte fields are deserialized from the `{"$bytes": "<base64>"}` format.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// Helper: build a mock session for testing.
AtprotoSession _testSession({
  String accessJwt = 'old-access',
  String refreshJwt = 'refresh-token',
}) =>
    AtprotoSession(
      did: 'did:plc:test',
      handle: 'test.bsky.social',
      accessJwt: accessJwt,
      refreshJwt: refreshJwt,
      pdsUrl: 'https://pds.example.com',
    );

/// Helper: JSON body for a successful refreshSession response.
String _refreshResponse({
  String accessJwt = 'new-access',
  String refreshJwt = 'new-refresh',
}) =>
    jsonEncode({
      'did': 'did:plc:test',
      'handle': 'test.bsky.social',
      'accessJwt': accessJwt,
      'refreshJwt': refreshJwt,
    });

/// Helper: JSON body for a successful createRecord response.
String _createRecordResponse() => jsonEncode({
      'uri': 'at://did:plc:test/social.moat.event/abc123',
      'cid': 'bafyxyz',
    });

void main() {
  group('AtprotoClient auto-refresh', () {
    test('publishEvent retries after 401 with refreshed token', () async {
      var requestCount = 0;

      final mockClient = MockClient((request) async {
        requestCount++;

        // First createRecord call → 401
        if (requestCount == 1) {
          expect(request.headers['Authorization'], 'Bearer old-access');
          return http.Response(
            jsonEncode({'error': 'ExpiredToken', 'message': 'Token has expired'}),
            401,
          );
        }

        // Second call: refreshSession
        if (requestCount == 2) {
          expect(request.url.path, '/xrpc/com.atproto.server.refreshSession');
          expect(request.headers['Authorization'], 'Bearer refresh-token');
          return http.Response(_refreshResponse(), 200);
        }

        // Third call: retry createRecord with new token
        if (requestCount == 3) {
          expect(request.headers['Authorization'], 'Bearer new-access');
          return http.Response(_createRecordResponse(), 200);
        }

        fail('Unexpected request #$requestCount');
      });

      final client = AtprotoClient(httpClient: mockClient);
      client.restoreSession(_testSession());

      final tag = Uint8List.fromList(List.filled(16, 0xAA));
      final ciphertext = Uint8List.fromList(List.filled(256, 0xBB));
      final uri = await client.publishEvent(
        tag,
        ciphertext,
      );

      expect(uri, contains('social.moat.event'));
      expect(requestCount, 3);
      // Verify session was updated
      expect(client.session!.accessJwt, 'new-access');
    });

    test('onSessionRefreshed callback fires after auto-refresh', () async {
      var callbackSession = <AtprotoSession>[];

      final mockClient = MockClient((request) async {
        if (request.url.path.contains('createRecord')) {
          if (request.headers['Authorization'] == 'Bearer old-access') {
            return http.Response(
              jsonEncode({'message': 'Token has expired'}),
              401,
            );
          }
          return http.Response(_createRecordResponse(), 200);
        }
        if (request.url.path.contains('refreshSession')) {
          return http.Response(_refreshResponse(), 200);
        }
        fail('Unexpected: ${request.url}');
      });

      final client = AtprotoClient(httpClient: mockClient);
      client.restoreSession(_testSession());
      client.onSessionRefreshed = (s) => callbackSession.add(s);

      await client.publishEvent(Uint8List(16), Uint8List(32));

      expect(callbackSession, hasLength(1));
      expect(callbackSession.first.accessJwt, 'new-access');
    });

    test('non-401 errors propagate without refresh attempt', () async {
      var requestCount = 0;

      final mockClient = MockClient((request) async {
        requestCount++;
        return http.Response(
          jsonEncode({'message': 'Server error'}),
          500,
        );
      });

      final client = AtprotoClient(httpClient: mockClient);
      client.restoreSession(_testSession());

      await expectLater(
        () => client.publishEvent(Uint8List(16), Uint8List(32)),
        throwsA(isA<AtprotoException>()),
      );
      // Only one request — no refresh attempted
      expect(requestCount, 1);
    });

    test('refresh failure propagates the refresh error', () async {
      var requestCount = 0;

      final mockClient = MockClient((request) async {
        requestCount++;
        if (requestCount == 1) {
          return http.Response(
            jsonEncode({'message': 'Token has expired'}),
            401,
          );
        }
        // Refresh also fails
        return http.Response(
          jsonEncode({'message': 'Invalid refresh token'}),
          401,
        );
      });

      final client = AtprotoClient(httpClient: mockClient);
      client.restoreSession(_testSession());

      expect(
        () => client.publishEvent(Uint8List(16), Uint8List(32)),
        throwsA(isA<AtprotoException>().having(
          (e) => e.message,
          'message',
          contains('Invalid refresh token'),
        )),
      );
    });

    test('publishKeyPackage also auto-refreshes on 401', () async {
      var refreshed = false;

      final mockClient = MockClient((request) async {
        if (request.url.path.contains('createRecord')) {
          if (!refreshed) {
            return http.Response(
              jsonEncode({'message': 'Token has expired'}),
              401,
            );
          }
          return http.Response(_createRecordResponse(), 200);
        }
        if (request.url.path.contains('refreshSession')) {
          refreshed = true;
          return http.Response(_refreshResponse(), 200);
        }
        fail('Unexpected: ${request.url}');
      });

      final client = AtprotoClient(httpClient: mockClient);
      client.restoreSession(_testSession());

      final uri = await client.publishKeyPackage(Uint8List(64));
      expect(uri, isNotEmpty);
      expect(refreshed, true);
    });
  });

  group('ATProto IPLD bytes wire format — publish', () {
    late Map<String, dynamic> capturedRecord;

    setUp(() {
      capturedRecord = {};
    });

    MockClient _captureClient() => MockClient((request) async {
          if (request.url.path.contains('createRecord')) {
            final body = jsonDecode(request.body) as Map<String, dynamic>;
            capturedRecord = body['record'] as Map<String, dynamic>;
            return http.Response(_createRecordResponse(), 200);
          }
          fail('Unexpected: ${request.url}');
        });

    test('publishEvent serializes tag and ciphertext as {"\$bytes": "..."}', () async {
      final client = AtprotoClient(httpClient: _captureClient());
      client.restoreSession(_testSession());

      final tag = Uint8List.fromList(List.generate(16, (i) => i));
      final ciphertext = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);

      await client.publishEvent(tag, ciphertext);

      expect(capturedRecord['tag'], isA<Map>());
      expect((capturedRecord['tag'] as Map)[r'$bytes'], isA<String>());
      expect(capturedRecord['ciphertext'], isA<Map>());
      expect((capturedRecord['ciphertext'] as Map)[r'$bytes'], isA<String>());

      // Verify the base64 round-trips correctly
      final decodedTag = base64Decode((capturedRecord['tag'] as Map)[r'$bytes'] as String);
      expect(decodedTag, tag);
    });

    test('publishKeyPackage serializes keyPackage as {"\$bytes": "..."}', () async {
      final client = AtprotoClient(httpClient: _captureClient());
      client.restoreSession(_testSession());

      final kp = Uint8List.fromList(List.generate(64, (i) => i));
      await client.publishKeyPackage(kp);

      expect(capturedRecord['keyPackage'], isA<Map>());
      expect((capturedRecord['keyPackage'] as Map)[r'$bytes'], isA<String>());

      final decoded = base64Decode((capturedRecord['keyPackage'] as Map)[r'$bytes'] as String);
      expect(decoded, kp);
    });

    test('publishStealthAddress serializes scanPubkey as {"\$bytes": "..."}', () async {
      final client = AtprotoClient(httpClient: _captureClient());
      client.restoreSession(_testSession());

      final pubkey = Uint8List.fromList(List.generate(32, (i) => i + 1));
      await client.publishStealthAddress(pubkey, 'My Phone');

      expect(capturedRecord['scanPubkey'], isA<Map>());
      expect((capturedRecord['scanPubkey'] as Map)[r'$bytes'], isA<String>());

      final decoded = base64Decode((capturedRecord['scanPubkey'] as Map)[r'$bytes'] as String);
      expect(decoded, pubkey);
    });
  });

  group('ATProto IPLD bytes wire format — parse', () {
    test('EventRecord.fromJson parses {"\$bytes": "..."} tag and ciphertext', () {
      final tag = Uint8List.fromList(List.generate(16, (i) => i));
      final ciphertext = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);

      final json = {
        'uri': 'at://did:plc:test/social.moat.event/abc123',
        'value': {
          'tag': {r'$bytes': base64Encode(tag)},
          'ciphertext': {r'$bytes': base64Encode(ciphertext)},
          'createdAt': '2024-01-01T00:00:00.000Z',
        },
      };

      final record = EventRecord.fromJson(json);
      expect(record.tag, tag);
      expect(record.ciphertext, ciphertext);
    });

    test('KeyPackageRecord.fromJson parses {"\$bytes": "..."} keyPackage', () {
      final kp = Uint8List.fromList(List.generate(64, (i) => i));

      final json = {
        'ciphersuite': 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
        'keyPackage': {r'$bytes': base64Encode(kp)},
        'expiresAt': '2099-01-01T00:00:00.000Z',
        'createdAt': '2024-01-01T00:00:00.000Z',
      };

      final record = KeyPackageRecord.fromJson(json);
      expect(record.keyPackage, kp);
    });
  });
}
