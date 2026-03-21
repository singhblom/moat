/// Integration test for Drawbridge WebSocket protocol.
///
/// Requires a running Drawbridge relay server.
/// Set DRAWBRIDGE_TEST_URL env var (default: ws://localhost:9877/ws).
///
/// Run via: ./scripts/test-drawbridge-integration.sh
/// Or manually:
///   RELAY_TLS=false RELAY_ADDR=:9877 go run . &
///   DRAWBRIDGE_TEST_URL=ws://localhost:9877/ws flutter test --tags integration test/integration/drawbridge_integration_test.dart
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:web_socket_channel/io.dart';

String get _relayUrl =>
    Platform.environment['DRAWBRIDGE_TEST_URL'] ?? 'ws://localhost:9877/ws';

/// Helper to connect and read one JSON message.
Future<Map<String, dynamic>> _readOne(IOWebSocketChannel channel) {
  final completer = Completer<Map<String, dynamic>>();
  late StreamSubscription sub;
  sub = channel.stream.listen((data) {
    sub.cancel();
    completer.complete(jsonDecode(data as String) as Map<String, dynamic>);
  }, onError: (e) {
    if (!completer.isCompleted) completer.completeError(e);
  });
  return completer.future.timeout(const Duration(seconds: 5));
}

void main() {
  group('Drawbridge relay protocol', () {
    test('request_challenge returns a challenge with nonce', () async {
      final channel = IOWebSocketChannel.connect(Uri.parse(_relayUrl));
      await channel.ready;

      // Send request_challenge
      channel.sink.add(jsonEncode({'type': 'request_challenge'}));

      // Should get back a challenge message
      final msg = await _readOne(channel);
      expect(msg['type'], 'challenge');
      expect(msg['nonce'], isA<String>());
      expect((msg['nonce'] as String).isNotEmpty, true);

      await channel.sink.close();
    });

    test('unauthenticated event_posted returns error', () async {
      final channel = IOWebSocketChannel.connect(Uri.parse(_relayUrl));
      await channel.ready;

      // Try sending event_posted without authenticating first
      channel.sink.add(jsonEncode({
        'type': 'event_posted',
        'tag': 'aa' * 16,
        'rkey': 'test-rkey',
        'payload': 'dGVzdA==',
        'relay_urls': [],
      }));

      final msg = await _readOne(channel);
      expect(msg['type'], 'error');

      await channel.sink.close();
    });

    test('unauthenticated watch_tags returns error', () async {
      final channel = IOWebSocketChannel.connect(Uri.parse(_relayUrl));
      await channel.ready;

      channel.sink.add(jsonEncode({
        'type': 'watch_tags',
        'tags': ['aa' * 16],
      }));

      final msg = await _readOne(channel);
      expect(msg['type'], 'error');

      await channel.sink.close();
    });

    test('unknown message type returns error', () async {
      final channel = IOWebSocketChannel.connect(Uri.parse(_relayUrl));
      await channel.ready;

      channel.sink.add(jsonEncode({
        'type': 'bogus_message',
      }));

      final msg = await _readOne(channel);
      expect(msg['type'], 'error');

      await channel.sink.close();
    });

    test('ticket_auth is rejected (ticket system removed)', () async {
      final channel = IOWebSocketChannel.connect(Uri.parse(_relayUrl));
      await channel.ready;

      channel.sink.add(jsonEncode({
        'type': 'ticket_auth',
        'ticket': 'ab' * 32,
      }));

      final msg = await _readOne(channel);
      expect(msg['type'], 'error');

      await channel.sink.close();
    });
  });
}
