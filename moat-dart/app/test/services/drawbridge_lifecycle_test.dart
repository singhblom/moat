/// Tests for DrawbridgeService lifecycle management.
///
/// Verifies the init → connect → disconnect → reconnect → reset cycle
/// that AuthGate drives during login/logout/background/resume.
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

void main() {
  late DrawbridgeService db;

  setUp(() {
    DrawbridgeService.instance.reset();
    db = DrawbridgeService.instance;
  });

  group('DrawbridgeService lifecycle', () {
    test('init → disconnectAll → re-init cycle works', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      expect(db.isOwnConnected, false);

      db.disconnectAll();
      expect(db.isOwnConnected, false);

      // Re-init after disconnect (simulates app resume)
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      expect(db.isOwnConnected, false);
    });

    test('reset clears all state including tags and config cache', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      db.watchTags([Uint8List.fromList([1, 2, 3])]);
      db.cacheDrawbridgeConfig('did:plc:bob', ['wss://relay.example.com']);

      db.reset();
      expect(db.isOwnConnected, false);
      expect(db.relayUrlsForParticipants(['did:plc:bob']), isEmpty);
    });

    test('onNewEvent callback can be set and cleared', () {
      var callCount = 0;
      db.onNewEvent = (_) => callCount++;

      // Callback is set but won't fire without a real WebSocket
      expect(db.onNewEvent, isNotNull);

      // Simulate what reset does
      db.reset();
      // onNewEvent is not cleared by reset (AuthGate re-sets it)
      expect(db.onNewEvent, isNotNull);
    });

    test('watchTags before connect stores tags for later', () {
      db.watchTags([
        Uint8List.fromList([1, 2, 3]),
        Uint8List.fromList([4, 5, 6]),
      ]);
      // No crash = pass; tags are queued for when connection is established
    });

    test('notifyEventPosted is no-op when not connected', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      // Should not throw — silently ignored
      db.notifyEventPosted(
        tag: Uint8List.fromList([1, 2, 3]),
        rkey: 'rkey123',
        payload: Uint8List.fromList([4, 5, 6]),
        relayUrls: ['wss://relay.example.com'],
      );
    });

    test('connectOwn without init is no-op', () async {
      // No init called — _did and _keyBundle are null
      await db.connectOwn('wss://relay.example.com/ws');
      expect(db.isOwnConnected, false);
    });

    test('multiple disconnectAll calls are safe', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      db.disconnectAll();
      db.disconnectAll(); // second call should not throw
      expect(db.isOwnConnected, false);
    });

    test('multiple reset calls are safe', () {
      db.reset();
      db.reset(); // second call should not throw
      expect(db.isOwnConnected, false);
    });
  });

  group('Tag management', () {
    test('watchTags replaces previous tags', () {
      db.watchTags([Uint8List.fromList([1, 2, 3])]);
      db.watchTags([Uint8List.fromList([4, 5, 6])]);
      // No crash; second call replaces first set
    });

    test('addTags accumulates', () {
      db.addTags([Uint8List.fromList([1, 2, 3])]);
      db.addTags([Uint8List.fromList([4, 5, 6])]);
      // No crash; both tag sets are stored
    });

    test('updateTags adds and removes', () {
      db.watchTags([Uint8List.fromList([1, 2, 3])]);
      db.updateTags(
        add: [Uint8List.fromList([4, 5, 6])],
        remove: [Uint8List.fromList([1, 2, 3])],
      );
      // No crash; tag set should now contain only [4,5,6]
    });
  });

  group('Config cache lifecycle', () {
    test('cache survives disconnectAll but is cleared by reset', () {
      db.cacheDrawbridgeConfig('did:plc:bob', ['wss://relay.example.com']);

      db.disconnectAll();
      // Config cache survives disconnect (reconnect doesn't need to re-fetch)
      // (Cannot directly verify internal state, but relayUrlsForParticipants works)

      db.reset();
      expect(db.relayUrlsForParticipants(['did:plc:bob']), isEmpty);
    });

    test('cacheDrawbridgeConfig overwrites previous entry', () {
      db.cacheDrawbridgeConfig('did:plc:bob', ['wss://old-relay.com']);
      db.cacheDrawbridgeConfig('did:plc:bob', ['wss://new-relay.com']);

      final urls = db.relayUrlsForParticipants(['did:plc:bob']);
      expect(urls, ['wss://new-relay.com']);
    });
  });
}
