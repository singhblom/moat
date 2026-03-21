import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

void main() {
  group('DrawbridgeService', () {
    late DrawbridgeService service;

    setUp(() {
      // Reset singleton state for each test
      DrawbridgeService.instance.reset();
      service = DrawbridgeService.instance;
    });

    test('starts unconnected', () {
      expect(service.isOwnConnected, false);
    });

    test('init stores credentials', () {
      service.init(
        did: 'did:plc:test',
        keyBundle: Uint8List.fromList(List.filled(32, 0x42)),
      );
      // After init, still not connected (no WebSocket yet)
      expect(service.isOwnConnected, false);
    });

    test('notifyEventPosted does nothing when not authenticated', () {
      // Should not throw
      service.notifyEventPosted(
        tag: Uint8List.fromList([0x01, 0x02]),
        rkey: 'rkey123',
        payload: Uint8List.fromList([0x03, 0x04]),
        relayUrls: [],
      );
    });

    test('watchTags does nothing when not connected', () {
      // Should not throw — tags are stored but not sent
      service.watchTags([Uint8List.fromList([1, 2, 3])]);
    });

    test('addTags does nothing when not connected', () {
      service.addTags([Uint8List.fromList([4, 5, 6])]);
    });

    test('reset clears all state', () {
      service.init(
        did: 'did:plc:test',
        keyBundle: Uint8List.fromList(List.filled(32, 0x42)),
      );
      service.watchTags([Uint8List.fromList([1, 2, 3])]);
      service.cacheDrawbridgeConfig('did:plc:bob', ['wss://relay.example.com']);
      service.reset();
      expect(service.isOwnConnected, false);
      expect(service.relayUrlsForParticipants(['did:plc:bob']), isEmpty);
    });

    test('disconnectAll marks as disposed', () {
      service.init(
        did: 'did:plc:test',
        keyBundle: Uint8List.fromList(List.filled(32, 0x42)),
      );
      service.disconnectAll();
      expect(service.isOwnConnected, false);
    });
  });

  group('Drawbridge config cache', () {
    late DrawbridgeService service;

    setUp(() {
      DrawbridgeService.instance.reset();
      service = DrawbridgeService.instance;
    });

    test('cacheDrawbridgeConfig stores and retrieves URLs', () {
      service.cacheDrawbridgeConfig(
          'did:plc:alice', ['wss://relay-a.example.com']);
      service.cacheDrawbridgeConfig(
          'did:plc:bob', ['wss://relay-b.example.com']);

      final urls = service
          .relayUrlsForParticipants(['did:plc:alice', 'did:plc:bob']);
      expect(urls, hasLength(2));
      expect(urls, contains('wss://relay-a.example.com'));
      expect(urls, contains('wss://relay-b.example.com'));
    });

    test('relayUrlsForParticipants deduplicates', () {
      service.cacheDrawbridgeConfig(
          'did:plc:alice', ['wss://shared-relay.example.com']);
      service.cacheDrawbridgeConfig(
          'did:plc:bob', ['wss://shared-relay.example.com']);

      final urls = service
          .relayUrlsForParticipants(['did:plc:alice', 'did:plc:bob']);
      expect(urls, hasLength(1));
      expect(urls.first, 'wss://shared-relay.example.com');
    });

    test('relayUrlsForParticipants returns empty for unknown DIDs', () {
      final urls = service.relayUrlsForParticipants(['did:plc:unknown']);
      expect(urls, isEmpty);
    });

    test('cacheDrawbridgeConfig ignores empty URLs', () {
      service.cacheDrawbridgeConfig('did:plc:alice', []);
      final urls = service.relayUrlsForParticipants(['did:plc:alice']);
      expect(urls, isEmpty);
    });

    test('reset clears config cache', () {
      service.cacheDrawbridgeConfig(
          'did:plc:alice', ['wss://relay.example.com']);
      service.reset();
      final urls = service.relayUrlsForParticipants(['did:plc:alice']);
      expect(urls, isEmpty);
    });
  });

  group('DrawbridgeNewEvent', () {
    test('can be created with all fields', () {
      final event = DrawbridgeNewEvent(
        tagHex: 'aa' * 16,
        rkey: 'test-rkey',
        payload: Uint8List.fromList([1, 2, 3]),
      );
      expect(event.tagHex, 'aa' * 16);
      expect(event.rkey, 'test-rkey');
      expect(event.payload, isNotNull);
    });

    test('payload is optional', () {
      final event = DrawbridgeNewEvent(
        tagHex: 'bb' * 16,
        rkey: 'rkey2',
      );
      expect(event.payload, isNull);
    });
  });

  group('Conversation model (no Drawbridge fields)', () {
    Conversation makeConversation() {
      return Conversation(
        groupId: Uint8List.fromList([1, 2, 3, 4]),
        displayName: 'Test',
        participants: ['did:plc:bob'],
        keyBundleRef: 'ref',
        createdAt: DateTime.utc(2025, 1, 1),
      );
    }

    test('JSON roundtrip has no hint/ticket fields', () {
      final conv = makeConversation();
      final json = conv.toJson();
      expect(json.containsKey('partnerDrawbridgeHints'), false);
      expect(json.containsKey('ownDrawbridgeTicketHex'), false);

      final restored = Conversation.fromJson(json);
      expect(restored.groupIdHex, conv.groupIdHex);
      expect(restored.displayName, 'Test');
    });

    test('fromJson ignores legacy hint/ticket fields', () {
      final json = makeConversation().toJson();
      // Simulate old serialized data with legacy fields
      json['partnerDrawbridgeHints'] = [
        {
          'url': 'wss://old.relay.com',
          'deviceIdHex': 'aa',
          'ticketHex': 'bb' * 32,
          'partnerDid': 'did:plc:alice',
        }
      ];
      json['ownDrawbridgeTicketHex'] = 'cc' * 32;

      // Should not throw — unknown keys are silently ignored
      final restored = Conversation.fromJson(json);
      expect(restored.displayName, 'Test');
    });
  });
}
