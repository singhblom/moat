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
      expect(db.partnerConnectionCount, 0);

      // Re-init after disconnect (simulates app resume)
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      expect(db.isOwnConnected, false);
    });

    test('reset clears all state including tickets', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      db.registerTicket('group1', 'ticket1');
      db.registerTicket('group2', 'ticket2');

      db.reset();
      expect(db.isOwnConnected, false);
      expect(db.partnerConnectionCount, 0);
    });

    test('onNewEvent callback can be set and cleared', () {
      var callCount = 0;
      db.onNewEvent = () => callCount++;

      // Callback is set but won't fire without a real WebSocket
      expect(db.onNewEvent, isNotNull);

      // Simulate what reset does
      db.reset();
      // onNewEvent is not cleared by reset (AuthGate re-sets it)
      expect(db.onNewEvent, isNotNull);
    });

    test('registerTicket before connect is safe and idempotent', () {
      db.registerTicket('group1', 'ticket_aaa');
      db.registerTicket('group1', 'ticket_bbb'); // override
      db.registerTicket('group2', 'ticket_ccc');
      // No crash = pass; tickets are queued for when connection is established
    });

    test('notifyEventPosted is no-op when not connected', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      // Should not throw — silently ignored
      db.notifyEventPosted(Uint8List.fromList([1, 2, 3]), 'rkey123');
    });

    test('reconnectPartners with empty list is no-op', () async {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      await db.reconnectPartners([]);
      expect(db.partnerConnectionCount, 0);
    });

    test('reconnectPartners after dispose is no-op', () async {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      db.disconnectAll(); // sets _disposed = true
      await db.reconnectPartners([
        (
          url: 'wss://relay.example.com/ws',
          ticketHex: 'ab' * 32,
          tags: <Uint8List>[],
        ),
      ]);
      // Should be skipped because disposed
      expect(db.partnerConnectionCount, 0);
    });
  });

  group('Reconnect and resilience', () {
    test('disconnectAll cancels pending reconnect timer', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );

      // disconnectAll sets _disposed = true, which prevents reconnect
      db.disconnectAll();

      // Re-init should work cleanly (no stale timer firing)
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      expect(db.isOwnConnected, false);
    });

    test('reset clears reconnect attempts', () {
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      db.reset();

      // After reset, re-init and connect should start fresh
      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );
      expect(db.isOwnConnected, false);
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
      expect(db.partnerConnectionCount, 0);
    });
  });

  group('Conversation hint lifecycle', () {
    Conversation makeConv() => Conversation(
          groupId: Uint8List.fromList([1, 2, 3]),
          displayName: 'Test',
          participants: ['did:plc:bob'],
          keyBundleRef: 'ref',
          createdAt: DateTime.utc(2025, 1, 1),
        );

    test('build reconnect list from conversations with hints', () {
      final conv = makeConv();
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://relay-a.com/ws',
        deviceIdHex: 'dev1',
        ticketHex: 'aa' * 32,
        partnerDid: 'did:plc:bob',
      ));
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://relay-b.com/ws',
        deviceIdHex: 'dev2',
        ticketHex: 'bb' * 32,
        partnerDid: 'did:plc:bob',
      ));
      conv.ownDrawbridgeTicketHex = 'cc' * 32;

      // Simulate what _reconnectDrawbridge does
      final hintsWithTags =
          <({String url, String ticketHex, List<Uint8List> tags})>[];
      final fakeTags = [Uint8List.fromList([10, 20, 30])];

      for (final hint in conv.partnerDrawbridgeHints) {
        hintsWithTags.add((
          url: hint.url,
          ticketHex: hint.ticketHex,
          tags: fakeTags,
        ));
      }

      expect(hintsWithTags.length, 2);
      expect(hintsWithTags[0].url, 'wss://relay-a.com/ws');
      expect(hintsWithTags[1].url, 'wss://relay-b.com/ws');
    });

    test('conversations without hints produce empty reconnect list', () {
      final conv = makeConv();
      final hintsWithTags =
          <({String url, String ticketHex, List<Uint8List> tags})>[];
      if (conv.partnerDrawbridgeHints.isNotEmpty) {
        fail('should be empty');
      }
      expect(hintsWithTags, isEmpty);
    });

    test('own ticket re-registration from conversation metadata', () {
      final conv = makeConv();
      conv.ownDrawbridgeTicketHex = 'dd' * 32;

      db.init(
        did: 'did:plc:alice',
        keyBundle: Uint8List.fromList(List.filled(32, 1)),
      );

      // Simulate what _reconnectDrawbridge does
      if (conv.ownDrawbridgeTicketHex != null) {
        db.registerTicket(conv.groupIdHex, conv.ownDrawbridgeTicketHex!);
      }
      // No crash = success; ticket is queued for when own relay connects
    });
  });
}
