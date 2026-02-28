import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/conversation.dart';
import 'package:moat_flutter/services/drawbridge_service.dart';

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
      expect(service.partnerConnectionCount, 0);
    });

    test('init stores credentials', () {
      service.init(
        did: 'did:plc:test',
        keyBundle: Uint8List.fromList(List.filled(32, 0x42)),
      );
      // After init, still not connected (no WebSocket yet)
      expect(service.isOwnConnected, false);
    });

    test('registerTicket stores ticket for group', () {
      // Should not throw even when not connected (queues for later)
      service.registerTicket('aabbccdd', 'ticket123');
      // No crash = success; ticket is stored internally
    });

    test('notifyEventPosted does nothing when not authenticated', () {
      // Should not throw
      service.notifyEventPosted(
        Uint8List.fromList([0x01, 0x02]),
        'rkey123',
      );
    });

    test('reset clears all state', () {
      service.init(
        did: 'did:plc:test',
        keyBundle: Uint8List.fromList(List.filled(32, 0x42)),
      );
      service.registerTicket('group1', 'ticket1');
      service.reset();
      expect(service.isOwnConnected, false);
      expect(service.partnerConnectionCount, 0);
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

  group('StoredDrawbridgeHint', () {
    test('toJson / fromJson roundtrip', () {
      final hint = StoredDrawbridgeHint(
        url: 'wss://relay.example.com/ws',
        deviceIdHex: 'aabb',
        ticketHex: 'ccdd' * 16, // 64-char hex
        partnerDid: 'did:plc:partner',
      );
      final json = hint.toJson();
      final restored = StoredDrawbridgeHint.fromJson(json);

      expect(restored.url, hint.url);
      expect(restored.deviceIdHex, hint.deviceIdHex);
      expect(restored.ticketHex, hint.ticketHex);
      expect(restored.partnerDid, hint.partnerDid);
    });
  });

  group('Conversation Drawbridge fields', () {
    Conversation makeConversation({
      List<StoredDrawbridgeHint>? hints,
      String? ownTicket,
    }) {
      return Conversation(
        groupId: Uint8List.fromList([1, 2, 3, 4]),
        displayName: 'Test',
        participants: ['did:plc:bob'],
        keyBundleRef: 'ref',
        createdAt: DateTime.utc(2025, 1, 1),
        partnerDrawbridgeHints: hints,
        ownDrawbridgeTicketHex: ownTicket,
      );
    }

    test('empty hints roundtrips', () {
      final conv = makeConversation();
      final restored = Conversation.fromJson(conv.toJson());
      expect(restored.partnerDrawbridgeHints, isEmpty);
      expect(restored.ownDrawbridgeTicketHex, isNull);
    });

    test('hints roundtrip through JSON', () {
      final conv = makeConversation(
        hints: [
          StoredDrawbridgeHint(
            url: 'wss://a.com/ws',
            deviceIdHex: 'aa',
            ticketHex: 'bb' * 32,
            partnerDid: 'did:plc:alice',
          ),
          StoredDrawbridgeHint(
            url: 'wss://b.com/ws',
            deviceIdHex: 'cc',
            ticketHex: 'dd' * 32,
            partnerDid: 'did:plc:alice',
          ),
        ],
        ownTicket: 'ee' * 32,
      );
      final restored = Conversation.fromJson(conv.toJson());
      expect(restored.partnerDrawbridgeHints.length, 2);
      expect(restored.partnerDrawbridgeHints[0].url, 'wss://a.com/ws');
      expect(restored.partnerDrawbridgeHints[1].deviceIdHex, 'cc');
      expect(restored.ownDrawbridgeTicketHex, 'ee' * 32);
    });

    test('upsertPartnerHint adds new hint', () {
      final conv = makeConversation();
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://relay.com/ws',
        deviceIdHex: 'aa',
        ticketHex: 'bb' * 32,
        partnerDid: 'did:plc:bob',
      ));
      expect(conv.partnerDrawbridgeHints.length, 1);
    });

    test('upsertPartnerHint replaces hint for same device', () {
      final conv = makeConversation();
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://old-relay.com/ws',
        deviceIdHex: 'aa',
        ticketHex: 'old_ticket',
        partnerDid: 'did:plc:bob',
      ));
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://new-relay.com/ws',
        deviceIdHex: 'aa',
        ticketHex: 'new_ticket',
        partnerDid: 'did:plc:bob',
      ));
      expect(conv.partnerDrawbridgeHints.length, 1);
      expect(conv.partnerDrawbridgeHints[0].url, 'wss://new-relay.com/ws');
      expect(conv.partnerDrawbridgeHints[0].ticketHex, 'new_ticket');
    });

    test('upsertPartnerHint keeps hints for different devices', () {
      final conv = makeConversation();
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://relay.com/ws',
        deviceIdHex: 'device_a',
        ticketHex: 'ticket_a',
        partnerDid: 'did:plc:bob',
      ));
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://relay.com/ws',
        deviceIdHex: 'device_b',
        ticketHex: 'ticket_b',
        partnerDid: 'did:plc:bob',
      ));
      expect(conv.partnerDrawbridgeHints.length, 2);
    });

    test('upsertPartnerHint distinguishes same device across different DIDs', () {
      final conv = makeConversation();
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://relay.com/ws',
        deviceIdHex: 'same_device',
        ticketHex: 'ticket_1',
        partnerDid: 'did:plc:alice',
      ));
      conv.upsertPartnerHint(StoredDrawbridgeHint(
        url: 'wss://relay.com/ws',
        deviceIdHex: 'same_device',
        ticketHex: 'ticket_2',
        partnerDid: 'did:plc:bob',
      ));
      // Different DIDs, same device ID → both should be kept
      expect(conv.partnerDrawbridgeHints.length, 2);
    });

    test('missing partnerDrawbridgeHints in JSON defaults to empty', () {
      final json = makeConversation().toJson();
      json.remove('partnerDrawbridgeHints');
      final restored = Conversation.fromJson(json);
      expect(restored.partnerDrawbridgeHints, isEmpty);
    });

    test('missing ownDrawbridgeTicketHex in JSON defaults to null', () {
      final json = makeConversation(ownTicket: 'abc').toJson();
      json.remove('ownDrawbridgeTicketHex');
      final restored = Conversation.fromJson(json);
      expect(restored.ownDrawbridgeTicketHex, isNull);
    });
  });
}
