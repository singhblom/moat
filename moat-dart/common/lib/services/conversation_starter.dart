import 'dart:typed_data';
import '../models/conversation.dart';
import '../rust/api/simple.dart';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'drawbridge_service.dart';
import 'debug_log.dart';

/// Start a new conversation with a recipient.
///
/// Encapsulates the full flow: resolve handle, fetch stealth addresses + key
/// packages, create MLS group, publish stealth-encrypted welcome, register
/// tags, optionally set up Drawbridge push, and save the conversation.
///
/// Used by both the Flutter app and the headless server so that integration
/// tests exercise the exact same code path as production.
Future<Conversation> startConversation({
  required String recipientHandle,
  required AuthService authService,
  required ConversationsService convsService,
  String? drawbridgeUrl,
}) async {
  final client = authService.atprotoClient;

  // 1. Resolve handle → DID.
  final recipientDid = await client.resolveDid(recipientHandle);

  // 2. Self-check.
  if (recipientDid == authService.did) {
    throw Exception('Cannot create a conversation with yourself');
  }

  // 3. Fetch stealth addresses.
  final stealthRecords = await client.fetchStealthAddresses(recipientDid);
  if (stealthRecords.isEmpty) {
    throw Exception(
        'Recipient has no stealth address published. '
        'They may need to update their Moat client.');
  }
  final stealthPubkeys = stealthRecords.map((r) => r.scanPubkey).toList();

  // 4. Fetch key packages.
  final keyPackages = await client.fetchKeyPackages(recipientDid);
  if (keyPackages.isEmpty) {
    throw Exception('Recipient has no valid key packages');
  }
  final recipientKeyPackage = keyPackages.first.keyPackage;

  // 5. Create MLS group + welcome.
  final result = await authService.createConversation(
    recipientDid: recipientDid,
    recipientStealthPubkeys: stealthPubkeys,
    recipientKeyPackage: recipientKeyPackage,
  );

  // 6. Publish stealth-encrypted welcome.
  await client.publishEvent(result.randomTag, result.stealthCiphertext);

  // 7. Populate candidate tags.
  await authService.populateConversationTags(result.groupId);

  final groupIdHex = _bytesToHex(result.groupId);

  // 8. Drawbridge setup (if URL provided).
  String? ownTicketHex;
  if (drawbridgeUrl != null) {
    final ticket = generateDrawbridgeTicket();
    ownTicketHex =
        ticket.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    // Register ticket on our own relay.
    DrawbridgeService.instance.registerTicket(groupIdHex, ownTicketHex);

    // Create and publish DrawbridgeHint event.
    final session = authService.moatSession;
    final keyBundle = await authService.getKeyBundle();
    if (session != null && keyBundle != null) {
      final hintEvent = createDrawbridgeHint(
        handle: session,
        groupId: result.groupId,
        url: drawbridgeUrl,
        ticket: ticket,
      );

      final encResult = await session.encryptEvent(
        groupId: result.groupId,
        keyBundle: keyBundle,
        event: hintEvent,
      );
      final hintUri =
          await client.publishEvent(encResult.tag, encResult.ciphertext);
      await authService.saveMlsState();

      // Notify relay about the hint event.
      final hintRkey = hintUri.split('/').last;
      DrawbridgeService.instance
          .notifyEventPosted(encResult.tag, hintRkey);
    }
  }

  // 9. Resolve display name.
  String displayName;
  try {
    displayName = await client.resolveHandle(recipientDid);
  } catch (_) {
    displayName = recipientDid;
  }

  // 10. Save conversation.
  final conversation = Conversation(
    groupId: result.groupId,
    displayName: displayName,
    participants: [recipientDid],
    epoch: result.epoch,
    keyBundleRef: 'key_bundle_$groupIdHex',
    createdAt: DateTime.now(),
    ownDrawbridgeTicketHex: ownTicketHex,
  );

  await convsService.saveConversation(conversation);

  moatLog('startConversation: $groupIdHex created with $recipientHandle');

  return conversation;
}

String _bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
