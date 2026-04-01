import 'dart:typed_data';
import '../models/conversation.dart';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'drawbridge_service.dart';
import 'debug_log.dart';

/// Start a new conversation with a recipient.
///
/// Encapsulates the full flow: resolve handle, fetch stealth addresses + key
/// packages, create MLS group, publish stealth-encrypted welcome, register
/// tags, fetch partner Drawbridge config, and save the conversation.
///
/// Used by both the Flutter app and the headless server so that integration
/// tests exercise the exact same code path as production.
Future<Conversation> startConversation({
  required String recipientHandle,
  required AuthService authService,
  required ConversationsService convsService,
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

  // 8. Register tags on own Drawbridge.
  final session = authService.moatSession;
  if (session != null) {
    final tags = session.populateCandidateTags(groupId: result.groupId);
    DrawbridgeService.instance
        .addTags(tags.map((t) => Uint8List.fromList(t)).toList());
  }

  // 9. Fetch recipient's Drawbridge config and cache it.
  final recipientRelayUrls = await client.fetchDrawbridgeConfig(recipientDid);
  DrawbridgeService.instance
      .cacheDrawbridgeConfig(recipientDid, recipientRelayUrls);

  // 10. Save conversation.
  final conversation = Conversation(
    groupId: result.groupId,
    participants: [recipientDid],
    epoch: result.epoch,
    keyBundleRef: 'key_bundle_$groupIdHex',
    createdAt: DateTime.now(),
  );

  await convsService.saveConversation(conversation);

  moatLog('startConversation: $groupIdHex created with $recipientHandle');

  return conversation;
}

String _bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
