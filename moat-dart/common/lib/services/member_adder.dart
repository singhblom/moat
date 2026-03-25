import 'dart:math';
import 'dart:typed_data';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'drawbridge_service.dart';
import 'debug_log.dart';
import '../rust/api/simple.dart';
import '../utils/welcome_envelope.dart';

/// Add a member to an existing conversation.
///
/// Encapsulates the full flow: resolve handle, check not already in group,
/// fetch stealth addresses + key packages, MLS add_member, publish
/// stealth-encrypted welcome + commit, update conversation metadata.
///
/// Used by both the Flutter app and the headless server so that integration
/// tests exercise the exact same code path as production.
Future<void> addMemberToConversation({
  required String memberHandle,
  required Uint8List groupId,
  required AuthService authService,
  required ConversationsService convsService,
}) async {
  final client = authService.atprotoClient;
  final session = authService.moatSession;
  if (session == null) {
    throw StateError('MLS session not initialized');
  }

  // 1. Resolve handle → DID.
  final newDid = await client.resolveDid(memberHandle);

  // 2. Self-check.
  if (newDid == authService.did) {
    throw Exception('Cannot add yourself to a conversation');
  }

  // 3. Check DID not already in group.
  if (session.isDidInGroup(groupId: groupId, did: newDid)) {
    throw Exception('$memberHandle is already in this group');
  }

  // 4. Fetch stealth addresses for new member.
  final stealthRecords = await client.fetchStealthAddresses(newDid);
  if (stealthRecords.isEmpty) {
    throw Exception(
        'No stealth address found for $memberHandle. '
        'They may need to update their Moat client.');
  }
  final stealthPubkeys = stealthRecords.map((r) => r.scanPubkey).toList();

  // 5. Fetch key packages for new member.
  final keyPackages = await client.fetchKeyPackages(newDid);
  if (keyPackages.isEmpty) {
    throw Exception('No key package found for $memberHandle');
  }
  final newMemberKeyPackage = keyPackages.first.keyPackage;

  // 6. Load our key bundle.
  final keyBundle = await authService.getKeyBundle();
  if (keyBundle == null) {
    throw StateError('No key bundle available');
  }

  // 7. Derive commit tag BEFORE add_member (pre-epoch).
  final commitTag = deriveNextTag(
    handle: session,
    groupId: groupId,
    keyBundle: keyBundle,
  );

  // 8. Add member to MLS group.
  final welcomeResult = await session.addMember(
    groupId: groupId,
    keyBundle: keyBundle,
    newMemberKeyPackage: newMemberKeyPackage,
  );

  // 9. Encode Welcome in envelope (matches Rust CLI's add_member_to_group),
  //    then encrypt for new member's stealth keys. Publish with random tag.
  final envelope = encodeWelcomeEnvelope(welcomeResult.welcome);
  final stealthCiphertext = await encryptForStealth(
    recipientScanPubkeys: stealthPubkeys,
    welcomeBytes: envelope,
  );
  final random = Random.secure();
  final randomTag = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    randomTag[i] = random.nextInt(256);
  }
  await client.publishEvent(randomTag, stealthCiphertext);

  // 10. Publish Commit with pre-epoch tag for existing members.
  await client.publishEvent(commitTag, welcomeResult.commit);

  // 11. Save MLS state.
  await authService.saveMlsState();

  // 12. Update conversation metadata.
  final conversation = convsService.findByGroupId(groupId);
  if (conversation != null) {
    if (!conversation.participants.contains(newDid)) {
      conversation.participants.add(newDid);
    }
    // Re-resolve all participant handles for display name.
    final resolvedHandles = <String>[];
    for (final did in conversation.participants) {
      try {
        resolvedHandles.add(await client.resolveHandle(did));
      } catch (_) {
        resolvedHandles.add(did);
      }
    }
    conversation.displayName = resolvedHandles.join(', ');
    await convsService.saveConversation(conversation);
  }

  // 13. Re-populate candidate tags for new epoch.
  await authService.populateConversationTags(groupId);
  final tags = session.populateCandidateTags(groupId: groupId);
  DrawbridgeService.instance
      .addTags(tags.map((t) => Uint8List.fromList(t)).toList());

  // 14. Fetch new member's Drawbridge config.
  try {
    final relayUrls = await client.fetchDrawbridgeConfig(newDid);
    DrawbridgeService.instance.cacheDrawbridgeConfig(newDid, relayUrls);
  } catch (_) {}

  final groupIdHex = _bytesToHex(groupId);
  moatLog('addMemberToConversation: added $memberHandle to group $groupIdHex');
}

String _bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
