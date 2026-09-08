import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';
import 'package:moat_dart_common/rust/api/simple.dart' as ffi;
import 'package:moat_dart_common/utils/platform_int64.dart';

/// A conversation whose history arrives by sync before the fan-out `Add`
/// that puts this device in the MLS group.
///
/// Before this, the sync session planned for such a conversation and
/// stored its messages, but nothing registered the conversation itself —
/// so the messages sat in storage visible nowhere, since the list the UI
/// reads is built from registered conversations.
void main() {
  late Directory tempDir;
  late ConversationStorage storage;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('synced_conv_test_');
    storage = ConversationStorage(backend: IoDocumentBackend(tempDir));
  });

  tearDown(() {
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
  });

  ffi.SyncMessageDto message(String rkey, String senderDid) =>
      ffi.SyncMessageDto(
        rkey: rkey,
        senderDid: senderDid,
        senderDeviceName: 'laptop',
        timestampMs: toPlatformInt64(0),
        content: 'content of $rkey',
        isOwn: false,
        reactions: const [],
      );

  const convId = 'aabbccdd00112233445566778899aabb';
  const myDid = 'did:plc:alice';

  group('registerSyncedConversation', () {
    test('registers an unknown conversation as read-only', () async {
      await registerSyncedConversation(
        storage,
        convId,
        [message('r1', 'did:plc:bob'), message('r2', 'did:plc:bob')],
        myDid,
      );

      final all = await storage.loadAll();
      expect(all, hasLength(1));
      expect(all.single.groupIdHex, convId);
      expect(
        all.single.isMember,
        isFalse,
        reason: 'there is no local MLS group to send into yet',
      );
      expect(all.single.unreadCount, 2);
    });

    test('infers participants from who sent the messages, excluding us',
        () async {
      await registerSyncedConversation(
        storage,
        convId,
        [
          message('r1', 'did:plc:bob'),
          message('r2', myDid),
          message('r3', 'did:plc:carol'),
          message('r4', 'did:plc:bob'),
        ],
        myDid,
      );

      final all = await storage.loadAll();
      expect(
        all.single.participants,
        ['did:plc:bob', 'did:plc:carol'],
        reason: 'no MLS group to ask, so senders are the only evidence — '
            'each once, and never ourselves',
      );
    });

    test('leaves an already-known conversation alone', () async {
      await storage.save(Conversation(
        groupId: Uint8List.fromList(List.filled(16, 7)),
        participants: const ['did:plc:bob'],
        keyBundleRef: 'existing',
        createdAt: DateTime.now(),
      ));
      final existingHex = (await storage.loadAll()).single.groupIdHex;

      await registerSyncedConversation(
        storage,
        existingHex,
        [message('r1', 'did:plc:carol')],
        myDid,
      );

      final all = await storage.loadAll();
      expect(all, hasLength(1));
      expect(
        all.single.isMember,
        isTrue,
        reason: 'a conversation we are already in must not be downgraded '
            'to read-only by a later sync',
      );
      expect(all.single.participants, ['did:plc:bob']);
    });
  });

  group('Conversation.isMember', () {
    test('survives a JSON roundtrip', () {
      final conv = Conversation(
        groupId: Uint8List.fromList([1, 2, 3, 4]),
        participants: const ['did:plc:bob'],
        keyBundleRef: 'ref',
        createdAt: DateTime.now(),
        isMember: false,
      );
      final restored = Conversation.fromJson(conv.toJson());
      expect(restored.isMember, isFalse);
    });

    test('defaults to true for records written before the field existed', () {
      final json = {
        'groupId': 'AQIDBA==',
        'participants': <String>[],
        'keyBundleRef': 'ref',
        'createdAt': DateTime.now().toIso8601String(),
      };
      expect(Conversation.fromJson(json).isMember, isTrue);
    });
  });

  /// A field held on one side and not carried by sync is lost for good on
  /// the other: history predating the receiver's membership cannot be
  /// re-read from the PDS, because those events are not decryptable to
  /// it. So the contract is total — everything stored travels.
  ///
  /// `thumbhash` and `reactions` were both dropped here until this test
  /// existed. Mirrors `every_stored_field_survives_the_round_trip` in
  /// `crates/moat-cli/src/sync.rs`.
  group('sync message fidelity', () {
    test('reactions survive the mapping', () async {
      final groupId = Uint8List.fromList(List.filled(16, 3));
      final dto = ffi.SyncMessageDto(
        rkey: 'r1',
        senderDid: 'did:plc:bob',
        senderDeviceName: 'phone',
        timestampMs: toPlatformInt64(0),
        content: 'hi',
        isOwn: false,
        reactions: [
          const ffi.SyncReactionDto(emoji: '👍', senderDid: 'did:plc:bob'),
          const ffi.SyncReactionDto(emoji: '🎉', senderDid: 'did:plc:carol'),
        ],
      );

      await registerSyncedConversation(storage, convId, [dto], myDid);
      final messageStorage = MessageStorage(backend: IoDocumentBackend(tempDir));
      await storeSyncOutputMessages(messageStorage, convId, [dto], myDid);

      final stored = await messageStorage.loadMessages(convId);
      expect(stored.single.reactions.map((r) => r.emoji), ['👍', '🎉']);
      expect(
        stored.single.reactions.map((r) => r.senderDid),
        ['did:plc:bob', 'did:plc:carol'],
        reason: 'reaction events predate the receiver, so sync is the only '
            'route by which they can arrive',
      );
    });

    test('an image attachment keeps its thumbhash', () async {
      final thumb = Uint8List.fromList(List.generate(24, (i) => i));
      final dto = ffi.SyncMessageDto(
        rkey: 'r2',
        senderDid: 'did:plc:bob',
        senderDeviceName: 'phone',
        timestampMs: toPlatformInt64(0),
        content: 'photo',
        isOwn: false,
        blobUri: 'at://did:plc:bob/bafyimage',
        blobKey: Uint8List.fromList(List.filled(32, 1)),
        blobCiphertextHash: Uint8List.fromList(List.filled(32, 2)),
        blobCiphertextSize: BigInt.from(4096),
        blobContentHash: Uint8List.fromList(List.filled(32, 3)),
        blobThumbhash: thumb,
        blobMime: 'image/webp',
        blobWidth: 1024,
        blobHeight: 768,
        reactions: const [],
      );

      final messageStorage = MessageStorage(backend: IoDocumentBackend(tempDir));
      await storeSyncOutputMessages(messageStorage, convId, [dto], myDid);

      final attachment =
          (await messageStorage.loadMessages(convId)).single.attachment;
      expect(attachment, isA<ImageAttachment>());
      expect(
        (attachment as ImageAttachment).thumbhash,
        thumb,
        reason: 'the placeholder is stored beside the blob metadata and '
            'nowhere the receiver can otherwise reach',
      );
    });
  });
}
