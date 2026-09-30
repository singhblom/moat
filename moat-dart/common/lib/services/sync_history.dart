import 'dart:async';
import 'dart:typed_data';

import '../models/conversation.dart';
import '../models/message.dart';
import '../rust/api/simple.dart' as ffi;
import '../utils/platform_int64.dart';
import 'conversations_service.dart';
import 'message_storage.dart';

/// Every conversation's settled messages, for a transfer's `Hello`.
///
/// Dart mirror of `App::load_sync_history` in `crates/moat-cli/src/app.rs`.
Future<List<ffi.ConvHistoryDto>> loadSyncHistory(
  ConversationsService convService,
  MessageStorage messageStorage,
) async {
  final out = <ffi.ConvHistoryDto>[];
  for (final conv in convService.conversations) {
    out.add(ffi.ConvHistoryDto(
      groupId: conv.groupId,
      messages: await _loadSyncMessagesFor(messageStorage, conv.groupIdHex),
    ));
  }
  return out;
}

/// Surface a conversation whose history arrived by sync before we were a
/// member of it.
///
/// `handle_hello` plans for every conversation the peer has and we do
/// not, so a donor can serve history for a group whose fan-out `Add` has
/// not reached us yet. Without this the messages land in storage and are
/// visible nowhere, because the conversation list is what the UI reads.
///
/// Registered read-only: participants are inferred from who actually sent
/// the messages, since there is no MLS group to ask, and `isMember` stays
/// false until the `Add` arrives. Normally transient — the peer that had
/// the history is in the conversation and will add us — but not
/// guaranteed to be brief, since an `Add` can only come from a member.
///
/// Dart mirror of `App::register_synced_conversation` in
/// `crates/moat-cli/src/app.rs`.
Future<void> registerSyncedConversation(
  ConversationsService convService,
  String convId,
  List<ffi.SyncMessageDto> messages,
  String myDid,
) async {
  if (convService.findByGroupId(_decodeHex(convId)) != null) return;

  final participants = <String>[];
  for (final m in messages) {
    if (m.senderDid == myDid) continue;
    if (!participants.contains(m.senderDid)) participants.add(m.senderDid);
  }

  await convService.saveConversation(Conversation(
    groupId: _decodeHex(convId),
    participants: participants,
    keyBundleRef: convId,
    createdAt: DateTime.now(),
    unreadCount: messages.length,
    isMember: false,
  ));
}

/// Convert and persist a `SyncOutput.store` batch. Returns the number of
/// messages stored.
Future<int> storeSyncOutputMessages(
  MessageStorage messageStorage,
  String convId,
  List<ffi.SyncMessageDto> messages,
  String myDid,
) async {
  final groupId = _decodeHex(convId);
  final mapped = messages
      .map((m) => _messageFromSyncDto(m, groupId, myDid))
      .toList(growable: false);
  if (mapped.isNotEmpty) {
    await messageStorage.appendMessages(convId, mapped);
  }
  return mapped.length;
}

Message _messageFromSyncDto(ffi.SyncMessageDto m, Uint8List groupId, String myDid) {
  final isOwn = m.senderDid == myDid;
  final id = '${_hex(groupId)}_${m.rkey}';
  return Message(
    id: id,
    groupId: groupId,
    senderDid: m.senderDid,
    senderDeviceId: m.senderDeviceName.isEmpty ? null : m.senderDeviceName,
    content: m.content,
    timestamp: DateTime.fromMillisecondsSinceEpoch(platformInt64ToInt(m.timestampMs)),
    isOwn: isOwn,
    messageId: m.messageId,
    attachment: _attachmentFromSyncDto(m),
    // Reactions arrive as their own PDS events, which a device receiving
    // this message through sync cannot decrypt — they predate its
    // membership. Sync is their only route, so they are carried here
    // rather than left to be rebuilt.
    reactions: m.reactions
        .map((r) => Reaction(emoji: r.emoji, senderDid: r.senderDid))
        .toList(growable: false),
  );
}

/// Rebuild an [ImageAttachment] from a synced message's blob reference.
///
/// All five required fields must be present — a partial reference cannot
/// be fetched or integrity-checked, so it is dropped rather than turned
/// into an attachment that fails on open.
///
/// `thumbhash` travels with the rest: it is stored beside the blob
/// metadata, and a device receiving this message cannot recover it from
/// the PDS, since the event carrying it predates that device's
/// membership.
Attachment? _attachmentFromSyncDto(ffi.SyncMessageDto m) {
  final uri = m.blobUri;
  final key = m.blobKey;
  final ciphertextHash = m.blobCiphertextHash;
  final ciphertextSize = m.blobCiphertextSize;
  final contentHash = m.blobContentHash;
  if (uri == null ||
      key == null ||
      ciphertextHash == null ||
      ciphertextSize == null ||
      contentHash == null) {
    return null;
  }
  return ImageAttachment(
    uri: uri,
    key: key,
    ciphertextHash: ciphertextHash,
    ciphertextSize: ciphertextSize.toInt(),
    contentHash: contentHash,
    thumbhash: m.blobThumbhash,
    mime: m.blobMime,
    width: m.blobWidth,
    height: m.blobHeight,
  );
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List _decodeHex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Future<List<ffi.SyncMessageDto>> _loadSyncMessagesFor(
  MessageStorage messageStorage,
  String convId,
) async {
  final messages = await messageStorage.loadMessages(convId);
  final out = <ffi.SyncMessageDto>[];
  for (final m in messages) {
    // Skip optimistic/local-only messages: they have no rkey assigned yet.
    if (m.localId != null && m.rkey == 'pending') continue;
    final image = m.attachment is ImageAttachment
        ? m.attachment as ImageAttachment
        : null;
    out.add(ffi.SyncMessageDto(
      rkey: m.rkey,
      messageId: m.messageId,
      senderDid: m.senderDid,
      senderDeviceName: m.senderDeviceId ?? '',
      timestampMs: toPlatformInt64(m.timestamp.millisecondsSinceEpoch),
      content: m.content,
      // The attachment *reference*, not its bytes: the blob stays on the
      // PDS and is fetched when the user opens it. Without these fields a
      // synced image has nothing to open, and the original PDS record is
      // no help — a device receiving history predating its membership
      // cannot decrypt it.
      blobUri: image?.uri,
      blobKey: image?.key,
      blobCiphertextHash: image?.ciphertextHash,
      blobCiphertextSize:
          image == null ? null : BigInt.from(image.ciphertextSize),
      blobContentHash: image?.contentHash,
      blobMime: image?.mime,
      blobWidth: image?.width,
      blobHeight: image?.height,
      blobThumbhash: image?.thumbhash,
      reactions: m.reactions
          .map((r) => ffi.SyncReactionDto(
                emoji: r.emoji,
                senderDid: r.senderDid,
              ))
          .toList(growable: false),
    ));
  }
  return out;
}
