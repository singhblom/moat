import 'dart:async';
import 'dart:typed_data';

import '../models/conversation.dart';
import '../models/message.dart';
import '../rust/api/simple.dart' as ffi;
import '../utils/platform_int64.dart';
import 'conversation_storage.dart';
import 'debug_log.dart';
import 'message_storage.dart';

/// Result of [buildPairedSyncSession]: a freshly-built `SyncSession`
/// (already past `onPaired`) plus the outputs that call produced.
class PairedSyncSetup {
  final ffi.SyncSessionHandle session;
  final List<ffi.SyncOutputDto> outputs;
  PairedSyncSetup({required this.session, required this.outputs});
}

/// Build a fresh `SyncSessionHandle` and call `onPaired` for it, from
/// local keystore/digest state. Shared by [SyncService] (established-
/// devices reconnect-sync, ring-MLS wire encryption) and [PairingService]
/// (pairing-driven onboarding sync, pairing-AEAD wire encryption) — only
/// the wire encryption differs between the two callers, which is handled
/// by whatever encrypts/decrypts the `SyncOutputDto.send` bytes and feeds
/// `onMessage`, not by this shared setup step.
///
/// Dart mirror of `App::build_paired_sync_session` in
/// `crates/moat-cli/src/app.rs`.
Future<PairedSyncSetup> buildPairedSyncSession({
  required ffi.MoatSessionHandle session,
  required ConversationStorage convStorage,
  required MessageStorage messageStorage,
  required BigInt ringEpoch,
}) async {
  final conversations = await convStorage.loadAll();
  final syncSession = ffi.SyncSessionHandle.newSession();

  final convStates = <ffi.ConvStateDto>[];
  for (final conv in conversations) {
    final ourMessages = await _loadSyncMessagesFor(messageStorage, conv.groupIdHex);
    await syncSession.addConvPlan(
      groupId: conv.groupId,
      convId: conv.groupIdHex,
      ourMessages: ourMessages,
      expectingBatch: ourMessages.isEmpty,
    );
    final state = await _convStateFor(session, conv, ourMessages);
    if (state != null) convStates.add(state);
  }

  final outputs = await syncSession.onPaired(ourConvs: convStates, ringEpoch: ringEpoch);
  return PairedSyncSetup(session: syncSession, outputs: outputs);
}

/// Convert and persist a `SyncOutput.store` batch. Shared by [SyncService]
/// and [PairingService] — the `store` arm's logic doesn't depend on which
/// wire encryption produced the batch. Returns the number of messages
/// stored.
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
    epoch: 0,
    messageId: m.messageId,
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
    out.add(ffi.SyncMessageDto(
      rkey: m.rkey,
      messageId: m.messageId,
      senderDid: m.senderDid,
      senderDeviceName: m.senderDeviceId ?? '',
      timestampMs: toPlatformInt64(m.timestamp.millisecondsSinceEpoch),
      content: m.content,
      isOwn: m.isOwn,
      // Attachments are not yet round-tripped through sync; keep null for
      // text-only messages and rely on the original PDS publish for media.
    ));
  }
  return out;
}

Future<ffi.ConvStateDto?> _convStateFor(
  ffi.MoatSessionHandle session,
  Conversation conv,
  List<ffi.SyncMessageDto> ourMessages,
) async {
  try {
    final tip = await session.digestTip(groupId: conv.groupId);
    final anchors = await session.digestAnchors(groupId: conv.groupId);
    // digestRange relies on append_to_digest which is not called in the Dart
    // path. Derive oldest/newest directly from the messages we loaded.
    String? oldestRkey;
    String? newestRkey;
    if (ourMessages.isNotEmpty) {
      final rkeys = ourMessages.map((m) => m.rkey).toList()..sort();
      oldestRkey = rkeys.first;
      newestRkey = rkeys.last;
    }
    // The rkeys we hold, so the peer sends exactly the complement rather
    // than its whole history. Omitted past the cap, where the peer falls
    // back to serving everything (`ConvStateDto.rkeys`).
    final rkeys = ourMessages.map((m) => m.rkey).toList(growable: false);
    return ffi.ConvStateDto(
      groupId: conv.groupId,
      oldestRkey: oldestRkey,
      newestRkey: newestRkey,
      tipDigest: tip ?? Uint8List(32),
      anchors: anchors,
      rkeys: rkeys.length <= ffi.syncInventoryCap() ? rkeys : null,
    );
  } catch (e) {
    moatLog('buildPairedSyncSession: convState failed for ${conv.groupIdHex}: $e');
    return null;
  }
}
