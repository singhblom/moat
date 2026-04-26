import 'dart:async';
import 'dart:typed_data';

import '../models/conversation.dart';
import '../models/message.dart';
import '../rust/api/simple.dart' as ffi;
import 'auth_service.dart';
import 'conversation_storage.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'message_storage.dart';

/// Owns a [ffi.SyncSessionHandle] and bridges it to the Drawbridge `/pair` WS.
///
/// Dart-side analogue of `App::start_sync_session` / `process_sync_outputs` /
/// `process_sync_frame` in `crates/moat-cli/src/app.rs`. Subscribes to
/// `DrawbridgeService` pair callbacks, drives the moat-core sync state
/// machine, encrypts/decrypts ring-MLS frames via the `encryptSyncApp` /
/// `decryptSyncFrame` FFI helpers, and appends synced batches into
/// [MessageStorage].
class SyncService {
  final AuthService _auth;
  final DrawbridgeService _drawbridge;
  final DeviceRingService _ring;
  final ConversationStorage _convStorage;
  final MessageStorage _messageStorage;

  ffi.SyncSessionHandle? _session;
  bool _active = false;

  /// True iff a sync session is currently in progress.
  bool get isActive => _active;

  SyncService({
    required AuthService auth,
    required DrawbridgeService drawbridge,
    required DeviceRingService ring,
    required ConversationStorage conversationStorage,
    required MessageStorage messageStorage,
  })  : _auth = auth,
        _drawbridge = drawbridge,
        _ring = ring,
        _convStorage = conversationStorage,
        _messageStorage = messageStorage {
    _drawbridge.onPairConnected = _handlePairConnected;
    _drawbridge.onPairFrame = _handlePairFrame;
    _drawbridge.onPairClosed = _handlePairClosed;
  }

  Future<void> dispose() async {
    _drawbridge.onPairConnected = null;
    _drawbridge.onPairFrame = null;
    _drawbridge.onPairClosed = null;
    await _reset();
  }

  // ── Pair WS event handlers ────────────────────────────────────────────────

  void _handlePairConnected() {
    // Run the async start in the background; errors are logged inside.
    unawaited(_startSession());
  }

  void _handlePairFrame(Uint8List ciphertext) {
    unawaited(_processFrame(ciphertext));
  }

  void _handlePairClosed(String reason) {
    moatLog('SyncService: pair closed: $reason');
    unawaited(_reset());
  }

  // ── Session lifecycle ─────────────────────────────────────────────────────

  Future<void> _startSession() async {
    if (_active) {
      moatLog('SyncService: pair_connected received but session already active');
      return;
    }

    final session = _auth.moatSession;
    final did = _auth.did;
    if (session == null || did == null) {
      moatLog('SyncService: cannot start — auth not ready');
      return;
    }

    final ringId = await _ring.ringGroupId();
    if (ringId == null) {
      moatLog('SyncService: cannot start — no ring group');
      return;
    }
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    if (keyBundle == null) {
      moatLog('SyncService: cannot start — missing key bundle');
      return;
    }
    final ringEpoch = (await session.getGroupEpoch(groupId: ringId)) ?? BigInt.zero;

    final conversations = await _convStorage.loadAll();
    final syncSession = ffi.SyncSessionHandle.newSession();

    final convStates = <ffi.ConvStateDto>[];
    for (final conv in conversations) {
      final ourMessages =
          await _loadSyncMessagesFor(conv.groupIdHex, conv.groupId);
      await syncSession.addConvPlan(
        groupId: conv.groupId,
        convId: conv.groupIdHex,
        ourMessages: ourMessages,
        expectingBatch: ourMessages.isEmpty,
      );
      final state = await _convStateFor(session, conv);
      if (state != null) convStates.add(state);
    }

    _session = syncSession;
    _active = true;

    final outputs =
        await syncSession.onPaired(ourConvs: convStates, ringEpoch: ringEpoch);
    await _processOutputs(outputs, ringId, keyBundle, did);
  }

  Future<void> _processFrame(Uint8List ciphertext) async {
    final syncSession = _session;
    if (syncSession == null) {
      moatLog('SyncService: pair frame received but no active session');
      return;
    }
    final session = _auth.moatSession;
    final did = _auth.did;
    final ringId = await _ring.ringGroupId();
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    if (session == null || did == null || ringId == null || keyBundle == null) {
      moatLog('SyncService: pair frame dropped — preconditions missing');
      return;
    }

    final Uint8List payload;
    try {
      payload = await session.decryptSyncFrame(
        ringGroupId: ringId,
        ciphertext: ciphertext,
      );
    } catch (e) {
      moatLog('SyncService: decryptSyncFrame failed: $e');
      return;
    }

    try {
      final outputs =
          await syncSession.onMessage(msgBytes: payload, ourDid: did);
      await _processOutputs(outputs, ringId, keyBundle, did);
    } catch (e) {
      moatLog('SyncService: onMessage failed: $e');
    }
  }

  Future<void> _processOutputs(
    List<ffi.SyncOutputDto> outputs,
    Uint8List ringId,
    Uint8List keyBundle,
    String did,
  ) async {
    final session = _auth.moatSession;
    if (session == null) return;

    for (final output in outputs) {
      await output.when(
        send: (bytes) async {
          try {
            final ciphertext = await session.encryptSyncApp(
              ringGroupId: ringId,
              keyBundle: keyBundle,
              payload: bytes,
            );
            _drawbridge.sendPairBinary(ciphertext);
          } catch (e) {
            moatLog('SyncService: encryptSyncApp failed: $e');
          }
        },
        store: (convId, messages) async {
          final groupId = _decodeHex(convId);
          final mapped = messages
              .map((m) => _messageFromSyncDto(m, groupId, did))
              .toList(growable: false);
          if (mapped.isNotEmpty) {
            await _messageStorage.appendMessages(convId, mapped);
          }
          moatLog(
              'SyncService: stored ${mapped.length} message(s) for $convId');
        },
        complete: () async {
          moatLog('SyncService: session complete — closing pair WS');
          await _reset();
          await _drawbridge.clearPair();
        },
      );
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  Future<List<ffi.SyncMessageDto>> _loadSyncMessagesFor(
    String convId,
    Uint8List groupId,
  ) async {
    final messages = await _messageStorage.loadMessages(convId);
    final out = <ffi.SyncMessageDto>[];
    for (final m in messages) {
      // Skip optimistic/local-only messages: they have no rkey assigned yet.
      if (m.localId != null && m.rkey == 'pending') continue;
      out.add(ffi.SyncMessageDto(
        rkey: m.rkey,
        messageId: m.messageId,
        senderDid: m.senderDid,
        senderDeviceName: m.senderDeviceId ?? '',
        timestampMs: m.timestamp.millisecondsSinceEpoch,
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
  ) async {
    try {
      final tip = await session.digestTip(groupId: conv.groupId);
      final anchors = await session.digestAnchors(groupId: conv.groupId);
      final range = await session.digestRange(groupId: conv.groupId);
      return ffi.ConvStateDto(
        groupId: conv.groupId,
        oldestRkey: range?.$1,
        newestRkey: range?.$2,
        tipDigest: tip ?? Uint8List(32),
        anchors: anchors,
      );
    } catch (e) {
      moatLog('SyncService: convState failed for ${conv.groupIdHex}: $e');
      return null;
    }
  }

  Message _messageFromSyncDto(
    ffi.SyncMessageDto m,
    Uint8List groupId,
    String myDid,
  ) {
    final isOwn = m.senderDid == myDid;
    final id = '${_hex(groupId)}_${m.rkey}';
    return Message(
      id: id,
      groupId: groupId,
      senderDid: m.senderDid,
      senderDeviceId: m.senderDeviceName.isEmpty ? null : m.senderDeviceName,
      content: m.content,
      timestamp: DateTime.fromMillisecondsSinceEpoch(m.timestampMs),
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

  Future<void> _reset() async {
    _active = false;
    _session = null;
    _ring.clearPendingPair();
  }
}
