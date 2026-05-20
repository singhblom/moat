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
  // Frames that arrive during the async setup window (before onPaired is called)
  // are buffered here and replayed after onPaired completes.
  List<Uint8List>? _pendingFrames;

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
    moatLog('SyncService: _handlePairConnected called');
    // Run the async start in the background; errors are logged inside.
    unawaited(_startSession());
  }

  void _handlePairFrame(Uint8List ciphertext) {
    moatLog('SyncService: pair frame received ${ciphertext.length}B');
    unawaited(_processFrame(ciphertext));
  }

  void _handlePairClosed(String reason) {
    moatLog('SyncService: pair closed: $reason');
    unawaited(_reset());
  }

  // ── Session lifecycle ─────────────────────────────────────────────────────

  Future<void> _startSession() async {
    moatLog('SyncService: _startSession called active=$_active');
    if (_active) {
      moatLog('SyncService: pair_connected received but session already active');
      return;
    }
    _active = true;
    _pendingFrames = [];

    final session = _auth.moatSession;
    final did = _auth.did;
    if (session == null || did == null) {
      moatLog('SyncService: cannot start — auth not ready');
      await _reset();
      return;
    }

    final ringId = await _ring.ringGroupId();
    if (ringId == null) {
      moatLog('SyncService: cannot start — no ring group');
      await _reset();
      return;
    }
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    if (keyBundle == null) {
      moatLog('SyncService: cannot start — missing key bundle');
      await _reset();
      return;
    }
    final ringEpoch = (await session.getGroupEpoch(groupId: ringId)) ?? BigInt.zero;

    final conversations = await _convStorage.loadAll();
    final syncSession = ffi.SyncSessionHandle.newSession();
    _session = syncSession;

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
      final state = await _convStateFor(session, conv, ourMessages);
      if (state != null) convStates.add(state);
    }

    moatLog('SyncService: calling onPaired with ${convStates.length} convs, ringEpoch=$ringEpoch');

    final outputs =
        await syncSession.onPaired(ourConvs: convStates, ringEpoch: ringEpoch);
    moatLog('SyncService: onPaired returned ${outputs.length} outputs');
    await _processOutputs(outputs, ringId, keyBundle, did);

    // Replay any frames that arrived during the async setup window (before
    // onPaired was called).  Now that the state machine has processed onPaired,
    // it is in WaitingHello phase and can correctly handle them.
    final pending = _pendingFrames;
    _pendingFrames = null;
    if (pending != null && pending.isNotEmpty) {
      moatLog('SyncService: replaying ${pending.length} buffered frame(s)');
      for (final frame in pending) {
        await _processFrame(frame);
      }
    }
  }

  Future<void> _processFrame(Uint8List ciphertext) async {
    // If the session object doesn't exist yet, _active guards whether we should
    // buffer. If _active is true but _session is still null, we're in the
    // async setup window; buffer the frame and replay after onPaired.
    if (_active && _pendingFrames != null) {
      moatLog('SyncService: buffering frame (${ciphertext.length}B) until onPaired');
      _pendingFrames!.add(ciphertext);
      return;
    }
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
      moatLog('SyncService: decryptSyncFrame ok payload=${payload.length}B');
    } catch (e) {
      moatLog('SyncService: decryptSyncFrame failed: $e');
      return;
    }

    try {
      final outputs =
          await syncSession.onMessage(msgBytes: payload, ourDid: did);
      moatLog('SyncService: onMessage returned ${outputs.length} outputs');
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
          moatLog('SyncService: sending ${bytes.length}B to peer via pair WS');
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
      return ffi.ConvStateDto(
        groupId: conv.groupId,
        oldestRkey: oldestRkey,
        newestRkey: newestRkey,
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
    _pendingFrames = null;
    _ring.clearPendingPair();
  }
}
