import 'dart:async';
import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
import 'auth_service.dart';
import 'conversation_storage.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'message_storage.dart';
import 'paired_sync_builder.dart';

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

  /// Lifecycle hooks for whoever *opened* this channel — today
  /// `SyncRequestService`, which needs them to keep its own projection
  /// honest. The transfer itself stays entirely this service's business.
  void Function()? onSessionStarted;
  void Function()? onSessionComplete;
  void Function(String reason)? onSessionAborted;
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
    reclaimPairCallbacks();
  }

  /// (Re-)claim `DrawbridgeService.onPairConnected`/`onPairFrame`/
  /// `onPairClosed`. Normally only needed once, from the constructor —
  /// exposed as a public method so `PairingService` can hand these
  /// callback slots back after a live pairing exchange (which needs them
  /// too, for its own attached-phase Enroll/Admit/Done + post-Done sync)
  /// completes or aborts.
  void reclaimPairCallbacks() {
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
    onSessionAborted?.call(reason);
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
    onSessionStarted?.call();

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

    final setup = await buildPairedSyncSession(
      session: session,
      convStorage: _convStorage,
      messageStorage: _messageStorage,
      ringEpoch: ringEpoch,
    );
    _session = setup.session;

    moatLog('SyncService: onPaired returned ${setup.outputs.length} outputs');
    await _processOutputs(setup.outputs, ringId, keyBundle, did);

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
      final outputs = await syncSession.onMessage(
        session: session,
        msgBytes: payload,
        ourDid: did,
      );
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
          final count =
              await storeSyncOutputMessages(_messageStorage, convId, messages, did);
          moatLog('SyncService: stored $count message(s) for $convId');
        },
      );
    }

    // Teardown happens after every output has been applied, never as one of
    // them: closing the channel mid-list would strand whatever followed.
    if (await _session?.isDone() ?? false) {
      moatLog('SyncService: session complete — closing pair WS');
      onSessionComplete?.call();
      await _reset();
      await _drawbridge.clearPair();
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  //
  // Conv-state gathering (loading local messages, building ConvStateDtos)
  // and Store-output handling moved to `paired_sync_builder.dart`, shared
  // with `PairingService`'s post-Done sync phase.

  /// Single teardown funnel for a sync session, however it ended. Every path
  /// that drops the session goes through here so the ring driver always learns
  /// the offer is no longer in flight.
  Future<void> _reset() async {
    _active = false;
    _session = null;
    _pendingFrames = null;
    _ring.clearPendingPair();
  }
}
