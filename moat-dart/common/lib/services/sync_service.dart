import 'dart:async';
import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
import '../utils/value_listenable.dart';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'message_storage.dart';
import 'paired_sync_builder.dart';
import 'sync_channel.dart';

/// Runs history transfers on the Drawbridge `/pair` WS, one at a time.
///
/// Dart-side analogue of `App::start_sync_transfer` / `process_sync_outputs` /
/// `process_sync_frame` in `crates/moat-cli/src/app.rs`. Drives the
/// moat-core sync state machine over a [SyncChannel] and appends synced
/// batches into [MessageStorage]. A sync between established devices starts
/// here, on `pair_connected`; the transfer after a pairing is handed in by
/// [PairingService] through [runTransfer].
class SyncService {
  final AuthService _auth;
  final DrawbridgeService _drawbridge;
  final DeviceRingService _ring;
  final ConversationsService _convService;
  final MessageStorage _messageStorage;

  _Transfer? _transfer;

  /// Serialises everything that touches the pair channel — see [_enqueue].
  Future<void> _frameQueue = Future.value();

  /// Lifecycle hooks for a sync between established devices — today
  /// `SyncRequestService`, which needs them to keep its own projection
  /// honest. The transfer itself stays entirely this service's business.
  void Function()? onSessionStarted;

  /// Called once the transfer finishes, with what it moved and the peer it
  /// moved from.
  void Function(ffi.SyncTallyDto tally, String? deviceName)? onSessionComplete;
  void Function(String reason)? onSessionAborted;

  /// True iff a transfer is in progress, whichever gesture opened it.
  bool get isActive => _transfer != null;

  final SimpleValueNotifier<ffi.SyncProgressDto?> _progress =
      SimpleValueNotifier(null);

  /// How far the running transfer has got; `null` when none is running.
  ValueListenable<ffi.SyncProgressDto?> get progress => _progress;

  SyncService({
    required AuthService auth,
    required DrawbridgeService drawbridge,
    required DeviceRingService ring,
    required ConversationsService conversationsService,
    required MessageStorage messageStorage,
  })  : _auth = auth,
        _drawbridge = drawbridge,
        _ring = ring,
        _convService = conversationsService,
        _messageStorage = messageStorage {
    reclaimPairCallbacks();
  }

  /// (Re-)claim `DrawbridgeService.onPairConnected`/`onPairFrame`/
  /// `onPairClosed`. Normally only needed once, from the constructor —
  /// exposed as a public method so `PairingService` can hand these
  /// callback slots back after a live pairing exchange completes or aborts.
  void reclaimPairCallbacks() {
    _drawbridge.onPairConnected = _handlePairConnected;
    _drawbridge.onPairFrame = _handlePairFrame;
    _drawbridge.onPairClosed = _handlePairClosed;
  }

  Future<void> dispose() async {
    _drawbridge.onPairConnected = null;
    _drawbridge.onPairFrame = null;
    _drawbridge.onPairClosed = null;
    _clear();
    _ring.clearPendingPair();
  }

  // ── Transfers handed in by PairingService ─────────────────────────────────

  /// Start a transfer over [channel], replacing any still running. Frames
  /// and the close for it arrive through [receiveFrame] / [receiveClose],
  /// since the pair callbacks stay with the caller until it ends.
  void runTransfer(
    SyncChannel channel, {
    required Uint8List ringId,
    required Future<void> Function() onComplete,
    required Future<void> Function(String reason) onAbort,
  }) {
    final previous = _transfer;
    final t = _Transfer(
      channel,
      onComplete: (_, __) => onComplete(),
      onAbort: onAbort,
    );
    _transfer = t;
    _enqueue(() async {
      if (previous != null) await previous.onAbort('superseded');
      await _start(t, ringId);
    });
  }

  void receiveFrame(SyncChannel channel, Uint8List frame) {
    _enqueue(() async {
      final t = _transfer;
      if (t?.channel == channel) await _processFrame(t!, frame);
    });
  }

  void receiveClose(SyncChannel channel, String reason) {
    _enqueue(() async {
      final t = _transfer;
      if (t?.channel == channel) await _abort(t!, reason);
    });
  }

  /// Drop [channel]'s transfer without telling whoever started it.
  void cancelTransfer(SyncChannel channel) {
    if (_transfer?.channel == channel) _clear();
  }

  // ── Pair WS event handlers ────────────────────────────────────────────────

  void _handlePairConnected() {
    moatLog('SyncService: _handlePairConnected called');
    _enqueue(_startRingTransfer);
  }

  void _handlePairFrame(Uint8List frame) {
    moatLog('SyncService: pair frame received ${frame.length}B');
    _enqueue(() async {
      final t = _transfer;
      if (t == null) {
        moatLog('SyncService: pair frame received but no active session');
        return;
      }
      await _processFrame(t, frame);
    });
  }

  /// Queued like frames, so a close never overtakes the frames the peer
  /// sent before it — the last of which is usually its `Fin`.
  void _handlePairClosed(String reason) {
    moatLog('SyncService: pair closed: $reason');
    _enqueue(() async {
      final t = _transfer;
      if (t != null) {
        await _abort(t, reason);
      } else {
        onSessionAborted?.call(reason);
        _ring.clearPendingPair();
      }
    });
  }

  /// Run pair-channel work one item at a time, in arrival order.
  ///
  /// Running them concurrently lets one frame's teardown land between
  /// another's sends, closing the socket with a batch still pending.
  /// Session setup is the first item, so frames arriving during it wait
  /// rather than needing their own buffer.
  ///
  /// `catchError` stops one failed item breaking the chain. The queue is
  /// never reset: reassigning it from inside a queued item would let the
  /// next one start alongside an unfinished one.
  void _enqueue(Future<void> Function() work) {
    _frameQueue = _frameQueue.then((_) => work()).catchError((Object e) {
      moatLog('SyncService: pair channel work failed: $e');
    });
  }

  // ── Transfer lifecycle ────────────────────────────────────────────────────

  Future<void> _startRingTransfer() async {
    if (_transfer != null) {
      moatLog('SyncService: pair_connected received but session already active');
      return;
    }
    onSessionStarted?.call();

    final session = _auth.moatSession;
    final ringId = await _ring.ringGroupId();
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    if (session == null || ringId == null || keyBundle == null) {
      moatLog('SyncService: cannot start — auth, ring or key bundle not ready');
      onSessionAborted?.call('not ready to sync');
      _ring.clearPendingPair();
      await _drawbridge.clearPair();
      return;
    }

    final t = _Transfer(
      RingSyncChannel(session: session, ringId: ringId, keyBundle: keyBundle),
      onComplete: (tally, deviceName) async {
        onSessionComplete?.call(tally, deviceName);
        _ring.clearPendingPair();
        await _drawbridge.clearPair();
      },
      onAbort: (reason) async {
        onSessionAborted?.call(reason);
        _ring.clearPendingPair();
      },
    );
    _transfer = t;
    await _start(t, ringId);
  }

  Future<void> _start(_Transfer t, Uint8List ringId) async {
    final session = _auth.moatSession;
    final did = _auth.did;
    if (session == null || did == null) {
      await _abort(t, 'not logged in');
      return;
    }
    t.did = did;
    final ringEpoch = (await session.getGroupEpoch(groupId: ringId)) ?? BigInt.zero;
    if (!identical(_transfer, t)) return;

    final setup = await buildPairedSyncSession(
      session: session,
      convService: _convService,
      messageStorage: _messageStorage,
      ringEpoch: ringEpoch,
    );
    if (!identical(_transfer, t)) return;
    t.session = setup.session;

    moatLog('SyncService: onPaired returned ${setup.outputs.length} outputs');
    await _processOutputs(t, setup.outputs);
  }

  Future<void> _processFrame(_Transfer t, Uint8List frame) async {
    final session = t.session;
    if (session == null) return;

    final Uint8List? payload;
    try {
      payload = await t.channel.open(frame);
    } catch (e) {
      await _abort(t, 'frame failed to open: $e', closePair: true);
      return;
    }
    if (payload == null || !identical(_transfer, t)) return;

    final List<ffi.SyncOutputDto> outputs;
    try {
      outputs = await session.onMessage(msgBytes: payload);
    } catch (e) {
      // The peer believes it delivered something we did not take, so
      // carrying on would end in a sync that is quietly wrong.
      await _abort(t, 'sync protocol error: $e', closePair: true);
      return;
    }
    moatLog('SyncService: onMessage returned ${outputs.length} outputs');
    await _processOutputs(t, outputs);
  }

  Future<void> _processOutputs(_Transfer t, List<ffi.SyncOutputDto> outputs) async {
    for (final output in outputs) {
      if (!identical(_transfer, t)) return;
      await output.when(
        send: (bytes) async {
          moatLog('SyncService: sending ${bytes.length}B to peer via pair WS');
          try {
            final frame = await t.channel.seal(bytes);
            if (identical(_transfer, t)) _drawbridge.sendPairBinary(frame);
          } catch (e) {
            moatLog('SyncService: sealing a frame failed: $e');
          }
        },
        store: (convId, messages) async {
          await registerSyncedConversation(_convService, convId, messages, t.did);
          final count =
              await storeSyncOutputMessages(_messageStorage, convId, messages, t.did);
          moatLog('SyncService: stored $count message(s) for $convId');
        },
      );
    }
    if (!identical(_transfer, t)) return;

    final session = t.session!;
    _progress.value = session.progress();

    // Teardown happens after every output has been applied, never as one of
    // them: closing the channel mid-list would strand whatever followed.
    if (session.isDone()) {
      final tally = session.tally();
      moatLog('SyncService: session complete — received ${tally.messages} '
          'message(s) across ${tally.conversations} conversation(s), sent '
          '${tally.sentMessages} across ${tally.sentConversations}; closing pair WS');
      _transfer = null;
      await t.onComplete(tally, t.channel.peerDeviceName);
      // Held through `onComplete`, whose follow-up work is still part of
      // what the user is waiting for.
      if (_transfer == null) _progress.value = null;
    }
  }

  Future<void> _abort(_Transfer t, String reason, {bool closePair = false}) async {
    if (!identical(_transfer, t)) return;
    moatLog('SyncService: transfer aborted: $reason');
    _clear();
    await t.onAbort(reason);
    if (closePair) await _drawbridge.clearPair();
  }

  void _clear() {
    _transfer = null;
    _progress.value = null;
  }
}

/// One transfer, and what to tell whoever started it when it ends.
class _Transfer {
  _Transfer(this.channel, {required this.onComplete, required this.onAbort});

  final SyncChannel channel;
  final Future<void> Function(ffi.SyncTallyDto tally, String? deviceName) onComplete;
  final Future<void> Function(String reason) onAbort;

  /// Set once setup has built it; frames before then wait in the queue.
  ffi.SyncSessionHandle? session;
  late final String did;
}
