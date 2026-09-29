import 'dart:async';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import '../rust/api/simple.dart' as ffi;
import '../utils/platform_int64.dart';
import '../utils/value_listenable.dart';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'message_storage.dart';
import 'sync_history.dart';

/// Drives this device's pair channel — pairing, sync requests and offers,
/// and the history transfer either hands on to — through moat-core's
/// `PairChannelDriver`, and carries out the I/O it asks for.
///
/// Dart mirror of the `pair_channel` handling in `crates/moat-cli/src/app.rs`
/// (`apply_pair_commands` and the `BgEvent::Pair*` arms). The driver holds
/// all pair-channel state; this service holds none of its own.
class PairChannelService {
  final AuthService _auth;
  final DrawbridgeService _drawbridge;
  final DeviceRingService _ring;
  final ConversationsService _convService;
  final MessageStorage _messageStorage;

  final ffi.PairChannelHandle _driver = ffi.PairChannelHandle.newDriver();

  /// Driver calls run one at a time, in arrival order: most need identity
  /// loaded asynchronously first, and a frame must not overtake the one
  /// before it.
  Future<void> _queue = Future.value();

  final SimpleValueNotifier<ffi.PairingUiStateDto> _pairingState =
      SimpleValueNotifier(const ffi.PairingUiStateDto.idle());
  final SimpleValueNotifier<ffi.SyncRequestUiStateDto> _syncRequestState =
      SimpleValueNotifier(const ffi.SyncRequestUiStateDto.idle());
  final SimpleValueNotifier<ffi.SyncProgressDto?> _progress =
      SimpleValueNotifier(null);

  /// Pairing progress; retained once `done` or `failed`.
  ValueListenable<ffi.PairingUiStateDto> get pairingState => _pairingState;

  /// The sync-request gesture; retained once `complete` or `failed`.
  ValueListenable<ffi.SyncRequestUiStateDto> get syncRequestState =>
      _syncRequestState;

  /// How far the running transfer has got; `null` when none is running.
  ValueListenable<ffi.SyncProgressDto?> get progress => _progress;

  /// True iff a history transfer holds the pair channel.
  bool get isTransferring => _driver.isTransferring();

  PairChannelService({
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
    _drawbridge.onPairReady = (ready) =>
        _run(() => _apply(_driver.onPairReady(token: ready.token, url: ready.pairUrl)));
    _drawbridge.onPairConnected = () => _runWithEnv((e) => _driver.onPaired(
          session: e.session,
          ring: e.ring,
          identity: e.identity,
          siblingStealth: e.siblingStealth,
          nowMs: e.nowMs,
        ));
    _drawbridge.onPairFrame = (data) => _runWithEnv((e) => _driver.onFrame(
          session: e.session,
          ring: e.ring,
          identity: e.identity,
          siblingStealth: e.siblingStealth,
          nowMs: e.nowMs,
          data: data,
        ));
    // Queued behind frames, so a close never overtakes the frames the
    // peer sent before it — the last of which is usually its `Fin`.
    _drawbridge.onPairClosed = (reason) =>
        _run(() => _apply(_driver.onPairClosed(token: null, reason: reason)));
    _drawbridge.onAuthenticated =
        () => _run(() => _apply(_driver.onRelayConnected()));
  }

  void dispose() {
    _drawbridge.onPairReady = null;
    _drawbridge.onPairConnected = null;
    _drawbridge.onPairFrame = null;
    _drawbridge.onPairClosed = null;
    _drawbridge.onAuthenticated = null;
    unawaited(_drawbridge.clearPair());
  }

  // ── Pairing ─────────────────────────────────────────────────────────────

  /// New device: start a pairing and return the code to show. Render
  /// [pairingState]'s `showingCode` for both its text and QR forms.
  Future<String> startPairing() => _call(() async {
        final started = _driver.pairNew();
        await _apply(started.commands);
        return started.code;
      });

  /// Existing device: enter a code shown elsewhere, as text or as the
  /// `moat-pair:` URI a QR scan yields. Approval is a separate step.
  Future<void> confirmPairingCode(String code) =>
      _call(() => _apply(_driver.pairConfirm(code: code)));

  /// Existing device: approve the pending `Enroll`. Throws if there was
  /// nothing to approve or approving failed; [pairingState] shows why.
  Future<void> approvePairing() => _call(() async {
        final e = await _env();
        await _apply(await _driver.pairApprove(
          session: e.session,
          ring: e.ring,
          identity: e.identity,
          siblingStealth: e.siblingStealth,
          nowMs: e.nowMs,
        ));
        final state = _driver.pairingUiState();
        if (state is ffi.PairingUiStateDto_Failed) {
          throw StateError(state.reason);
        }
      });

  /// Existing device: decline the pending `Enroll`.
  Future<void> rejectPairing() =>
      _call(() => _apply(_driver.pairReject()));

  /// Either role: abandon an in-flight pairing.
  Future<void> cancelPairing() =>
      _call(() => _apply(_driver.pairCancel()));

  // ── Sync requests and offers ────────────────────────────────────────────

  /// Ask this user's other devices for history this one is missing;
  /// [targetDeviceId] names one of them.
  Future<void> requestSync({Uint8List? targetDeviceId}) => _call(() async {
        final e = await _env();
        await _apply(await _driver.syncRequest(
          session: e.session,
          ring: e.ring,
          identity: e.identity,
          siblingStealth: e.siblingStealth,
          nowMs: e.nowMs,
          target: targetDeviceId,
        ));
      });

  /// Send this device's history to [targetDeviceId], which joins without
  /// a prompt of its own.
  Future<void> offerSync(Uint8List targetDeviceId) => _call(() async {
        final e = await _env();
        await _apply(await _driver.syncOffer(
          session: e.session,
          ring: e.ring,
          identity: e.identity,
          siblingStealth: e.siblingStealth,
          nowMs: e.nowMs,
          target: targetDeviceId,
        ));
      });

  /// Serve the sibling whose request is awaiting approval.
  Future<void> acceptSyncRequest() =>
      _call(() => _apply(_driver.syncAccept()));

  /// Refuse the sibling's request. Local only.
  Future<void> declineSyncRequest() => _call(() async {
        _driver.syncDecline();
        _syncState();
      });

  /// A sibling's `ring.msg`. [deviceName] must come from the sender's MLS
  /// leaf credential, not from the payload.
  Future<void> onRingMessage(Uint8List payload, String deviceName, Uint8List _) =>
      _run(() async {
        final session = _auth.moatSession;
        if (session == null) return;
        try {
          await _apply(_driver.onRingMsg(
            payload: payload,
            senderName: deviceName,
            ownDeviceId: session.deviceId(),
            nowMs: _now(),
          ));
        } catch (e) {
          moatLog('PairChannelService: undecodable ring message: $e');
        }
      });

  /// Expire an unanswered sync request. Driven from the polling tick.
  void expireIfDue() => _run(() => _apply(_driver.tick(nowMs: _now())));

  /// The sync-request state with expiry applied, for on-demand reads.
  ffi.SyncRequestUiStateDto refreshSyncRequest() {
    final cmds = _driver.tick(nowMs: _now());
    _run(() => _apply(cmds));
    return _driver.syncRequestUiState();
  }

  // ── Driver plumbing ─────────────────────────────────────────────────────

  static PlatformInt64 _now() =>
      toPlatformInt64(DateTime.now().millisecondsSinceEpoch);

  /// Queue [work] behind every earlier driver call.
  Future<void> _run(Future<void> Function() work) {
    final done = _queue.then((_) => work());
    _queue = done.catchError((Object e) {
      moatLog('PairChannelService: $e');
    });
    return _queue;
  }

  /// Like [_run], but the caller sees the result or the error.
  Future<T> _call<T>(Future<T> Function() work) {
    final done = _queue.then((_) => work());
    _queue = done.then((_) {}, onError: (Object _) {});
    return done;
  }

  void _runWithEnv(Future<List<ffi.PairChannelCommandDto>> Function(_Env e) step) {
    _run(() async {
      final _Env env;
      try {
        env = await _env();
      } catch (e) {
        await _apply(_driver.onRendezvousFailed(reason: '$e'));
        return;
      }
      await _apply(await step(env));
    });
  }

  Future<_Env> _env() async {
    final session = _auth.moatSession;
    final ring = _ring.driverHandle;
    final did = _auth.did;
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    final stealthPubkey = await _auth.secureStorage.loadStealthPublicKey();
    if (session == null ||
        ring == null ||
        did == null ||
        keyBundle == null ||
        stealthPubkey == null) {
      throw StateError('identity not ready');
    }
    return _Env(
      session: session,
      ring: ring,
      identity: ffi.PairIdentityDto(
        credential: ffi.CredentialDto(
          did: did,
          deviceId: session.deviceId(),
          deviceName: _auth.deviceName ?? '',
        ),
        keyBundle: keyBundle,
        stealthPubkey: stealthPubkey,
      ),
      siblingStealth: _ring.cachedSiblingStealth,
      nowMs: _now(),
    );
  }

  /// Carry out the driver's commands in order. Only ever called from
  /// inside the queue.
  Future<void> _apply(List<ffi.PairChannelCommandDto> cmds) async {
    for (final cmd in cmds) {
      switch (cmd) {
        case ffi.PairChannelCommandDto_SendPairOffer(:final token):
          _drawbridge.sendPairOffer(token);
        case ffi.PairChannelCommandDto_SendPairJoin(:final token):
          _drawbridge.sendPairJoin(token);
        case ffi.PairChannelCommandDto_ConnectPair(:final url, :final token):
          unawaited(_drawbridge.connectPair(url, token));
        case ffi.PairChannelCommandDto_SendFrame(:final data):
          _drawbridge.sendPairBinary(data);
        case ffi.PairChannelCommandDto_ClosePair():
        case ffi.PairChannelCommandDto_DropPair():
          await _drawbridge.clearPair();
        case ffi.PairChannelCommandDto_PublishRingEvent(:final tag, :final ciphertext):
          await _publishRingEvent(tag, ciphertext);
        case ffi.PairChannelCommandDto_LoadHistory(:final token):
          final history = await loadSyncHistory(_convService, _messageStorage);
          final e = await _env();
          await _apply(await _driver.provideHistory(
            session: e.session,
            ring: e.ring,
            identity: e.identity,
            siblingStealth: e.siblingStealth,
            nowMs: e.nowMs,
            token: token,
            history: history,
          ));
        case ffi.PairChannelCommandDto_StoreMessages(:final convId, :final messages):
          final did = _auth.did;
          if (did == null) break;
          await registerSyncedConversation(_convService, convId, messages, did);
          final count =
              await storeSyncOutputMessages(_messageStorage, convId, messages, did);
          moatLog('PairChannelService: stored $count message(s) for $convId');
        case ffi.PairChannelCommandDto_SaveMlsState():
          await _auth.saveMlsState();
        case ffi.PairChannelCommandDto_SaveRingState():
          await _ring.persist();
        case ffi.PairChannelCommandDto_RingJoined(:final ringId):
          await _auth.populateConversationTags(ringId);
          // Fan-out Welcomes may already be waiting.
          unawaited(_ring.tick());
        case ffi.PairChannelCommandDto_DeviceAdmitted(:final ringId):
          // The ring's epoch, and so its candidate tags, advance on every Add.
          await _auth.populateConversationTags(ringId);
          unawaited(_ring.tick());
        case ffi.PairChannelCommandDto_SiblingStealthLearned(
            :final deviceId,
            :final scanPubkey
          ):
          _ring.upsertSiblingStealth(deviceId, scanPubkey);
        case ffi.PairChannelCommandDto_TransferComplete(:final tally):
          moatLog('PairChannelService: transfer complete — received '
              '${tally.messages} message(s) across ${tally.conversations} '
              'conversation(s), sent ${tally.sentMessages} across '
              '${tally.sentConversations}');
          // A new device may already be owed conversations.
          unawaited(_ring.tick());
        case ffi.PairChannelCommandDto_TransferFailed(:final detail):
          moatLog('PairChannelService: transfer failed: $detail');
        case ffi.PairChannelCommandDto_Log(:final line):
          moatLog('PairChannelService: $line');
      }
    }
    _syncState();
  }

  Future<void> _publishRingEvent(Uint8List tag, Uint8List ciphertext) async {
    try {
      final uri = await _auth.atprotoClient.publishEvent(tag, ciphertext);
      _drawbridge.notifyEventPosted(
        tag: tag,
        rkey: uri.split('/').last,
        payload: ciphertext,
        relayUrls: const [],
      );
    } catch (e) {
      moatLog('PairChannelService: publish ring event failed: $e');
      await _apply(_driver.onRingPublishFailed(tag: tag, detail: '$e'));
    }
  }

  void _syncState() {
    _pairingState.value = _driver.pairingUiState();
    _syncRequestState.value = _driver.syncRequestUiState();
    _progress.value = _driver.progress();
  }
}

/// This device's local state, for the driver calls that need it.
class _Env {
  _Env({
    required this.session,
    required this.ring,
    required this.identity,
    required this.siblingStealth,
    required this.nowMs,
  });

  final ffi.MoatSessionHandle session;
  final ffi.RingDriverHandle ring;
  final ffi.PairIdentityDto identity;
  final List<ffi.SiblingStealthDto> siblingStealth;
  final PlatformInt64 nowMs;
}
