import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
import '../utils/platform_int64.dart';
import '../utils/value_listenable.dart';
import 'auth_service.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'sync_service.dart';

/// The user-initiated "sync my history" gesture between two devices that
/// are already ring members.
///
/// Dart analogue of `App::api_sync_request` / `api_sync_accept` /
/// `api_sync_decline` and the `ring.msg` poll arm in
/// `crates/moat-cli/src/app.rs`.
///
/// Pairing hands a new device its history over the pairing channel, and
/// that covers its first moments only. A device already in the ring can
/// still be missing history — the sibling it paired with may not have held
/// it, a conversation may have arrived as a membership-only
/// `UserConvWelcome` after its pairing sync finished, or a transfer may
/// have been cut short with no way to reopen the (deliberately ephemeral)
/// pairing channel. So the user asks: this device publishes a
/// `RingMsg::SyncRequest` on the ring, every online sibling prompts, and
/// whichever one the user approves joins the rendezvous.
///
/// The transfer itself is not this service's job. Once the pair channel is
/// up, [SyncService] runs the ordinary ring-MLS-encrypted session; this
/// service only opens the rendezvous and tracks the state the UI renders.
class SyncRequestService {
  final AuthService _auth;
  final DrawbridgeService _drawbridge;
  final DeviceRingService _ring;
  final SyncService _sync;

  ffi.SyncRequestSessionHandle? _session;

  final SimpleValueNotifier<ffi.SyncRequestUiStateDto> _state =
      SimpleValueNotifier(const ffi.SyncRequestUiStateDto.idle());

  /// Current state — `idle` when nothing is in flight, otherwise the live
  /// session's projection. Retained after a terminal outcome so a failed
  /// sync stays distinguishable from a slow one.
  ValueListenable<ffi.SyncRequestUiStateDto> get state => _state;

  SyncRequestService({
    required AuthService auth,
    required DrawbridgeService drawbridge,
    required DeviceRingService ring,
    required SyncService sync,
  })  : _auth = auth,
        _drawbridge = drawbridge,
        _ring = ring,
        _sync = sync {
    // The transfer's lifecycle belongs to `SyncService`; this service only
    // needs to hear about it to keep `state` honest.
    _sync.onSessionStarted = _handleChannelUp;
    _sync.onSessionComplete = _handleComplete;
    _sync.onSessionAborted = _handleAborted;
  }

  void _syncState() {
    _state.value = _session?.uiState() ?? const ffi.SyncRequestUiStateDto.idle();
  }

  /// Move an unanswered request to `Failed` once its rendezvous token has
  /// expired. The session has no clock of its own, so a host must supply
  /// one — this is driven from the polling tick and from every read of
  /// [state] via [refresh], since nobody answering is by far the most
  /// likely way a request ends.
  void expireIfDue() {
    final session = _session;
    if (session == null) return;
    if (session.expireIfDue(
        nowMs: toPlatformInt64(DateTime.now().millisecondsSinceEpoch))) {
      moatLog('SyncRequestService: request expired with no device answering');
      _syncState();
    }
  }

  /// The current state, with expiry applied first — for callers that read
  /// on demand (`GET /sync/status`) rather than reacting to [state].
  ffi.SyncRequestUiStateDto refresh() {
    expireIfDue();
    return _state.value;
  }

  /// Ask this user's other devices for history this one is missing.
  ///
  /// Throws if there is no ring to publish on, or if the ring message
  /// can't be sealed — the rendezvous is only registered once the request
  /// itself is certain to go out.
  Future<void> requestSync({Uint8List? targetDeviceId}) async {
    final session = _auth.moatSession;
    if (session == null) {
      throw StateError('no active MoatSession');
    }
    final ringId = await _ring.ringGroupId();
    if (ringId == null) {
      throw StateError('no device ring — pair a device first');
    }
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    if (keyBundle == null) {
      throw StateError('missing key bundle');
    }

    final token = _randomBytes(16);
    final epoch = (await session.getGroupEpoch(groupId: ringId)) ?? BigInt.zero;
    final payload = await ffi.ringMsgEncodeSyncRequest(
      token: token,
      targetDeviceId: targetDeviceId,
    );
    final encrypted = await session.encryptEvent(
      groupId: ringId,
      keyBundle: keyBundle,
      event: ffi.EventDto(
        kind: ffi.EventKindDto.ringMsg,
        groupId: ringId,
        epoch: epoch,
        payload: payload,
      ),
    );
    await _auth.saveMlsState();

    _session = ffi.SyncRequestSessionHandle.request(
      token: token,
      nowMs: toPlatformInt64(DateTime.now().millisecondsSinceEpoch),
    );
    _syncState();

    _drawbridge.sendPairOffer(token);

    // Publish after the rendezvous is registered: a sibling that answers
    // instantly would otherwise race an offer that isn't there yet.
    try {
      final uri = await _auth.atprotoClient.publishEvent(
        encrypted.tag,
        encrypted.ciphertext,
      );
      // `publishEvent` returns the record's AT URI; the relay verifies
      // against the bare rkey.
      final rkey = uri.split('/').last;
      // Siblings watch the ring's tags, so the relay hands them this at
      // once rather than leaving it for their next poll.
      _drawbridge.notifyEventPosted(
        tag: encrypted.tag,
        rkey: rkey,
        payload: encrypted.ciphertext,
        relayUrls: const [],
      );
      moatLog('SyncRequestService: published sync request rkey=$rkey');
    } catch (e) {
      moatLog('SyncRequestService: publish failed: $e');
      _session?.fail(
          reason: ffi.SyncFailureDto.publishFailed(detail: e.toString()));
      _syncState();
      rethrow;
    }
  }

  /// Offer history to a sibling that does not have it.
  ///
  /// The mirror of [requestSync], for when the device holding the history
  /// is the one in the user's hands. This call *is* the human approval,
  /// so the target joins without prompting — exactly one approval per
  /// session, on the side that can judge. Always targeted: the relay
  /// admits two attaches, so an untargeted offer would pick its recipient
  /// arbitrarily.
  Future<void> offerSync(Uint8List targetDeviceId) async {
    final session = _auth.moatSession;
    if (session == null) {
      throw StateError('no active MoatSession');
    }
    final ringId = await _ring.ringGroupId();
    if (ringId == null) {
      throw StateError('no device ring — pair a device first');
    }
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    if (keyBundle == null) {
      throw StateError('missing key bundle');
    }

    final token = _randomBytes(16);
    final epoch = (await session.getGroupEpoch(groupId: ringId)) ?? BigInt.zero;
    final payload = await ffi.ringMsgEncodeSyncOffer(
      token: token,
      targetDeviceId: targetDeviceId,
    );
    final encrypted = await session.encryptEvent(
      groupId: ringId,
      keyBundle: keyBundle,
      event: ffi.EventDto(
        kind: ffi.EventKindDto.ringMsg,
        groupId: ringId,
        epoch: epoch,
        payload: payload,
      ),
    );
    await _auth.saveMlsState();

    _session = ffi.SyncRequestSessionHandle.offer(
      token: token,
      nowMs: toPlatformInt64(DateTime.now().millisecondsSinceEpoch),
    );
    _syncState();

    _drawbridge.sendPairOffer(token);

    try {
      final uri = await _auth.atprotoClient.publishEvent(
        encrypted.tag,
        encrypted.ciphertext,
      );
      _drawbridge.notifyEventPosted(
        tag: encrypted.tag,
        rkey: uri.split('/').last,
        payload: encrypted.ciphertext,
        relayUrls: const [],
      );
      moatLog('SyncRequestService: offered history to a sibling');
    } catch (e) {
      moatLog('SyncRequestService: offer publish failed: $e');
      _session?.fail(
          reason: ffi.SyncFailureDto.publishFailed(detail: e.toString()));
      _syncState();
      rethrow;
    }
  }

  /// A sibling's `ring.msg` arrived: a request for history, or an offer of
  /// it.
  ///
  /// `deviceName` and `deviceId` must both come from the MLS leaf
  /// credential of the sender, not from the payload — that is the whole
  /// reason this lane is the ring rather than the stealth one.
  Future<void> onRingMessage(
    Uint8List payload,
    String deviceName,
    Uint8List deviceId,
  ) async {
    final ffi.RingMsgDto msg;
    try {
      msg = await ffi.ringMsgDecode(payload: payload);
    } catch (e) {
      moatLog('SyncRequestService: undecodable ring message: $e');
      return;
    }

    switch (msg) {
      case ffi.RingMsgDto_SyncRequest(:final token, :final targetDeviceId):
        // A request naming another device is not ours to answer:
        // prompting would ask the user about someone else's business, and
        // two approvals would race for a rendezvous that admits two.
        if (targetDeviceId != null && !_isUs(targetDeviceId)) {
          moatLog('SyncRequestService: ignoring a request addressed elsewhere');
          return;
        }
        await _onSyncRequest(token, deviceName);
        return;
      case ffi.RingMsgDto_SyncOffer(:final token, :final targetDeviceId):
        if (!_isUs(targetDeviceId)) {
          moatLog('SyncRequestService: ignoring an offer addressed elsewhere');
          return;
        }
        await _onSyncOffer(token, deviceName);
        return;
    }
  }

  bool _isUs(List<int> deviceId) {
    final mine = _auth.moatSession?.deviceId();
    if (mine == null || mine.length != deviceId.length) return false;
    for (var i = 0; i < mine.length; i++) {
      if (mine[i] != deviceId[i]) return false;
    }
    return true;
  }

  /// A sibling is offering us history.
  ///
  /// Joined without a prompt, deliberately: the offer already carries one
  /// human decision, made on the side that could judge, and it comes from
  /// an authenticated ring member that can already read everything it is
  /// about to send. Asking again would be asking the user to approve
  /// receiving their own messages.
  ///
  /// Still refused while something else is in flight — an offer must not
  /// supersede a decision the user is already looking at.
  Future<void> _onSyncOffer(Uint8List token, String deviceName) async {
    final nowMs = toPlatformInt64(DateTime.now().millisecondsSinceEpoch);
    final existing = _session;
    if (existing != null &&
        !existing.isTerminal() &&
        !existing.isExpired(nowMs: nowMs)) {
      moatLog('SyncRequestService: ignoring an offer — one is already in flight');
      return;
    }

    moatLog('SyncRequestService: accepting $deviceName\'s offer of history');
    _session = ffi.SyncRequestSessionHandle.acceptOffer(
      token: token,
      nowMs: nowMs,
    );
    _syncState();
    _drawbridge.sendPairJoin(token);
  }

  Future<void> _onSyncRequest(Uint8List token, String deviceName) async {

    final nowMs = toPlatformInt64(DateTime.now().millisecondsSinceEpoch);
    // One sync session at a time. A live request of our own, or a prompt
    // the user is already looking at, outranks a new arrival — superseding
    // either would yank a decision out from under them.
    final existing = _session;
    if (existing != null &&
        !existing.isTerminal() &&
        !existing.isExpired(nowMs: nowMs)) {
      moatLog('SyncRequestService: ignoring request — one is already in flight');
      return;
    }

    moatLog('SyncRequestService: $deviceName is asking for history');
    _session = ffi.SyncRequestSessionHandle.received(
      token: token,
      deviceName: deviceName,
      nowMs: nowMs,
    );
    _syncState();
  }

  /// Send this device's history to the sibling that asked for it.
  Future<void> accept() async {
    final session = _session;
    if (session == null) {
      throw StateError('no sync request to accept');
    }
    final token = session.accept();
    _syncState();
    _drawbridge.sendPairJoin(Uint8List.fromList(token));
  }

  /// Refuse a sibling's request. Local only — with several siblings
  /// prompted, one refusal must not cancel the requester's outstanding
  /// request, so nothing goes on the wire.
  void decline() {
    final session = _session;
    if (session == null) {
      throw StateError('no sync request to decline');
    }
    session.decline();
    _syncState();
  }

  void _handleChannelUp() {
    final session = _session;
    if (session == null) return;
    try {
      session.onChannelUp();
    } catch (e) {
      moatLog('SyncRequestService: channel up on a finished request: $e');
    }
    _syncState();
  }

  void _handleComplete(ffi.SyncTallyDto tally, String? deviceName) {
    _session?.onComplete(tally: tally, deviceName: deviceName);
    _syncState();
  }

  void _handleAborted(String reason) {
    // A no-op once the session completed, which is the ordinary case: the
    // relay closes the channel right after a successful transfer.
    _session?.fail(reason: ffi.SyncFailureDto.channelClosed(detail: reason));
    _syncState();
  }

  void dispose() {
    _sync.onSessionStarted = null;
    _sync.onSessionComplete = null;
    _sync.onSessionAborted = null;
    _session = null;
  }

  static Uint8List _randomBytes(int n) {
    final rng = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => rng.nextInt(256)));
  }
}
