import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
import '../utils/value_listenable.dart';
import 'auth_service.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'sync_channel.dart';
import 'sync_service.dart';

/// URI scheme prefix for the QR form of a pairing code — matches
/// `moat_core::pairing::PAIRING_URI_SCHEME`. `confirmCode` dispatches on
/// this prefix to accept either the URI form (QR scan) or the bare text
/// form (manual entry) transparently.
const _pairingUriScheme = 'moat-pair:';

/// Owns a [ffi.PairingSessionHandle] and drives the full live-pairing
/// exchange (Enroll/Admit), then hands the history transfer that
/// follows to [SyncService], still under the pairing AEAD.
///
/// Dart-side analogue of the pairing interpreter in
/// `crates/moat-cli/src/app.rs` (`start_pairing_enroll`,
/// `handle_pairing_frame`, `approve_pending_pairing`,
/// `interpret_pairing_commands`, `start_pairing_sync_session`).
///
/// [state] is the single source of truth for pairing progress — screens
/// render off it rather than caching the code, prompt or a done flag
/// (mirroring `PairingSession::ui_state`). No host auto-approves an
/// incoming `Enroll`: approval is always an explicit [approvePending].
///
/// While a pairing is in flight this service temporarily takes over all
/// four of [DrawbridgeService]'s pair-WS callbacks — it needs both the
/// rendezvous (normally [DeviceRingService]'s job) and the attached-phase
/// handling (normally [SyncService]'s), since a device only ever drives
/// one pair-WS-mediated thing at a time. It hands them back via
/// [DeviceRingService.reclaimPairReadyCallback] /
/// [SyncService.reclaimPairCallbacks] once done or aborted.
class PairingService {
  final AuthService _auth;
  final DrawbridgeService _drawbridge;
  final DeviceRingService _ring;
  final SyncService _sync;

  ffi.PairingSessionHandle? _session;

  /// `true` for the new (joining) device, `false` for the existing
  /// (approving) device. Tells [_handlePairConnected] whether to call
  /// `startEnroll`.
  bool? _isNewDevice;

  final SimpleValueNotifier<ffi.PairingUiStateDto> _state =
      SimpleValueNotifier(const ffi.PairingUiStateDto.idle());

  /// The current pairing UI state — `idle` if no pairing is in flight,
  /// otherwise the active session's `uiState()`. Left reporting `done`/
  /// `failed` after completion, not just at the instant it happens (mirrors
  /// `PairingSession::ui_state`'s retention of a terminal outcome).
  ValueListenable<ffi.PairingUiStateDto> get state => _state;

  /// Refresh [state] from the live session — call after every operation
  /// that may have changed it (construction, `startEnroll`/`onFrameReceived`/
  /// `approve`/`reject`/`cancel`, success or failure alike).
  void _syncState() {
    _state.value = _session?.uiState() ?? const ffi.PairingUiStateDto.idle();
  }

  /// The post-Done history transfer [SyncService] is running for us, if
  /// any. While set, pair-channel frames and the close are forwarded to it.
  PairingSyncChannel? _transfer;

  /// Serializes pair-WS frame processing. Unlike `moat-cli`'s single
  /// event-loop actor (which handles one `BgEvent` at a time by
  /// construction), each incoming frame here starts its own async call
  /// chain — without this, two frames that arrive close together (e.g. the
  /// existing device's `Admit` immediately followed by its `StartSync`
  /// `Hello`, both sent within the same command-batch interpretation) can
  /// have their processing interleaved: the second frame's `_handleFrameReceived`
  /// can run its guard checks *before* the first frame's slower awaits
  /// (persisting ring state, populating tags) have caught the session up to
  /// `isDone()`/[_transfer], misrouting it into the PairingMsg decoder and
  /// aborting the session.
  Future<void> _frameQueue = Future.value();

  /// Bumped by [_supersedePreviousPairing] and [_releaseTransport]. Async
  /// call chains capture the generation they started under and re-check it
  /// after each await before mutating shared state or sending a frame —
  /// otherwise a stale continuation left running when a pairing is
  /// aborted/superseded (rather than cancelled) could still write into a
  /// since-replaced session or a since-reopened pair WS.
  int _generation = 0;

  PairingService({
    required AuthService auth,
    required DrawbridgeService drawbridge,
    required DeviceRingService ring,
    required SyncService sync,
  })  : _auth = auth,
        _drawbridge = drawbridge,
        _ring = ring,
        _sync = sync;

  /// The ring this session ended up in, once known.
  Uint8List? get ringId => _session?.ringId();

  /// New device: request a pairing code. Generates a fresh token+secret,
  /// starts a `PairingSessionHandle.newDevice` (which derives the code's
  /// text/URI forms itself — see `moat_core::PairingSession::new_device`),
  /// sends `pair_offer`, and returns the text-form code. Render `state`'s
  /// `ShowingCode` for both the text and the `moat-pair:` URI form (QR).
  Future<String> startEnroll() async {
    _supersedePreviousPairing();
    final token = _randomBytes(16);
    final secret = _randomBytes(16);

    final session = ffi.PairingSessionHandle.newDevice(secret: secret, token: token);
    _session = session;
    _isNewDevice = true;
    _syncState();

    _claimPairCallbacks();
    _drawbridge.sendPairOffer(token);

    final uiState = session.uiState();
    if (uiState is ffi.PairingUiStateDto_ShowingCode) {
      return uiState.code;
    }
    // Unreachable: a freshly constructed new-device session is always
    // ShowingCode (see moat-core's `PairingSession::new_device`).
    throw StateError('pairing session did not start in ShowingCode');
  }

  /// Existing device: enter a pairing code scanned/typed elsewhere — either
  /// the bare text form (manual entry) or the `moat-pair:` URI form (QR
  /// scan result). Parses it, starts a `PairingSessionHandle.existingDevice`,
  /// and sends `pair_join`. Approval of the resulting `Enroll` is a
  /// separate, explicit step (`approvePending`/`rejectPending`) once `state`
  /// reports `AwaitingApproval` — `confirmCode` never implies it.
  Future<void> confirmCode(String code) async {
    _supersedePreviousPairing();
    final trimmed = code.trim();
    final payload = trimmed.startsWith(_pairingUriScheme)
        ? await ffi.pairingPayloadFromUri(uri: trimmed)
        : await ffi.pairingPayloadFromText(text: trimmed);
    final token = Uint8List.fromList(payload.token);
    final secret = Uint8List.fromList(payload.secret);

    _session = ffi.PairingSessionHandle.existingDevice(secret: secret, token: token);
    _isNewDevice = false;
    _syncState();

    _claimPairCallbacks();
    _drawbridge.sendPairJoin(token);
  }

  /// Existing device: called once the user taps Approve, or `state` reports
  /// `AwaitingApproval` and the caller (e.g. the headless server) decides to
  /// approve. Creates the ring (first pairing) or adds the joiner
  /// (subsequent pairings), seeds the newcomer's KP pool, and emits the
  /// sealed `Admit` frame.
  ///
  /// Throws on any failure — precondition guard or the `approve()` call
  /// itself — so `POST /pair/approve` gets a real signal. UI callers can
  /// ignore it: `state` already reflects the outcome either way.
  ///
  /// Runs in the frame queue: the new device's sync `Hello` can arrive
  /// while this is still publishing, and must wait for the handoff.
  Future<void> approvePending() {
    final approved = _frameQueue.then((_) => _approvePending());
    _frameQueue = approved.catchError((Object _) {});
    return approved;
  }

  Future<void> _approvePending() async {
    final gen = _generation;
    final session = _session;
    if (session == null) {
      throw StateError('no active pairing session');
    }
    final pending = session.pendingEnroll();
    if (pending == null) {
      throw StateError('approvePending() called with no pending Enroll to approve');
    }
    final moatSession = _auth.moatSession;
    if (moatSession == null) {
      throw StateError('no active MoatSession');
    }

    final credential = _ownCredential(moatSession);
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    final stealthPubkey = await _auth.secureStorage.loadStealthPublicKey();
    if (keyBundle == null || stealthPubkey == null) {
      throw StateError('cannot approve — identity not ready');
    }

    final existingRingId = await _ring.ringGroupId();
    final isFirstPairing = existingRingId == null;
    final knownSiblings = await _knownSiblings(moatSession, existingRingId);

    // Capture the newcomer's stealth key before approve() consumes
    // pendingEnroll internally — Admit.roster only ever carries
    // *already-known* siblings (see SiblingInfo's doc on the Rust side),
    // so this is the only chance to record it for future fan-out to reach
    // this newcomer.
    final newcomerDeviceId = pending.credential.deviceId;
    final newcomerStealthPubkey = pending.stealthScanPubkey;

    List<ffi.PairingCommandDto> cmds;
    try {
      cmds = await session.approve(
        session: moatSession,
        credential: credential,
        keyBundle: keyBundle,
        ownStealthPubkey: stealthPubkey,
        knownSiblings: knownSiblings,
        existingRingId: existingRingId,
      );
    } catch (e) {
      // `approve()` already recorded `Failed { reason }` on the session —
      // keep it, release the transport, and rethrow for the HTTP caller.
      moatLog('PairingService: approve failed: $e');
      await _releaseTransport();
      _syncState();
      rethrow;
    }
    if (_generation != gen) return;

    // approve() just performed create_device_ring/add_member — the
    // heaviest MLS mutations in this flow. Persist immediately rather
    // than relying on some later, unrelated step to happen to save.
    await _auth.saveMlsState();

    if (isFirstPairing) {
      final newRingId = session.ringId();
      if (newRingId != null) {
        await _ring.recordRingMembership(newRingId);
      }
    }
    // Candidate tags for the ring, refreshed on *every* approve() (not
    // just the first) since the epoch — and therefore the candidate tag
    // set — advances on every Add. Without this a bystander sibling's
    // poll could never recognize the commit `publishRingCommit` is about
    // to publish.
    final ringIdForTags = session.ringId();
    if (ringIdForTags != null) {
      await _auth.populateConversationTags(ringIdForTags);
    }
    _ring.upsertSiblingStealth(newcomerDeviceId, newcomerStealthPubkey);

    if (_generation != gen) return;
    await _interpretCommands(cmds, gen);
    // qr-pairing.md §2: "On approve: ring add + conversation fan-out +
    // history sync all run over the established channel. The new device
    // shows conversations within seconds" — fan the newcomer into every
    // pre-existing user conversation right away rather than waiting on
    // the next periodic ring tick.
    unawaited(_ring.tick());
  }

  /// Existing device: reject the pending `Enroll`, moving the session to
  /// `Failed` (via moat-core's `PairingSession::reject`) rather than
  /// silently discarding it. Throws if there's no active session or
  /// nothing pending — see `approvePending`'s doc on why.
  Future<void> rejectPending() async {
    final session = _session;
    if (session == null) {
      throw StateError('no active pairing session');
    }
    try {
      session.reject();
    } catch (e) {
      moatLog('PairingService: reject failed: $e');
      await _releaseTransport();
      _syncState();
      rethrow;
    }
    await _releaseTransport();
    _syncState();
  }

  /// Either role: abort an in-flight pairing before it reaches a terminal
  /// state — e.g. the user backs out of the show-code or enter-code
  /// screen. Moves the session to `Failed` (via moat-core's
  /// `PairingSession::cancel`) rather than silently discarding it. Throws
  /// if there's no active session, or it has already reached a terminal
  /// state — see `approvePending`'s doc on why.
  Future<void> cancel() async {
    final session = _session;
    if (session == null) {
      throw StateError('no active pairing session');
    }
    try {
      session.cancel();
    } catch (e) {
      moatLog('PairingService: cancel failed: $e');
      await _releaseTransport();
      _syncState();
      rethrow;
    }
    await _releaseTransport();
    _syncState();
  }

  Future<void> dispose() async {
    if (_session != null) {
      try {
        await cancel();
      } catch (e) {
        moatLog('PairingService: dispose cancel failed: $e');
      }
    }
    _state.dispose();
  }

  // ── Pair WS callback ownership ──────────────────────────────────────────

  void _claimPairCallbacks() {
    _drawbridge.onPairReady = _handlePairReady;
    _drawbridge.onPairConnected = _handlePairConnected;
    _drawbridge.onPairFrame = _handlePairFrame;
    _drawbridge.onPairClosed = _handlePairClosed;
  }

  void _releasePairCallbacks() {
    _ring.reclaimPairReadyCallback();
    _sync.reclaimPairCallbacks();
  }

  /// Supersede whatever pairing came before, however it ended: a device
  /// drives one pairing at a time, and a leftover transfer would misread
  /// the new pairing's frames. Unlike [_releaseTransport], this also drops
  /// `_session` itself.
  void _supersedePreviousPairing() {
    _generation++;
    _drawbridge.clearPair();
    _drawbridge.clearPendingPairRendezvous();
    _dropTransfer();
    _frameQueue = Future.value();
    _session = null;
    _isNewDevice = null;
    _syncState();
  }

  /// Release the pair-WS transport and our ownership of its callbacks, once
  /// the exchange has nothing left to send or receive. Deliberately leaves
  /// `_session` alone: its state (including a just-recorded
  /// `Failed { reason }`) is what `state` reports.
  Future<void> _releaseTransport() async {
    _generation++;
    _dropTransfer();
    _frameQueue = Future.value();
    await _drawbridge.clearPair();
    _drawbridge.clearPendingPairRendezvous();
    _releasePairCallbacks();
  }

  void _handlePairReady(DrawbridgePairReady ready) {
    moatLog('PairingService: pair_ready — opening pair WS at ${ready.pairUrl}');
    unawaited(_drawbridge.connectPair(ready.pairUrl, ready.token));
  }

  void _handlePairConnected() {
    moatLog('PairingService: pair WS paired, isNewDevice=$_isNewDevice');
    if (_isNewDevice == true) {
      unawaited(_startEnrollFrame());
    }
    // Existing device: nothing to send yet, just wait for Enroll.
  }

  void _handlePairFrame(Uint8List data) {
    _enqueue(() => _handleFrameReceived(data));
  }

  /// Queued behind frames, so a close never overtakes the frames the peer
  /// sent before it — the last of which is usually its `Fin`.
  void _handlePairClosed(String reason) {
    moatLog('PairingService: pair WS closed: $reason');
    final gen = _generation;
    _enqueue(() async {
      // The transport this close belonged to has already been released.
      if (_generation != gen) return;
      final transfer = _transfer;
      if (transfer != null) {
        _sync.receiveClose(transfer, reason);
        return;
      }
      // Hand the callbacks back, or every later sync's frames would be
      // swallowed here.
      final session = _session;
      if (session == null) return;
      // Cancel a still-in-flight session so `state` reports why instead of
      // leaving it stuck forever in whatever phase it was in — a no-op
      // (ignored) if it had already reached a terminal state.
      try {
        session.cancel();
      } catch (_) {}
      await _releaseTransport();
      _syncState();
    });
  }

  /// Run pair-channel work one item at a time, in arrival order.
  void _enqueue(Future<void> Function() work) {
    _frameQueue = _frameQueue.then((_) => work()).catchError((Object e) {
      moatLog('PairingService: frame processing error: $e');
    });
  }

  // ── Enroll / Admit ───────────────────────────────────────────────────────

  Future<void> _startEnrollFrame() async {
    final gen = _generation;
    final session = _session;
    final moatSession = _auth.moatSession;
    if (session == null || moatSession == null) return;

    final credential = _ownCredential(moatSession);
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    final stealthPubkey = await _auth.secureStorage.loadStealthPublicKey();
    if (keyBundle == null || stealthPubkey == null) {
      moatLog('PairingService: cannot start_enroll — identity not ready');
      return;
    }
    if (_generation != gen) return;

    // Seed the approver's kp_pools entry for us directly
    // (Enroll.conv_kps), so it can fan us into pre-existing user
    // conversations immediately instead of waiting on a
    // KpRequest/KpBatch round trip over the stealth lane.
    final convKps = await _buildConvKpsBatch(moatSession, credential, keyBundle);
    if (_generation != gen) return;

    List<ffi.PairingCommandDto> cmds;
    try {
      cmds = await session.startEnroll(
        session: moatSession,
        credential: credential,
        keyBundle: keyBundle,
        stealthScanPubkey: stealthPubkey,
        convKps: convKps,
      );
    } catch (e) {
      // `start_enroll()` already recorded `Failed { reason }` on the
      // session itself before throwing — see the matching note in
      // `approvePending`.
      moatLog('PairingService: start_enroll failed: $e');
      await _releaseTransport();
      _syncState();
      return;
    }
    if (_generation != gen) return;
    await _auth.saveMlsState();
    if (_generation != gen) return;
    await _interpretCommands(cmds, gen);
  }

  Future<void> _handleFrameReceived(Uint8List data) async {
    // Past Done, the channel carries the history transfer. Forwarded from
    // inside the queue, so it reaches `SyncService` in arrival order.
    final transfer = _transfer;
    if (transfer != null) {
      _sync.receiveFrame(transfer, data);
      return;
    }
    final gen = _generation;
    final session = _session;
    final moatSession = _auth.moatSession;
    if (session == null || moatSession == null || session.isDone()) {
      return;
    }
    final credential = _ownCredential(moatSession);

    List<ffi.PairingCommandDto> cmds;
    try {
      cmds = await session.onFrameReceived(
        session: moatSession,
        ownCredential: credential,
        ciphertext: data,
      );
    } catch (e) {
      // `on_frame_received()` already recorded `Failed { reason }` on the
      // session itself before throwing — see the matching note in
      // `approvePending`.
      moatLog('PairingService: frame rejected: $e');
      await _releaseTransport();
      _syncState();
      return;
    }
    if (_generation != gen) return;
    await _auth.saveMlsState();
    if (_generation != gen) return;
    await _interpretCommands(cmds, gen);
  }

  /// Mirrors `interpret_pairing_commands` in `crates/moat-cli/src/app.rs`.
  /// `surfaceApprovalPrompt` is a no-op, same as moat-cli: `state`'s
  /// `AwaitingApproval` already carries deviceName/did.
  Future<void> _interpretCommands(List<ffi.PairingCommandDto> cmds, int gen) async {
    for (final cmd in cmds) {
      if (_generation != gen) return;
      await cmd.when(
        sendFrame: (ciphertext) async {
          if (_generation != gen) return;
          _drawbridge.sendPairBinary(ciphertext);
        },
        seedKpPool: (deviceId, kps) async {
          await _ring.ingestKpBatch(deviceId, kps);
        },
        publishRingCommit: (tag, ciphertext) async {
          try {
            await _auth.atprotoClient.publishEvent(tag, ciphertext);
          } catch (e) {
            moatLog('PairingService: publish ring commit failed: $e');
          }
        },
        surfaceApprovalPrompt: (deviceName, did) async {},
        persistRing: (ringId) async {
          await _ring.recordRingMembership(ringId);
          await _auth.populateConversationTags(ringId);
          // New device, right after persisting ring membership:
          // proactively scan for the UserConvWelcomes an existing
          // sibling's fan-out may already have published, rather than
          // waiting for the next periodic ring tick.
          unawaited(_ring.tick());
        },
        rosterReceived: (roster) async {
          final myDeviceId = _auth.moatSession?.deviceId();
          for (final s in roster) {
            if (myDeviceId != null && _bytesEqual(s.deviceId, myDeviceId)) {
              continue;
            }
            _ring.upsertSiblingStealth(s.deviceId, s.stealthPubkey);
          }
        },
        startSync: () async => _startPairingSyncSession(),
      );
    }
    if (_generation == gen) {
      _syncState();
    }
  }

  // ── Post-Done history transfer, under the pairing AEAD ──────────────────
  //
  // Per qr-pairing.md §3.2 the pairing AEAD keeps running for the whole
  // session rather than re-keying to ring MLS: the new device has no
  // ring-MLS traffic history to fall back on for this exchange.

  void _startPairingSyncSession() {
    // `startSync` only follows a done session, which has both.
    final session = _session;
    final ringId = session?.ringId();
    final handle = session?.transferChannel();
    if (ringId == null || handle == null) return;

    final channel = PairingSyncChannel(handle);
    _transfer = channel;
    _sync.runTransfer(
      channel,
      ringId: ringId,
      onComplete: () async {
        if (_transfer != channel) return;
        moatLog('PairingService: pairing-sync complete — closing pair WS');
        _transfer = null;
        await _releaseTransport();
        // Fan-out Welcomes may already be waiting for the new device.
        await _ring.tick();
      },
      onAbort: (reason) async {
        if (_transfer != channel) return;
        moatLog('PairingService: pairing-sync aborted: $reason');
        _transfer = null;
        _session?.transferFailed(reason: reason);
        await _releaseTransport();
        _syncState();
      },
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  void _dropTransfer() {
    final transfer = _transfer;
    _transfer = null;
    if (transfer != null) _sync.cancelTransfer(transfer);
  }

  ffi.CredentialDto _ownCredential(ffi.MoatSessionHandle moatSession) {
    return ffi.CredentialDto(
      did: _auth.did ?? '',
      deviceId: moatSession.deviceId(),
      deviceName: _auth.deviceName ?? '',
    );
  }

  /// Existing device: assemble the roster of already-known ring siblings
  /// for `Admit.roster` — `device_name` comes from ring MLS member
  /// credentials, stealth key from `DeviceRingService`'s cache. Empty for
  /// a first pairing (no ring, no siblings yet).
  Future<List<ffi.SiblingInfoDto>> _knownSiblings(
    ffi.MoatSessionHandle moatSession,
    Uint8List? ringId,
  ) async {
    if (ringId == null) return const [];
    var members = const <ffi.CredentialDto>[];
    try {
      members = await moatSession.getGroupMemberCredentials(groupId: ringId);
    } catch (e) {
      moatLog('PairingService: getGroupMemberCredentials failed: $e');
    }
    return _ring.cachedSiblingStealth.map((s) {
      var deviceName = '';
      for (final c in members) {
        if (_bytesEqual(c.deviceId, s.deviceId)) {
          deviceName = c.deviceName;
          break;
        }
      }
      return ffi.SiblingInfoDto(
        deviceId: s.deviceId,
        deviceName: deviceName,
        stealthPubkey: s.scanPubkey,
      );
    }).toList();
  }

  /// Generate a `kp_pool_target()`-sized batch of fresh KeyPackages for
  /// `Enroll.conv_kps`, mirroring `DeviceRingState::build_kp_batch`'s
  /// generation (seq allocation + fresh KeyPackage per entry), which is
  /// private to that module — this is the host reimplementing the same
  /// three lines against public APIs, same as `moat-cli` does.
  Future<List<ffi.OfferedKpDto>> _buildConvKpsBatch(
    ffi.MoatSessionHandle moatSession,
    ffi.CredentialDto credential,
    Uint8List keyBundle,
  ) async {
    final seqs = await _ring.allocateKpSeqs(ffi.kpPoolTarget().toInt());
    final out = <ffi.OfferedKpDto>[];
    for (final seq in seqs) {
      Uint8List keyPackage;
      try {
        keyPackage = await moatSession.replenishKeyPackage(
          did: credential.did,
          deviceName: credential.deviceName,
          keyBundle: keyBundle,
        );
      } catch (e) {
        moatLog('PairingService: replenishKeyPackage failed: $e');
        break;
      }
      out.add(ffi.OfferedKpDto(
        rkey: _randomBytes(16),
        seq: seq,
        keyPackage: keyPackage,
      ));
    }
    return out;
  }

  Uint8List _randomBytes(int length) {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => rng.nextInt(256)));
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
