import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
import '../utils/value_listenable.dart';
import 'auth_service.dart';
import 'conversation_storage.dart';
import 'debug_log.dart';
import 'device_ring_service.dart';
import 'drawbridge_service.dart';
import 'message_storage.dart';
import 'paired_sync_builder.dart';
import 'sync_service.dart';

/// URI scheme prefix for the QR form of a pairing code — matches
/// `moat_core::pairing::PAIRING_URI_SCHEME`. `confirmCode` dispatches on
/// this prefix to accept either the URI form (QR scan) or the bare text
/// form (manual entry) transparently.
const _pairingUriScheme = 'moat-pair:';

/// Owns a [ffi.PairingSessionHandle] and drives the full live-pairing
/// exchange (Enroll/Admit/Done) plus the post-Done history-sync handoff,
/// entirely under the pairing AEAD.
///
/// Dart-side analogue of the pairing interpreter in
/// `crates/moat-cli/src/app.rs` (`start_pairing_enroll`,
/// `handle_pairing_frame`, `approve_pending_pairing`,
/// `interpret_pairing_commands`, `start_pairing_sync_session`,
/// `process_pairing_sync_outputs`, `process_pairing_sync_frame`).
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
  final ConversationStorage _convStorage;
  final MessageStorage _messageStorage;

  ffi.PairingSessionHandle? _session;

  /// `true` for the new (joining) device, `false` for the existing
  /// (approving) device. Tells [_handlePairConnected] whether to call
  /// `startEnroll`, and picks the right directional AEAD key once in the
  /// post-Done sync phase.
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

  // ── Post-Done pairing-AEAD sync phase state ──────────────────────────────
  // Set by `_startPairingSyncSession`; cleared on `SyncOutput.complete`,
  // on abort, or at the start of a new pairing — a second/third pairing
  // must not inherit a prior pairing's still-set sync keys.
  Uint8List? _pairingSyncKeyNewToOld;
  Uint8List? _pairingSyncKeyOldToNew;
  BigInt _pairingSyncSendCounter = BigInt.zero;
  BigInt _pairingSyncRecvCounter = BigInt.zero;
  ffi.SyncSessionHandle? _pairingSyncSession;

  /// Serializes pair-WS frame processing. Unlike `moat-cli`'s single
  /// event-loop actor (which handles one `BgEvent` at a time by
  /// construction), each incoming frame here starts its own async call
  /// chain — without this, two frames that arrive close together (e.g. the
  /// existing device's `Admit` immediately followed by its `StartSync`
  /// `Hello`, both sent within the same command-batch interpretation) can
  /// have their processing interleaved: the second frame's `_handleFrameReceived`
  /// can run its guard checks *before* the first frame's slower awaits
  /// (persisting ring state, populating tags) have caught the session up to
  /// `isDone()`/`_pairingSyncKeyNewToOld`, misrouting it into the
  /// PairingMsg decoder and aborting the session.
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
    required ConversationStorage conversationStorage,
    required MessageStorage messageStorage,
  })  : _auth = auth,
        _drawbridge = drawbridge,
        _ring = ring,
        _sync = sync,
        _convStorage = conversationStorage,
        _messageStorage = messageStorage;

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
    final secret = _randomBytes(32);

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
  Future<void> approvePending() async {
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

  /// A previous pairing's pair WS / sync state (if any) is now
  /// superseded — a device only ever drives one pairing exchange at a
  /// time, and leaving the old pairing-sync keys set would route this new
  /// pairing's incoming frames through the *old* AEAD channel's dispatch,
  /// misinterpreting them (see `_handleFrameReceived`'s dispatch note).
  /// Unlike [_releaseTransport], this also drops `_session` itself —
  /// starting a *new* pairing always supersedes whatever came before,
  /// regardless of how it ended.
  void _supersedePreviousPairing() {
    _generation++;
    _drawbridge.clearPair();
    _drawbridge.clearPendingPairRendezvous();
    _pairingSyncSession = null;
    _pairingSyncKeyNewToOld = null;
    _pairingSyncKeyOldToNew = null;
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
    _pairingSyncSession = null;
    _pairingSyncKeyNewToOld = null;
    _pairingSyncKeyOldToNew = null;
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
    _frameQueue = _frameQueue.then((_) => _handleFrameReceived(data)).catchError((Object e) {
      moatLog('PairingService: frame processing error: $e');
    });
  }

  void _handlePairClosed(String reason) {
    moatLog('PairingService: pair WS closed: $reason');
    // The pair WS dropped before `SyncOutput.complete`, the only other
    // place that hands the callbacks back to `SyncService`/`DeviceRingService`.
    // Without this we'd hold all four slots forever, silently swallowing
    // every later reconnect-sync frame.
    final session = _session;
    if (session == null) return;
    // Cancel a still-in-flight session so `state` reports why instead of
    // leaving it stuck forever in whatever phase it was in — a no-op
    // (ignored) if it had already reached a terminal state.
    try {
      session.cancel();
    } catch (_) {}
    unawaited(_releaseTransport());
    _syncState();
  }

  // ── Enroll / Admit / Done ────────────────────────────────────────────────

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
    // Three possible occupants of the pair channel: still mid
    // Enroll/Admit/Done (`_session`, not yet done), past Done and running
    // history sync under the *same* pairing AEAD (`_pairingSyncKeyNewToOld`
    // set), or — not applicable here, since PairingService only owns
    // these callbacks while a pairing is actually in flight.
    if (_pairingSyncKeyNewToOld != null) {
      await _processPairingSyncFrame(data);
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
  /// `startSync` is deferred to the end of the batch rather than acted on
  /// where it appears: it sends a sync `Hello` at the *next* pairing-AEAD
  /// counter, so any `sendFrame` later in the same batch (e.g. the new
  /// device's `Done`) must reach the wire first, or the peer sees frames
  /// out of counter order. `surfaceApprovalPrompt` is a no-op, same as
  /// moat-cli: `state`'s `AwaitingApproval` already carries deviceName/did.
  Future<void> _interpretCommands(List<ffi.PairingCommandDto> cmds, int gen) async {
    var startSync = false;
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
        startSync: () async {
          startSync = true;
        },
      );
    }
    if (_generation == gen) {
      _syncState();
    }
    if (startSync && _generation == gen) {
      await _startPairingSyncSession(gen);
    }
  }

  // ── Post-Done history sync, under the pairing AEAD ──────────────────────
  //
  // Deliberately does not reuse `SyncService`'s ring-MLS transport: per
  // qr-pairing.md §3.2 the pairing AEAD keeps running for the whole
  // session rather than re-keying to ring MLS (the new device in
  // particular has no ring-MLS traffic history to fall back on for this
  // exchange).

  Future<void> _startPairingSyncSession(int gen) async {
    final session = _session;
    final moatSession = _auth.moatSession;
    if (session == null || moatSession == null) return;

    final keyNewToOld = session.channelKeyNewToOld();
    final keyOldToNew = session.channelKeyOldToNew();
    final sendCounter = session.nextSendCounter();
    final recvCounter = session.nextRecvCounter();

    final ringId = session.ringId();
    if (ringId == null) return;
    final ringEpoch = (await moatSession.getGroupEpoch(groupId: ringId)) ?? BigInt.zero;
    if (_generation != gen) return;

    final setup = await buildPairedSyncSession(
      session: moatSession,
      convStorage: _convStorage,
      messageStorage: _messageStorage,
      ringEpoch: ringEpoch,
    );
    if (_generation != gen) return;

    // Only committed to shared state once we know this generation is
    // still current — an abort/supersede mid-setup must not leave these
    // keys set for a session that's no longer the live one.
    _pairingSyncKeyNewToOld = keyNewToOld;
    _pairingSyncKeyOldToNew = keyOldToNew;
    _pairingSyncSendCounter = sendCounter;
    _pairingSyncRecvCounter = recvCounter;
    _pairingSyncSession = setup.session;
    await _processPairingSyncOutputs(setup.outputs, gen);
  }

  Future<void> _processPairingSyncOutputs(List<ffi.SyncOutputDto> outputs, int gen) async {
    final did = _auth.did;
    for (final output in outputs) {
      if (_generation != gen) return;
      await output.when(
        send: (bytes) async {
          final key = _isNewDevice == true ? _pairingSyncKeyNewToOld : _pairingSyncKeyOldToNew;
          if (key == null) return;
          final counter = _pairingSyncSendCounter;
          try {
            final ciphertext = await ffi.pairingSealFrame(
              key: key,
              counter: counter,
              plaintext: bytes,
            );
            if (_generation != gen) return;
            _pairingSyncSendCounter = counter + BigInt.one;
            _drawbridge.sendPairBinary(ciphertext);
          } catch (e) {
            moatLog('PairingService: pairing_seal_frame failed: $e');
          }
        },
        store: (convId, messages) async {
          if (did == null) return;
          final count =
              await storeSyncOutputMessages(_messageStorage, convId, messages, did);
          moatLog('PairingService: pairing-sync stored $count message(s) for $convId');
        },
      );
    }

    // As in `SyncService`: tear down only once every output in the batch
    // has been applied, never as one of them.
    if (gen == _generation && (await _pairingSyncSession?.isDone() ?? false)) {
      moatLog('PairingService: pairing-sync complete — closing pair WS');
      _pairingSyncSession = null;
      _pairingSyncKeyNewToOld = null;
      _pairingSyncKeyOldToNew = null;
      await _releaseTransport();
    }
  }

  /// Open and dispatch an incoming binary frame under the pairing AEAD.
  ///
  /// The recv counter is the AEAD nonce for every frame after this one —
  /// once a frame has genuinely been consumed off the wire, there is no
  /// safe way to "skip" it: the peer's next frame was sealed expecting the
  /// counter to advance, so a frame we can't process is fatal to the rest
  /// of the session, not just to itself. Every early return below that
  /// happens *before* the counter would advance is a safe drop (the peer's
  /// send counter and ours are still in lockstep); every failure *after*
  /// [ffi.pairingOpenFrame] succeeds is unrecoverable and aborts the
  /// transport instead of returning silently — the pairing itself already
  /// reached `Done` at this point (this is the post-Done sync phase), so
  /// unlike the other catch blocks here there's no session state left to
  /// preserve, only the sync/transport state to tear down.
  Future<void> _processPairingSyncFrame(Uint8List data) async {
    final gen = _generation;
    final key = _isNewDevice == true ? _pairingSyncKeyOldToNew : _pairingSyncKeyNewToOld;
    final did = _auth.did;
    final syncSession = _pairingSyncSession;
    final moatSession = _auth.moatSession;
    if (key == null || did == null || syncSession == null || moatSession == null) {
      return;
    }

    Uint8List plaintext;
    try {
      plaintext = await ffi.pairingOpenFrame(
        key: key,
        counter: _pairingSyncRecvCounter,
        ciphertext: data,
      );
    } catch (e) {
      moatLog('PairingService: pairing-sync failed to open frame: $e — aborting '
          '(the recv counter cannot safely skip a frame that failed to open)');
      await _releaseTransport();
      return;
    }
    if (_generation != gen) return;
    _pairingSyncRecvCounter += BigInt.one;

    // The new device's advisory `Done` courtesy (channel-teardown only,
    // not load-bearing for either side's own completion) can still be in
    // flight when the peer locally transitions to sync mode: both sides
    // do so as soon as *their own* processing finishes, independent of
    // what the other side has sent or received yet. A `Done` that arrives
    // after that transition opens fine under the pairing AEAD (same
    // channel, next counter) but isn't a SyncMsg — recognize and ignore
    // it rather than treating it as a decode error.
    if (ffi.pairingFrameIsDone(plaintext: plaintext)) {
      moatLog('PairingService: pairing-sync received the pairing session\'s Done courtesy');
      return;
    }

    List<ffi.SyncOutputDto> outputs;
    try {
      outputs = await syncSession.onMessage(msgBytes: plaintext);
    } catch (e) {
      moatLog('PairingService: pairing-sync onMessage failed: $e — aborting');
      await _releaseTransport();
      return;
    }
    if (_generation != gen) return;
    await _processPairingSyncOutputs(outputs, gen);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

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
