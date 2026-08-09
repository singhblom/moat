import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
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

  String? _pendingCode;
  String? _pendingUri;
  String? _pendingDeviceName;
  String? _pendingDid;

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

  /// Bumped by [_supersedePreviousPairing] and [_abort]. Async call chains
  /// capture the generation they started under and re-check it after each
  /// await before mutating shared state or sending a frame — otherwise a
  /// stale continuation left running when a pairing is aborted/superseded
  /// (rather than cancelled) could still write into a since-replaced
  /// session or a since-reopened pair WS.
  int _generation = 0;

  /// Auto-approve incoming Enroll requests without a user tap — set by the
  /// headless server (`moat-dart/server`), left `false` for the
  /// interactive Flutter app (which shows an approve screen instead).
  bool autoApprove;

  /// Existing device, interactive UI only: fired the moment an `Enroll`
  /// arrives and needs a user decision — mirrors `moat-cli`'s TUI switching
  /// `Focus::PairApprove` synchronously inside `interpret_pairing_commands`.
  /// Not called when [autoApprove] is set (the headless server auto-accepts
  /// instead, same as moat-cli's `--http` mode).
  void Function()? onApprovalPending;

  PairingService({
    required AuthService auth,
    required DrawbridgeService drawbridge,
    required DeviceRingService ring,
    required SyncService sync,
    required ConversationStorage conversationStorage,
    required MessageStorage messageStorage,
    this.autoApprove = false,
  })  : _auth = auth,
        _drawbridge = drawbridge,
        _ring = ring,
        _sync = sync,
        _convStorage = conversationStorage,
        _messageStorage = messageStorage;

  /// `true` once the active pairing session (if any) has reached its
  /// terminal `Done` phase. Left in place (not cleared) once done —
  /// `/pair/status` must keep reporting `done: true` after completion, not
  /// just at the instant it happens.
  bool get isDone => _session?.isDone() ?? false;

  /// The ring this session ended up in, once known.
  Uint8List? get ringId => _session?.ringId();

  /// Existing device: name/DID of a peer whose `Enroll` has been received
  /// but not yet approved.
  String? get pendingDeviceName => _pendingDeviceName;
  String? get pendingDid => _pendingDid;

  /// New device: the text-form code returned by the most recent
  /// `startEnroll()`, kept around for redisplay (manual entry / clipboard).
  String? get pendingCode => _pendingCode;

  /// New device: the `moat-pair:` URI form of the same code, for rendering
  /// as a QR — qr-pairing.md §2: "so the app can register a handler and
  /// reject foreign QRs cheaply", vs. the bare text form which round-trips
  /// through manual entry and has no scheme to register.
  String? get pendingUri => _pendingUri;

  /// New device: request a pairing code. Generates a fresh token+secret,
  /// starts a `PairingSessionHandle.newDevice`, sends `pair_offer`, and
  /// returns the text-form code for the UI to render as manually-typeable
  /// text (render [pendingUri] as the QR).
  Future<String> startEnroll() async {
    _supersedePreviousPairing();
    final token = _randomBytes(16);
    final secret = _randomBytes(32);

    final code = await ffi.pairingPayloadToText(token: token, secret: secret);
    final uri = await ffi.pairingPayloadToUri(token: token, secret: secret);

    _session = ffi.PairingSessionHandle.newDevice(secret: secret, token: token);
    _isNewDevice = true;
    _pendingCode = code;
    _pendingUri = uri;

    _claimPairCallbacks();
    _drawbridge.sendPairOffer(token);
    return code;
  }

  /// Existing device: enter a pairing code scanned/typed elsewhere — either
  /// the bare text form (manual entry) or the `moat-pair:` URI form (QR
  /// scan result). Parses it, starts a `PairingSessionHandle.existingDevice`,
  /// and sends `pair_join`. Approval of the resulting `Enroll` happens
  /// later, once it arrives (auto-accepted when [autoApprove] is set, gated
  /// on a user tap in the interactive UI otherwise).
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

    _claimPairCallbacks();
    _drawbridge.sendPairJoin(token);
  }

  /// Existing device: called once the user taps Approve (interactive UI),
  /// or automatically as soon as `Enroll` arrives when [autoApprove] is
  /// set. Creates the ring (first pairing) or adds the joiner (subsequent
  /// pairings), seeds the newcomer's KP pool, and emits the sealed `Admit`
  /// frame.
  Future<void> approvePending() async {
    final gen = _generation;
    final session = _session;
    if (session == null) return;
    final pending = session.pendingEnroll();
    if (pending == null) return;
    final moatSession = _auth.moatSession;
    if (moatSession == null) return;

    final credential = _ownCredential(moatSession);
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    final stealthPubkey = await _auth.secureStorage.loadStealthPublicKey();
    if (keyBundle == null || stealthPubkey == null) {
      moatLog('PairingService: cannot approve — identity not ready');
      return;
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
      moatLog('PairingService: approve failed: $e');
      await _abort();
      return;
    }
    if (_generation != gen) return;

    _pendingDeviceName = null;
    _pendingDid = null;

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

  /// Existing device: reject a pending Enroll, aborting the pairing.
  Future<void> rejectPending() async {
    await _abort();
  }

  Future<void> dispose() async {
    await _abort();
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
  void _supersedePreviousPairing() {
    _generation++;
    _drawbridge.clearPair();
    _drawbridge.clearPendingPairRendezvous();
    _pairingSyncSession = null;
    _pairingSyncKeyNewToOld = null;
    _pairingSyncKeyOldToNew = null;
    _pendingDeviceName = null;
    _pendingDid = null;
    _pendingCode = null;
    _pendingUri = null;
    _frameQueue = Future.value();
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
    // The pair WS dropped (peer walked away, relay TTL, byte cap) before
    // this pairing reached `SyncOutput.complete` — which is the only other
    // place that releases the pair-WS callbacks back to
    // `SyncService`/`DeviceRingService`. Without this, a mid-exchange drop
    // leaves `PairingService` holding all four callback slots forever:
    // every subsequent unrelated pair session (an established-devices
    // reconnect sync) would silently route into `_handleFrameReceived`,
    // which drops every frame since `_session` is stale/null, with no
    // error surfaced anywhere. `_abort()` is idempotent-safe to call after
    // a session already completed and released its own callbacks.
    if (_session == null) return;
    unawaited(_abort());
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
      moatLog('PairingService: start_enroll failed: $e');
      await _abort();
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
      moatLog('PairingService: frame rejected: $e');
      await _abort();
      return;
    }
    if (_generation != gen) return;
    await _auth.saveMlsState();
    if (_generation != gen) return;
    await _interpretCommands(cmds, gen);
  }

  /// Mirrors `interpret_pairing_commands` in `crates/moat-cli/src/app.rs`.
  /// `startSync` is deferred to the end of the batch rather than acted on
  /// where it appears: it immediately sends a sync `Hello` at the *next*
  /// pairing-AEAD counter, so any `sendFrame` later in the same batch
  /// (e.g. the new device's `Done`, which follows `startSync` in the
  /// Admit-processing command list) must reach the wire first — otherwise
  /// the peer receives frames out of counter order and rejects the
  /// earlier one as undecryptable.
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
        surfaceApprovalPrompt: (deviceName, did) async {
          if (_generation != gen) return;
          _pendingDeviceName = deviceName;
          _pendingDid = did;
          if (autoApprove) {
            await approvePending();
          } else {
            onApprovalPending?.call();
          }
        },
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
        complete: () async {
          if (_generation != gen) return;
          moatLog('PairingService: pairing-sync session complete — closing pair WS');
          _pairingSyncSession = null;
          _pairingSyncKeyNewToOld = null;
          _pairingSyncKeyOldToNew = null;
          // This pairing is fully done, including its sync handoff. Clear
          // the role flag now — otherwise a later, unrelated pair session
          // (an established-devices reconnect sync) would still route
          // through this service's own handlers instead of falling
          // through to `SyncService`/`DeviceRingService`.
          _isNewDevice = null;
          await _drawbridge.clearPair();
          _releasePairCallbacks();
        },
      );
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
  /// [ffi.pairingOpenFrame] succeeds is unrecoverable and aborts instead of
  /// returning silently, so a corrupt/out-of-order frame produces a clear
  /// stall (`isDone` never flips) rather than a permanently wedged session
  /// that looks alive.
  Future<void> _processPairingSyncFrame(Uint8List data) async {
    final gen = _generation;
    final key = _isNewDevice == true ? _pairingSyncKeyOldToNew : _pairingSyncKeyNewToOld;
    final did = _auth.did;
    final syncSession = _pairingSyncSession;
    if (key == null || did == null || syncSession == null) return;

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
      await _abort();
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
      outputs = await syncSession.onMessage(msgBytes: plaintext, ourDid: did);
    } catch (e) {
      moatLog('PairingService: pairing-sync onMessage failed: $e — aborting');
      await _abort();
      return;
    }
    if (_generation != gen) return;
    await _processPairingSyncOutputs(outputs, gen);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  Future<void> _abort() async {
    _generation++;
    _session = null;
    _isNewDevice = null;
    _pendingDeviceName = null;
    _pendingDid = null;
    _pendingCode = null;
    _pendingUri = null;
    _pairingSyncSession = null;
    _pairingSyncKeyNewToOld = null;
    _pairingSyncKeyOldToNew = null;
    _frameQueue = Future.value();
    await _drawbridge.clearPair();
    _drawbridge.clearPendingPairRendezvous();
    _releasePairCallbacks();
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
