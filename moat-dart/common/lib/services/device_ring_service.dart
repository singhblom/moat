import 'dart:async';
import 'dart:typed_data';

import '../models/conversation.dart';
import '../rust/api/simple.dart' as ffi;
import '../utils/platform_int64.dart';
import 'auth_service.dart';
import 'conversations_service.dart';
import 'debug_log.dart';
import 'document_backend.dart';
import 'drawbridge_service.dart';

/// Owns a [ffi.RingDriverHandle] and drives the moat-core ring state machine.
///
/// Dart-side analogue of `App::ring_tick_inner` in `crates/moat-cli/src/app.rs`:
/// gathers inputs from the host (PDS records, key bundle, stealth privkey),
/// hands them to [ffi.RingDriverHandle.tick], and interprets the returned
/// [ffi.RingCommandDto]s as side effects (PDS publish, push offer, …).
///
/// Persists ring state via [DocumentBackend] under [_statePath] as JSON. The
/// ring driver itself is opaque on the Dart side — we only round-trip the
/// blob.
class DeviceRingService {
  static const String _statePath = 'device_ring/ring_state.json';

  final AuthService _auth;
  final DrawbridgeService _drawbridge;
  final DocumentBackend _backend;

  ffi.RingDriverHandle? _driver;
  bool _tickInFlight = false;
  Uint8List? _pendingPairToken;
  int _coordGroupCount = 0;

  /// Last tick's sibling stealth addresses, kept so KP-lane calls outside
  /// `tick()` (e.g. [emitKpRequestFor], [encryptUserConvWelcome] in
  /// `_pollForNewDevices`) can stealth-address a sibling without re-fetching.
  /// Mirrors moat-cli's `App.cached_sibling_stealth`; a one-tick-stale cache
  /// is fine because a skipped send self-heals via the consumer-driven
  /// KpRequest refill.
  List<ffi.SiblingStealthDto> _cachedSiblingStealth = const [];

  /// Read-only view of the cached sibling stealth addresses — used by
  /// `PairingService` to assemble `known_siblings` for `approve()`
  /// (`Admit.roster` needs every already-known sibling's stealth key,
  /// which lives here, not in MLS group state).
  List<ffi.SiblingStealthDto> get cachedSiblingStealth => _cachedSiblingStealth;

  /// Upsert one sibling's stealth address into the cache — used by
  /// `PairingService` to record a newcomer's stealth key (from its
  /// `Enroll`) or a roster entry (from a processed `Admit`) immediately,
  /// without waiting for the next `tick()`'s `stealthAddress`-record fetch.
  void upsertSiblingStealth(Uint8List deviceId, Uint8List scanPubkey) {
    final idx = _cachedSiblingStealth
        .indexWhere((s) => _bytesEqual(s.deviceId, deviceId));
    final entry = ffi.SiblingStealthDto(scanPubkey: scanPubkey, deviceId: deviceId);
    if (idx >= 0) {
      final updated = List<ffi.SiblingStealthDto>.from(_cachedSiblingStealth);
      updated[idx] = entry;
      _cachedSiblingStealth = updated;
    } else {
      _cachedSiblingStealth = [..._cachedSiblingStealth, entry];
    }
  }

  /// Injected by the server/app setup so pollForNewDevices and registerGroup
  /// for User groups can surface conversations.
  ConversationsService? convsService;

  /// Injected by the owner (e.g. ConversationManager) so the ring tick can
  /// suppress a new SyncOffer while a sync session is already in progress.
  bool Function() isSyncActive = () => false;

  /// True once a pair WS is in-flight (offer sent or join sent + ready received).
  bool get hasPendingPairToken => _pendingPairToken != null;

  DeviceRingService({
    required AuthService auth,
    required DrawbridgeService drawbridge,
    required DocumentBackend backend,
  })  : _auth = auth,
        _drawbridge = drawbridge,
        _backend = backend {
    reclaimPairReadyCallback();
  }

  /// (Re-)claim `DrawbridgeService.onPairReady`. Normally only needed once,
  /// from the constructor — exposed as a public method so `PairingService`
  /// can hand this callback slot back after a live pairing exchange
  /// (which needs it too, for its own rendezvous) completes or aborts.
  void reclaimPairReadyCallback() {
    _drawbridge.onPairReady = _handlePairReady;
  }

  /// Load persisted state (or start empty) and prime the driver.
  Future<void> init() async {
    if (_driver != null) return;
    String? json;
    try {
      json = await _backend.read(_statePath);
    } catch (e) {
      moatLog('DeviceRingService: failed to read $_statePath: $e');
    }
    if (json != null && json.isNotEmpty) {
      try {
        _driver = await ffi.RingDriverHandle.fromStateJson(json: json);
        _coordGroupCount = _countCoordGroupsFromJson(json);
      } catch (e) {
        moatLog('DeviceRingService: ring state corrupt, starting empty: $e');
        _driver = ffi.RingDriverHandle.newEmpty();
      }
    } else {
      _driver = ffi.RingDriverHandle.newEmpty();
    }
  }

  /// Always 0. There is no device-coordination-group concept in the ring
  /// driver; kept as a stable field for `coordGroupCount()`, surfaced in
  /// `server/lib/http/server.dart`'s `/ring-status`. Mirrors
  /// `DeviceRingState::coord_group_count` on the Rust side.
  static int _countCoordGroupsFromJson(String jsonStr) => 0;

  /// Returns the ring group id if the device is enrolled.
  Future<Uint8List?> ringGroupId() async {
    final d = _driver;
    if (d == null) return null;
    return d.ringGroupId();
  }

  /// Always 0 — a stable field on `/ring-status` responses.
  int coordGroupCount() => _coordGroupCount;

  /// Allocate `count` fresh, monotonic KP sequence numbers from this
  /// device's own owner-global counter, persisting the advanced counter
  /// immediately. Used by `PairingService.startEnroll` to build
  /// `Enroll.conv_kps` — must go through the driver's own counter (not a
  /// caller-local one) so seqs never collide with ones allocated elsewhere.
  Future<List<BigInt>> allocateKpSeqs(int count) async {
    final d = _driver;
    if (d == null) return const [];
    final seqs = d.allocateKpSeqs(count: BigInt.from(count));
    await _persist();
    return seqs;
  }

  /// Seed `ownerDeviceId`'s consumer-side pool with a freshly-received
  /// batch — called by `PairingService` (existing device, on Approve)
  /// with the newcomer's `Enroll.conv_kps`.
  Future<void> ingestKpBatch(Uint8List ownerDeviceId, List<ffi.OfferedKpDto> kps) async {
    final d = _driver;
    if (d == null) return;
    try {
      d.ingestKpBatch(ownerDeviceId: ownerDeviceId, kps: kps);
    } catch (e) {
      moatLog('DeviceRingService: ingestKpBatch failed: $e');
    }
    await _persist();
  }

  /// Record that we are now an MLS member of `ringId`, persisting
  /// immediately. Called by `PairingService` once on the new device (after
  /// processing `Admit`) and once on the existing device (right after a
  /// successful `approve()`, first pairing only — see the note on why the
  /// existing device has no command of its own for this).
  Future<void> recordRingMembership(Uint8List ringId) async {
    final d = _driver;
    final session = _auth.moatSession;
    if (d == null || session == null) return;
    final nowMs = toPlatformInt64(DateTime.now().millisecondsSinceEpoch);
    try {
      await d.recordRingMembership(session: session, ringId: ringId, nowMs: nowMs);
    } catch (e) {
      moatLog('DeviceRingService: recordRingMembership failed: $e');
    }
    await _persist();
  }

  /// The rkey cursor up to which the ring driver has consumed own-DID events.
  ///
  /// The polling service uses this to skip events already processed by the
  /// ring driver (same-user key-package-lane SiblingMsg payloads) so they
  /// are not misrouted as conversation Welcomes.
  String? ownEventsCursor() {
    final d = _driver;
    if (d == null) return null;
    return d.ownEventsCursor();
  }

  /// Throws if required properties have not been injected.
  ///
  /// Called at the start of [tick] so a missing injection fails loudly
  /// instead of silently skipping fan-out and group registration.
  void assertReady() {
    if (convsService == null) {
      throw StateError(
        'DeviceRingService.convsService is null — '
        'set it before the first tick (use createServiceBundle)',
      );
    }
  }

  /// Drive one ring tick.
  Future<void> tick() async {
    if (_tickInFlight) return;
    assertReady();
    _tickInFlight = true;
    try {
      await _tickInner();
    } catch (e, st) {
      moatLog('DeviceRingService: tick failed: $e\n$st');
    } finally {
      _tickInFlight = false;
    }
  }

  Future<void> _tickInner() async {
    final session = _auth.moatSession;
    final did = _auth.did;
    final deviceName = _auth.deviceName;
    if (session == null || did == null || deviceName == null) {
      moatLog('DeviceRingService: tick skipped — auth not ready');
      return;
    }
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    final stealthPriv = await _auth.secureStorage.loadStealthPrivateKey();
    if (keyBundle == null || stealthPriv == null) {
      moatLog('DeviceRingService: tick skipped — missing key material');
      return;
    }

    final driver = _driver;
    if (driver == null) {
      moatLog('DeviceRingService: tick before init()');
      return;
    }

    final client = _auth.atprotoClient;

    final keyPackages =
        (await _safe(() => client.fetchKeyPackages(did))) ?? [];
    final stealthRecords =
        (await _safe(() => client.fetchStealthAddresses(did))) ?? [];
    final cursorBefore = driver.ownEventsCursor();
    final ownEvents = (await _safe(() async {
          return client.fetchEvents(did, afterRkey: cursorBefore);
        })) ??
        [];
    // Sibling stealth addressing: every stealth record under our own DID
    // except our own device.  Pre-v3 records decode with an all-zero
    // deviceId and are unusable as a routing key, so drop them too.
    final myDeviceId = session.deviceId();
    final siblingStealth = stealthRecords
        .where((r) =>
            !_bytesEqual(r.deviceId, myDeviceId) && !_isAllZero(r.deviceId))
        .map((r) => ffi.SiblingStealthDto(
              scanPubkey: r.scanPubkey,
              deviceId: r.deviceId,
            ))
        .toList();
    _cachedSiblingStealth = siblingStealth;

    // Classify the pool exactly as the driver will, so the log answers "did
    // the driver see any siblings at all?" directly. A ring that never forms
    // because the pool held nothing but our own packages is otherwise
    // indistinguishable, from artifacts alone, from a state-machine failure.
    var kpMine = 0, kpSiblings = 0, kpForeign = 0, kpUnreadable = 0;
    final siblingIds = <String>[];
    for (final kp in keyPackages) {
      try {
        final cred = await session.extractCredentialFromKeyPackage(
          keyPackage: kp.keyPackage,
        );
        if (cred == null) {
          kpUnreadable++;
        } else if (cred.did != did) {
          kpForeign++;
        } else if (_bytesEqual(cred.deviceId, myDeviceId)) {
          kpMine++;
        } else {
          kpSiblings++;
          final id = _hex(cred.deviceId.sublist(0, 4));
          if (!siblingIds.contains(id)) siblingIds.add(id);
        }
      } catch (_) {
        kpUnreadable++;
      }
    }

    moatLog(
      'DeviceRingService: tick in  kp=${keyPackages.length} '
      '(mine=$kpMine siblings=$kpSiblings foreign=$kpForeign unreadable=$kpUnreadable) '
      'sibling_ids=[${siblingIds.join(",")}] stealth=${stealthRecords.length} '
      'sibling_stealth=${siblingStealth.length} own_events=${ownEvents.length} '
      'host_cursor=$cursorBefore | ${driver.debugSummary()}',
    );

    final inputs = ffi.TickInputsDto(
      keyPackages: keyPackages.map((kp) => kp.keyPackage).toList(),
      siblingStealth: siblingStealth,
      ownEvents: ownEvents
          .map((e) => ffi.OwnEventInputDto(
                rkey: e.rkey,
                ciphertext: e.ciphertext,
              ))
          .toList(),
      stealthPrivkey: stealthPriv,
      did: did,
      deviceName: deviceName,
      keyBundle: keyBundle,
      nowMs: toPlatformInt64(DateTime.now().millisecondsSinceEpoch),
    );

    final cmds = await driver.tick(session: session, inputs: inputs);
    moatLog( 
      'DeviceRingService: tick out cmds=[${_summarizeCmds(cmds)}] '
      '| ${driver.debugSummary()}',
    );
    await _persist();
    await _interpret(cmds, did);
  }

  Future<void> _interpret(List<ffi.RingCommandDto> cmds, String did) async {
    final client = _auth.atprotoClient;
    for (final cmd in cmds) {
      try {
        await cmd.when(
          // Stealth-addressed sibling payload (KpBatch/KpRequest/UserConvWelcome).
          // The host just publishes the ciphertext under the supplied tag;
          // the recipient decrypts it out-of-band, so it is not marked own.
          publishStealthEvent: (tag, ciphertext) async {
            await client.publishEvent(tag, ciphertext);
          },
          replenishKeyPackage: () async {
            await _replenishKeyPackage();
          },
          registerGroup: (groupId, kind) async {
            // Always register tags for routing coord messages.
            await _auth.populateConversationTags(Uint8List.fromList(groupId));
            // For User conversations found via ring_tick step-3 stealth Welcome
            // scan, surface them in ConversationsService (the normal poll path
            // would fail because the Welcome was already consumed above).
            if (kind == ffi.GroupKindDto.user) {
              await _registerUserGroup(Uint8List.fromList(groupId), did);
            }
          },
          pollForNewDevices: () async {
            await _pollForNewDevices(did);
          },
        );
      } catch (e, st) {
        moatLog('DeviceRingService: command failed ($cmd): $e\n$st');
      }
    }
  }

  Future<void> _replenishKeyPackage() async {
    // After joining a coord group, the key package init key is consumed. A
    // fresh key package is needed so the ring creator can add this device.
    try {
      await _auth.replenishKeyPackage();
      moatLog('DeviceRingService: key package replenished');
    } catch (e) {
      moatLog('DeviceRingService: replenish failed: $e');
    }
  }

  /// Add a User conversation discovered via ring_tick step-3 Welcome scan to
  /// ConversationsService so it appears in list_conversations.
  Future<void> _registerUserGroup(Uint8List groupId, String myDid) async {
    final cs = convsService;
    if (cs == null) return;
    final groupIdHex =
        groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final existing = cs.findByGroupId(groupId.toList());
    // Already a member: nothing to do — and in particular do not rewrite
    // its participants, which would replace resolved handles with bare
    // DIDs. Present but read-only means its history arrived by sync
    // before this Add, and *this* is the moment it stops being read-only,
    // so that case falls through rather than returning.
    if (existing != null && existing.isMember) return;
    final session = _auth.moatSession;
    if (session == null) return;
    try {
      final allDids =
          await session.getGroupDids(groupId: groupId.toList());
      final participants =
          allDids.where((d) => d != myDid).toList();
      if (existing != null) {
        // Participants become knowable from MLS here, where the
        // read-only registration could only infer them from senders.
        existing.isMember = true;
        existing.participants
          ..clear()
          ..addAll(participants);
        await cs.saveConversation(existing);
        moatLog(
            'DeviceRingService: $groupIdHex is no longer read-only — Add arrived');
        await _replenishKeyPackage();
        return;
      }
      final conv = Conversation(
        groupId: groupId,
        participants: participants,
        epoch: 1,
        keyBundleRef: 'key_bundle_$groupIdHex',
        createdAt: DateTime.now(),
      );
      await cs.saveConversation(conv);
      moatLog(
          'DeviceRingService: registered user group $groupIdHex from ring_tick');
      // Replenish init key consumed by this Welcome.
      await _replenishKeyPackage();
    } catch (e) {
      moatLog('DeviceRingService: _registerUserGroup failed: $e');
    }
  }

  /// Add sibling devices (same DID, different device_id) to all user
  /// conversations.  Dart equivalent of Rust's `poll_for_new_devices`.
  ///
  /// Same-user fan-out: walk every confirmed ring sibling, and for each user
  /// conversation they are not yet in, draw a KP from the same-user pool,
  /// MLS-add them, and ship the Welcome as a `CoordMsg::UserConvWelcome`
  /// stealth event addressed to that sibling.  If the pool is drained we emit
  /// one `KpRequest` per sibling per cycle and defer the add; the next poll
  /// retries once a `KpBatch` arrives.  The init key consumed comes from the
  /// KP-lane pool, not the shared `social.moat.keyPackage` pool, so no
  /// cross-user replenish is required.
  Future<void> _pollForNewDevices(String myDid) async {
    final cs = convsService;
    if (cs == null) {
      moatLog('DeviceRingService: pollForNewDevices — no convsService');
      return;
    }
    final session = _auth.moatSession;
    final driver = _driver;
    if (session == null || driver == null) return;
    final client = _auth.atprotoClient;
    final keyBundle = await _auth.getKeyBundle();
    if (keyBundle == null) return;

    // No ring → no KP pool → nothing to fan out.  Bootstrap and ring
    // formation happen elsewhere; we wait for them.
    if (driver.ringGroupId() == null) return;

    final siblings = driver.ringJoinedSiblings(session: session);
    if (siblings.isEmpty) return;

    final siblingStealth = _cachedSiblingStealth;

    // At most one KpRequest per sibling per cycle — without this, fan-out
    // across N conversations with an empty pool emits N redundant requests.
    final requestedRefill = <String>{};

    for (final conv in cs.conversations) {
      final groupId = conv.groupId;
      final groupIdHex = conv.groupIdHex;

      final List<ffi.CredentialDto> existingCreds;
      try {
        existingCreds = await session.getGroupMemberCredentials(
            groupId: groupId.toList());
      } catch (e) {
        moatLog(
            'DeviceRingService: pollForNewDevices getGroupMemberCredentials failed: $e');
        continue;
      }

      final existingDeviceIds =
          existingCreds.map((c) => c.deviceId.join(',')).toSet();

      for (final siblingId in siblings) {
        final siblingKey = siblingId.join(',');
        if (existingDeviceIds.contains(siblingKey)) continue;

        // Pool claim.  null ⇒ drained; request a refill and defer.
        final ffi.OfferedKpDto? kp;
        try {
          kp = driver.claimKp(ownerDeviceId: Uint8List.fromList(siblingId));
        } catch (e) {
          moatLog('DeviceRingService: pollForNewDevices claimKp failed: $e');
          continue;
        }
        if (kp == null) {
          if (requestedRefill.add(siblingKey)) {
            try {
              final cmds = await driver.emitKpRequestFor(
                session: session,
                myDid: myDid,
                keyBundle: keyBundle,
                siblingStealth: siblingStealth,
                ownerDeviceId: Uint8List.fromList(siblingId),
              );
              await _interpret(cmds, myDid);
              moatLog(
                  'DeviceRingService: pollForNewDevices KP pool empty for sibling $siblingKey; emitted KpRequest, deferring');
            } catch (e) {
              moatLog(
                  'DeviceRingService: pollForNewDevices emitKpRequestFor failed: $e');
            }
          }
          continue;
        }

        final ffi.WelcomeResultDto welcomeResult;
        try {
          welcomeResult = await session.addMember(
            groupId: groupId.toList(),
            keyBundle: keyBundle,
            newMemberKeyPackage: kp.keyPackage,
          );
        } catch (e) {
          moatLog('DeviceRingService: pollForNewDevices addMember failed: $e');
          continue;
        }

        existingDeviceIds.add(siblingKey);
        await _auth.saveMlsState();
        await _auth.populateConversationTags(Uint8List.fromList(groupId));

        // Publish the commit so cross-user members of this group see it.
        try {
          await client.publishEvent(welcomeResult.commitTag, welcomeResult.commit);
        } catch (e) {
          moatLog(
              'DeviceRingService: pollForNewDevices publish commit failed: $e');
        }

        // Stealth-addressed Welcome, same lane as bootstrap KPs.
        try {
          final cmd = await driver.encryptUserConvWelcome(
            session: session,
            myDid: myDid,
            keyBundle: keyBundle,
            siblingStealth: siblingStealth,
            ownerDeviceId: Uint8List.fromList(siblingId),
            groupId: groupId.toList(),
            welcome: welcomeResult.welcome,
          );
          if (cmd == null) {
            moatLog(
                'DeviceRingService: pollForNewDevices UserConvWelcome skipped — sibling $siblingKey stealth record not yet known');
          } else {
            await _interpret([cmd], myDid);
            moatLog(
                'DeviceRingService: pollForNewDevices added sibling $siblingKey to $groupIdHex');
          }
        } catch (e) {
          moatLog(
              'DeviceRingService: pollForNewDevices publish welcome failed: $e');
        }
      }
    }
    await _persist();
  }

  void _handlePairReady(DrawbridgePairReady ready) {
    moatLog('DeviceRingService: pair_ready received, connecting pair WS at ${ready.pairUrl}');
    // The /pair WS handshake itself is owned by SyncService, which subscribes
    // to onPairConnected / onPairFrame. We only need to forward the connect.
    _drawbridge.connectPair(ready.pairUrl, ready.token);
  }

  Future<void> _persist() async {
    final driver = _driver;
    if (driver == null) return;
    try {
      final jsonStr = await driver.toStateJson();
      await _backend.write(_statePath, jsonStr);
      // Cache the coord_group count from the state JSON so coordGroupCount()
      // can be synchronous (avoids re-serialising on every /ring-status call).
      _coordGroupCount = _countCoordGroupsFromJson(jsonStr);
    } catch (e) {
      moatLog('DeviceRingService: persist failed: $e');
    }
  }

  /// Drop any pending pair-WS state — used when sync ends or aborts.
  void clearPendingPair() {
    _pendingPairToken = null;
  }

  Future<void> dispose() async {
    _drawbridge.onPairReady = null;
    _pendingPairToken = null;
    _driver = null;
  }

  Future<T?> _safe<T>(Future<T> Function() body) async {
    try {
      return await body();
    } catch (e) {
      moatLog('DeviceRingService: gather input failed: $e');
      return null;
    }
  }

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  /// `name xN, name xM` — mirrors moat-core's `summarize_ring_commands` so a
  /// mixed-runtime failure produces comparable lines from both hosts.
  static String _summarizeCmds(List<ffi.RingCommandDto> cmds) {
    if (cmds.isEmpty) return 'none';
    final counts = <String, int>{};
    for (final c in cmds) {
      // freezed generates `_$PublishEventImpl` for `RingCommandDto_PublishEvent`;
      // strip both decorations so the line matches moat-core's rendering.
      final name = c.runtimeType
          .toString()
          .replaceFirst(r'_$', '')
          .replaceFirst('RingCommandDto_', '')
          .replaceFirst(RegExp(r'Impl$'), '');
      counts[name] = (counts[name] ?? 0) + 1;
    }
    return counts.entries
        .map((e) => e.value == 1 ? e.key : '${e.key} x${e.value}')
        .join(', ');
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static bool _isAllZero(Uint8List b) => b.every((byte) => byte == 0);
}
