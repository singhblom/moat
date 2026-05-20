import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../models/conversation.dart';
import '../rust/api/simple.dart' as ffi;
import '../utils/welcome_envelope.dart';
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

  /// Tags published by this device (mark_own=true) that the polling service
  /// must skip to avoid self-processing ring-group coord events (e.g. SyncOffer).
  final Set<String> _ownPublishedTagHexes = {};

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
      } catch (e) {
        moatLog('DeviceRingService: ring state corrupt, starting empty: $e');
        _driver = ffi.RingDriverHandle.newEmpty();
      }
    } else {
      _driver = ffi.RingDriverHandle.newEmpty();
    }
  }

  /// Returns the ring group id if the device is enrolled.
  Future<Uint8List?> ringGroupId() async {
    final d = _driver;
    if (d == null) return null;
    return d.ringGroupId();
  }

  /// Number of active coord groups (one per discovered sibling device).
  ///
  /// Updated after every [tick] from the persisted state JSON.
  int coordGroupCount() => _coordGroupCount;

  /// The rkey cursor up to which the ring driver has consumed own-DID events.
  ///
  /// The polling service uses this to skip events already processed by the ring
  /// driver (coord-group Welcomes) so they are not misrouted as conversation
  /// Welcomes.
  String? ownEventsCursor() {
    final d = _driver;
    if (d == null) return null;
    return d.ownEventsCursor();
  }

  /// Drive one ring tick.
  Future<void> tick() async {
    if (_tickInFlight) return;
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
    moatLog('DeviceRingService: tick cursor=$cursorBefore ownEvents=${ownEvents.map((e) => e.rkey).toList()} keyPackages=${keyPackages.length}');

    final inputs = ffi.TickInputsDto(
      keyPackages: keyPackages.map((kp) => kp.keyPackage).toList(),
      stealthPubkeys: stealthRecords.map((r) => r.scanPubkey).toList(),
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
      nowMs: DateTime.now().millisecondsSinceEpoch,
      drawbridgeHasOwnConnection: _drawbridge.isOwnConnected,
      syncSessionActive: isSyncActive(),
    );

    final cmds = await driver.tick(session: session, inputs: inputs);
    moatLog('DeviceRingService: tick done cursor=${driver.ownEventsCursor()} cmds=${cmds.map((c) => c.runtimeType).toList()}');
    await _persist();
    await _interpret(cmds, did);
  }

  /// Handle an incoming coord-group message (already decrypted; payload is
  /// the JSON from `CoordMsg`).
  /// Called when a coord-group Welcome was consumed by `_pollOwnDid` before
  /// ring_tick had a chance to process it.  Registers the coord group in the
  /// ring driver and publishes Hello so the sibling can exchange hellos.
  Future<void> notifyCoordGroupJoined(Uint8List groupId) async {
    final session = _auth.moatSession;
    final did = _auth.did;
    final driver = _driver;
    if (session == null || did == null || driver == null) return;
    final keyBundle = await _auth.secureStorage.loadKeyBundle();
    if (keyBundle == null) return;
    try {
      final cmds = await driver.notifyCoordGroupJoined(
        session: session,
        groupId: groupId,
        keyBundle: keyBundle,
        myDid: did,
      );
      await _persist();
      await _interpret(cmds, did);
    } catch (e) {
      moatLog('DeviceRingService: notifyCoordGroupJoined failed: $e');
    }
  }

  Future<void> handleCoordMsg({
    required Uint8List groupId,
    required Uint8List payload,
  }) async {
    final session = _auth.moatSession;
    final did = _auth.did;
    final driver = _driver;
    if (session == null || did == null || driver == null) {
      moatLog('DeviceRingService: handleCoordMsg skipped — not ready');
      return;
    }
    try {
      final cmds = await driver.handleCoordMsg(
        session: session,
        myDid: did,
        groupId: groupId,
        payload: payload,
      );
      await _persist();
      await _interpret(cmds, did);
    } catch (e, st) {
      moatLog('DeviceRingService: handleCoordMsg failed: $e\n$st');
    }
  }

  Future<void> _interpret(List<ffi.RingCommandDto> cmds, String did) async {
    final client = _auth.atprotoClient;
    for (final cmd in cmds) {
      try {
        await cmd.when(
          publishEvent: (tag, ciphertext, markOwn) async {
            await client.publishEvent(tag, ciphertext);
            if (markOwn) {
              final tagHex =
                  tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
              _ownPublishedTagHexes.add(tagHex);
            }
          },
          stealthPublishWelcome: (tag, ciphertext) async {
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
          sendDrawbridgePairOffer: (token) async {
            _pendingPairToken = token;
            _drawbridge.sendPairOffer(token);
          },
          sendDrawbridgePairJoin: (token) async {
            moatLog('DeviceRingService: SendDrawbridgePairJoin received, forwarding to Drawbridge');
            _pendingPairToken = token;
            _drawbridge.sendPairJoin(token);
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
    if (cs.findByGroupId(groupId.toList()) != null) return;
    final session = _auth.moatSession;
    if (session == null) return;
    try {
      final allDids =
          await session.getGroupDids(groupId: groupId.toList());
      final participants =
          allDids.where((d) => d != myDid).toList();
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
  /// conversations.  Dart equivalent of Rust's poll_for_new_devices.
  Future<void> _pollForNewDevices(String myDid) async {
    final cs = convsService;
    if (cs == null) {
      moatLog('DeviceRingService: pollForNewDevices — no convsService');
      return;
    }
    final session = _auth.moatSession;
    if (session == null) return;
    final client = _auth.atprotoClient;
    final keyBundle = await _auth.getKeyBundle();
    if (keyBundle == null) return;

    // Fetch all key packages for our own DID (all our devices).
    final keyPackageRecords = await client.fetchKeyPackages(myDid);
    if (keyPackageRecords.isEmpty) return;

    // Sort newest-first so we prefer replenished packages over consumed ones.
    final sorted = List.of(keyPackageRecords)
      ..sort((a, b) => b.createdAt.compareTo(a.createdAt));

    final stealthRecords = await client.fetchStealthAddresses(myDid);
    final stealthPubkeys = stealthRecords.map((r) => r.scanPubkey).toList();
    if (stealthPubkeys.isEmpty) {
      moatLog('DeviceRingService: pollForNewDevices — no stealth addresses');
      return;
    }

    for (final conv in cs.conversations) {
      final groupId = conv.groupId;
      final groupIdHex = conv.groupIdHex;

      // Collect existing (did, deviceId) pairs for this group.
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

      for (final kpRecord in sorted) {
        final rawKp = kpRecord.keyPackage;
        ffi.CredentialDto? cred;
        try {
          cred = await session
              .extractCredentialFromKeyPackage(keyPackage: rawKp);
        } catch (_) {}
        if (cred == null) continue;
        if (cred.did != myDid) continue;
        final deviceIdKey = cred.deviceId.join(',');
        if (existingDeviceIds.contains(deviceIdKey)) continue;

        // Compute pre-epoch commit tag.
        final commitTag = ffi.deriveNextTag(
          handle: session,
          groupId: groupId.toList(),
          keyBundle: keyBundle,
        );

        // Add device to group.
        ffi.WelcomeResultDto welcomeResult;
        try {
          welcomeResult = await session.addMember(
            groupId: groupId.toList(),
            keyBundle: keyBundle,
            newMemberKeyPackage: rawKp,
          );
        } catch (e) {
          moatLog(
              'DeviceRingService: pollForNewDevices addMember failed: $e');
          continue;
        }

        existingDeviceIds.add(deviceIdKey);
        await _auth.saveMlsState();
        await _auth.populateConversationTags(Uint8List.fromList(groupId));

        // Publish commit.
        try {
          await client.publishEvent(commitTag, welcomeResult.commit);
        } catch (e) {
          moatLog(
              'DeviceRingService: pollForNewDevices publish commit failed: $e');
        }

        // Publish stealth-encrypted Welcome.
        final envelope = encodeWelcomeEnvelope(welcomeResult.welcome);
        try {
          final ct = await ffi.encryptForStealth(
            recipientScanPubkeys: stealthPubkeys,
            welcomeBytes: envelope,
          );
          final rng = Random.secure();
          final randomTag =
              Uint8List.fromList(List.generate(16, (_) => rng.nextInt(256)));
          await client.publishEvent(randomTag, ct);
          moatLog(
              'DeviceRingService: pollForNewDevices added device ${cred.deviceName} to $groupIdHex');
        } catch (e) {
          moatLog(
              'DeviceRingService: pollForNewDevices publish welcome failed: $e');
        }
      }
    }
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
      try {
        final state = jsonDecode(jsonStr) as Map<String, dynamic>;
        final cg = state['coord_groups'];
        if (cg is Map) _coordGroupCount = cg.length;
      } catch (_) {
        // Non-fatal: count stays at previous value.
      }
    } catch (e) {
      moatLog('DeviceRingService: persist failed: $e');
    }
  }

  /// Returns true if [tag] was published by this device (mark_own=true) and
  /// should be skipped during message polling to avoid self-processing.
  bool isOwnPublishedTag(List<int> tag) {
    final hex = tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return _ownPublishedTagHexes.contains(hex);
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
}
