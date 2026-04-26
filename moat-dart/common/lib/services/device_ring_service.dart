import 'dart:async';
import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
import 'auth_service.dart';
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
    final ownEvents = (await _safe(() async {
          final cursor = driver.ownEventsCursor();
          return client.fetchEvents(did, afterRkey: cursor);
        })) ??
        [];

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
      syncSessionActive: false, // SyncService updates this in its own tick path
    );

    final cmds = await driver.tick(session: session, inputs: inputs);
    await _persist();
    await _interpret(cmds, did);
  }

  /// Handle an incoming coord-group message (already decrypted; payload is
  /// the JSON from `CoordMsg`).
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
          },
          stealthPublishWelcome: (tag, ciphertext) async {
            await client.publishEvent(tag, ciphertext);
          },
          replenishKeyPackage: () async {
            await _replenishKeyPackage();
          },
          registerGroup: (groupId, kind) async {
            // No-op for now: candidate tags are populated lazily via the
            // session when the polling service watches them. Future work:
            // notify ConversationManager to surface coord-group rings.
          },
          sendDrawbridgePairOffer: (token) async {
            _pendingPairToken = token;
            _drawbridge.sendPairOffer(token);
          },
          sendDrawbridgePairJoin: (token) async {
            _pendingPairToken = token;
            _drawbridge.sendPairJoin(token);
          },
          pollForNewDevices: () async {
            // Triggered when the ring grew; the polling service will pick up
            // new sibling stealth records on its next pass.
          },
        );
      } catch (e, st) {
        moatLog('DeviceRingService: command failed ($cmd): $e\n$st');
      }
    }
  }

  Future<void> _replenishKeyPackage() async {
    // moat-core's `MoatSession::replenish_key_package` is not yet exposed via
    // FFI. Until it is, log the request so the gap is visible in tests; the
    // Rust-side ring already replenishes on its own ticks.
    moatLog('DeviceRingService: replenish requested (FFI not yet wired)');
  }

  void _handlePairReady(DrawbridgePairReady ready) {
    // The /pair WS handshake itself is owned by SyncService, which subscribes
    // to onPairConnected / onPairFrame. We only need to forward the connect.
    _drawbridge.connectPair(ready.pairUrl, ready.token);
  }

  Future<void> _persist() async {
    final driver = _driver;
    if (driver == null) return;
    try {
      final json = await driver.toStateJson();
      await _backend.write(_statePath, json);
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
}
