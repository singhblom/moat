import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:web_socket_channel/status.dart' as ws_status;
import 'package:web_socket_channel/web_socket_channel.dart';
import '../rust/api/simple.dart' as ffi;
import 'atproto_client.dart';
import 'debug_log.dart';
import 'rendezvous_connection.dart';

/// No dart:ui dependency — VoidCallback defined here.
typedef VoidCallback = void Function();

/// Drawbridge relay this build was made for, from
/// `--dart-define=MOAT_DRAWBRIDGE_URL=...`. Empty means no relay.
const buildDrawbridgeUrl = String.fromEnvironment('MOAT_DRAWBRIDGE_URL');

/// moat-core's `PAIR_CLOSE_GRACE`, read once the Rust library is loaded.
final pairCloseGrace = Duration(milliseconds: ffi.pairCloseGraceMs());

/// [url] in the one form moat-core dials, signs and compares, or null if it
/// is not a Drawbridge URL. Every Drawbridge URL this library holds is in
/// that form, so two of them name one Drawbridge exactly when they are equal.
String? normalizedDrawbridgeUrl(String url) {
  try {
    return ffi.normalizeDrawbridgeUrl(url: url);
  } catch (e) {
    moatLog('Drawbridge URL $url is unusable: $e');
    return null;
  }
}

/// Event received from own Drawbridge relay via WebSocket.
class DrawbridgeNewEvent {
  final String tagHex;
  final String rkey;

  /// Base64-decoded ciphertext payload, if piped through the relay.
  final Uint8List? payload;

  DrawbridgeNewEvent({
    required this.tagHex,
    required this.rkey,
    this.payload,
  });
}

/// Server-side notification that a pair token's matched its peer and the
/// /pair WS is ready to accept attachers.
class DrawbridgePairReady {
  final String pairUrl;
  final Uint8List token;
  DrawbridgePairReady({required this.pairUrl, required this.token});
}

/// Manages the WebSocket connection to the user's own Drawbridge, and
/// while a pairing or sync rendezvous is live on another Drawbridge, a
/// [RendezvousConnection] to that one.
///
/// Events and tags go only through the **own** Drawbridge. Sending uses
/// envelope-based fan-out (payload + relay_urls). Receiving uses tag-based
/// routing on the own relay.
class DrawbridgeService {
  static final DrawbridgeService instance = DrawbridgeService._();
  DrawbridgeService._();

  WebSocketChannel? _ownChannel;
  StreamSubscription? _ownSubscription;
  String? _ownUrl;
  bool _ownAuthenticated = false;

  /// Called when own Drawbridge sends a new_event notification.
  void Function(DrawbridgeNewEvent)? onNewEvent;

  /// Called when the relay accepts a `pair_offer` and is waiting for a joiner.
  void Function()? onPairPending;

  /// Called when the relay matches a pair token and emits `pair_ready`.
  void Function(DrawbridgePairReady)? onPairReady;

  /// Called once the /pair WS for `token` reports `paired`.
  void Function(Uint8List token)? onPairConnected;

  /// Called for every binary frame received on the /pair WS for `token`
  /// after `paired`.
  void Function(Uint8List token, Uint8List data)? onPairFrame;

  /// Called when the /pair WS for `token` fails to connect or disconnects
  /// (cleanly or with an error).
  void Function(Uint8List token, String reason)? onPairClosed;

  /// Called each time a Drawbridge we hold a main WS to, our own or a rendezvous
  /// connection's, (re)authenticates, so an offer or join it has not
  /// acknowledged can be resent there.
  void Function(String drawbridgeUrl)? onAuthenticated;

  /// Called when the rendezvous connection to a Drawbridge ends from outside,
  /// having authenticated.
  void Function(String drawbridgeUrl)? onRendezvousClosed;

  /// Called when a rendezvous connection to a Drawbridge ended before it
  /// authenticated: the Drawbridge could not be reached.
  void Function(String drawbridgeUrl, String reason)? onRendezvousUnreachable;

  RendezvousConnection? _rendezvous;

  WebSocketChannel? _pairChannel;
  StreamSubscription? _pairSubscription;
  bool _pairAttached = false;

  Uint8List? _keyBundle;
  String? _did;
  bool _disposed = false;
  Timer? _reconnectTimer;
  int _reconnectAttempts = 0;
  static const _maxReconnectDelay = Duration(seconds: 60);


  /// Tags currently registered on own relay.
  final Set<String> _watchedTagHexes = {};

  /// Push token to register with the relay after authentication.
  String? _pushDeviceId;
  String? _pushToken;
  String? _pushPlatform;

  /// Drawbridge config cache: DID → the relays its devices sit on.
  final Map<String, _CachedConfig> _configCache = {};

  /// How long a DID's relay list is trusted before a poll re-reads it.
  static const configTtl = Duration(seconds: 30);

  void init({
    required String did,
    required Uint8List keyBundle,
  }) {
    _did = did;
    _keyBundle = keyBundle;
    _disposed = false;
  }

  Future<void> connectOwn(String url) async {
    if (_did == null || _keyBundle == null) {
      moatLog('DrawbridgeService: Cannot connect own - not initialized');
      return;
    }

    await _disconnectOwn();

    _ownUrl = url;
    moatLog('DrawbridgeService: Connecting to own relay at $url');

    try {
      final wsUrl = Uri.parse(url);
      _ownChannel = WebSocketChannel.connect(wsUrl);
      await _ownChannel!.ready;

      _ownSubscription = _ownChannel!.stream.listen(
        (data) => _handleOwnMessage(data as String),
        onError: (error) {
          moatLog('DrawbridgeService: Own relay error: $error');
          _ownAuthenticated = false;
          _scheduleReconnect();
        },
        onDone: () {
          moatLog('DrawbridgeService: Own relay disconnected');
          _ownAuthenticated = false;
          _scheduleReconnect();
        },
      );

      _reconnectAttempts = 0;

      _ownChannel!.sink.add(jsonEncode({
        'type': 'request_challenge',
      }));
    } catch (e) {
      moatLog('DrawbridgeService: Failed to connect to own relay: $e');
      _ownAuthenticated = false;
      _scheduleReconnect();
    }
  }

  void _handleOwnMessage(String data) {
    try {
      final msg = jsonDecode(data) as Map<String, dynamic>;
      final type = msg['type'] as String?;

      switch (type) {
        case 'challenge':
          _handleChallenge(msg);
        case 'authenticated':
          moatLog('DrawbridgeService: Own relay authenticated');
          _ownAuthenticated = true;
          _sendWatchedTags();
          _sendPushRegistration();
          final own = _ownUrl;
          if (own != null) onAuthenticated?.call(own);
        case 'new_event':
          _handleNewEvent(msg);
        case 'pair_pending':
          moatLog('DrawbridgeService: pair_pending');
          onPairPending?.call();
        case 'pair_ready':
          _handlePairReady(msg);
        case 'error':
          // Any error on the main WS is treated as connection-fatal, same
          // as `moat-cli`'s client — forces a reconnect cycle so a
          // rendezvous message lost to the pair_offer/pair_join race (the
          // relay doesn't close the socket for this error, it just replies
          // in-band) gets resent once reconnected.
          moatLog('DrawbridgeService: Own relay error: ${msg['message']}');
          _ownAuthenticated = false;
          _scheduleReconnect();
        default:
          moatLog('DrawbridgeService: Unknown own message type: $type');
      }
    } catch (e) {
      moatLog('DrawbridgeService: Error parsing own message: $e');
    }
  }

  Future<void> _handleChallenge(Map<String, dynamic> msg) async {
    final nonce = msg['nonce'] as String?;
    if (nonce == null || _keyBundle == null || _ownUrl == null) {
      moatLog('DrawbridgeService: Cannot handle challenge - missing data');
      return;
    }

    final channelForThisChallenge = _ownChannel;

    final timestamp = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final message = '$nonce\n$_ownUrl\n$timestamp\n';

    try {
      final result = await ffi.signDrawbridgeChallenge(
        keyBundle: _keyBundle!,
        message: Uint8List.fromList(utf8.encode(message)),
      );

      if (_ownChannel != channelForThisChallenge) {
        moatLog('DrawbridgeService: Discarding stale challenge response');
        return;
      }

      final sigB64 = base64Encode(result.signature);
      final pubB64 = base64Encode(result.publicKey);

      _ownChannel?.sink.add(jsonEncode({
        'type': 'challenge_response',
        'did': _did,
        'signature': sigB64,
        'timestamp': timestamp,
        'public_key': pubB64,
      }));
    } catch (e) {
      moatLog('DrawbridgeService: Challenge signing failed: $e');
    }
  }

  void _handleNewEvent(Map<String, dynamic> msg) {
    final tagHex = msg['tag'] as String?;
    final rkey = msg['rkey'] as String?;
    if (tagHex == null || rkey == null) return;

    final payloadB64 = msg['payload'] as String?;
    Uint8List? payload;
    if (payloadB64 != null) {
      try {
        payload = base64Decode(payloadB64);
      } catch (_) {
        moatLog('DrawbridgeService: Failed to decode payload for rkey=$rkey');
      }
    }

    moatLog('DrawbridgeService: new_event tag=$tagHex rkey=$rkey '
        'payload=${payload != null ? "${payload.length}B" : "none"}');

    onNewEvent?.call(DrawbridgeNewEvent(
      tagHex: tagHex,
      rkey: rkey,
      payload: payload,
    ));
  }

  void _handlePairReady(Map<String, dynamic> msg) {
    final pairUrl = msg['pair_url'] as String?;
    final tokenB64 = msg['token'] as String?;
    if (pairUrl == null || tokenB64 == null) {
      moatLog('DrawbridgeService: pair_ready missing fields');
      return;
    }
    final Uint8List token;
    try {
      token = base64Decode(tokenB64);
    } catch (e) {
      moatLog('DrawbridgeService: pair_ready bad token base64: $e');
      return;
    }
    moatLog('DrawbridgeService: pair_ready url=$pairUrl');
    // Rendezvous succeeded — no more resend-on-reconnect needed.
    onPairReady?.call(DrawbridgePairReady(pairUrl: pairUrl, token: token));
  }

  // -- Pair WS (sync-session transport) --------------------------------------

  /// Send `pair_offer{token}` to [drawbridgeUrl]. Caller is the offerer.
  void sendPairOffer(String drawbridgeUrl, Uint8List token) =>
      _sendRendezvous(drawbridgeUrl, 'pair_offer', token);

  /// Send `pair_join{token}` to [drawbridgeUrl]. Caller is the joiner.
  void sendPairJoin(String drawbridgeUrl, Uint8List token) =>
      _sendRendezvous(drawbridgeUrl, 'pair_join', token);

  /// Whether [drawbridgeUrl] is the Drawbridge this device's own connection is to.
  bool isOwnDrawbridge(String drawbridgeUrl) => _ownUrl == drawbridgeUrl;

  /// Whether the rendezvous connection is to [drawbridgeUrl].
  bool hasRendezvousConnection(String drawbridgeUrl) =>
      _rendezvous?.url == drawbridgeUrl;

  void _sendRendezvous(String drawbridgeUrl, String type, Uint8List token) {
    if (isOwnDrawbridge(drawbridgeUrl)) {
      if (!_ownAuthenticated || _ownChannel == null) {
        moatLog('DrawbridgeService: $type dropped — own WS not ready');
        return;
      }
      _ownChannel!.sink.add(jsonEncode({
        'type': type,
        'token': base64Encode(token),
      }));
      return;
    }
    // Sent once the connection has authenticated: `onAuthenticated` then
    // asks the driver to resend whatever is unacknowledged.
    final connection = ensureRendezvous(drawbridgeUrl);
    if (connection != null && !connection.send(type, token)) {
      moatLog('DrawbridgeService: $type waits for the rendezvous connection to $drawbridgeUrl');
    }
  }

  /// The rendezvous connection to [drawbridgeUrl], opened if there is none
  /// yet. Null when this device cannot authenticate anywhere, which
  /// [onRendezvousUnreachable] reports as it would a failed connection.
  RendezvousConnection? ensureRendezvous(String drawbridgeUrl) {
    final existing = _rendezvous;
    if (existing != null && existing.url == drawbridgeUrl) return existing;
    _rendezvous = null;
    unawaited(existing?.close());
    final did = _did;
    final keyBundle = _keyBundle;
    if (did == null || keyBundle == null) {
      onRendezvousUnreachable?.call(drawbridgeUrl, 'not signed in');
      return null;
    }
    late final RendezvousConnection connection;
    connection = RendezvousConnection(
      url: drawbridgeUrl,
      did: did,
      keyBundle: keyBundle,
      onAuthenticated: (drawbridgeUrl) => onAuthenticated?.call(drawbridgeUrl),
      onPairReady: (token, pairUrl) =>
          onPairReady?.call(DrawbridgePairReady(pairUrl: pairUrl, token: token)),
      onClosed: (drawbridgeUrl, reason, wasAuthenticated) {
        if (!identical(_rendezvous, connection)) return;
        _rendezvous = null;
        if (wasAuthenticated) {
          onRendezvousClosed?.call(drawbridgeUrl);
        } else {
          onRendezvousUnreachable?.call(drawbridgeUrl, reason);
        }
      },
    );
    _rendezvous = connection;
    unawaited(connection.connect());
    return connection;
  }

  /// Close the rendezvous connection, if one is open.
  Future<void> closeRendezvous() async {
    final connection = _rendezvous;
    _rendezvous = null;
    await connection?.close();
  }

  /// Open the `/pair` WebSocket, send `pair_attach{token}`, and wait for `paired`.
  /// Subsequent binary frames are surfaced via [onPairFrame]; close via [onPairClosed].
  Future<void> connectPair(String url, Uint8List token) async {
    await _disconnectPair();
    moatLog('DrawbridgeService: connecting pair WS at $url');

    final WebSocketChannel channel;
    try {
      channel = WebSocketChannel.connect(Uri.parse(url));
      await channel.ready;
    } catch (e) {
      onPairClosed?.call(token, 'connect failed: $e');
      return;
    }

    _pairChannel = channel;
    _pairAttached = false;

    channel.sink.add(jsonEncode({
      'type': 'pair_attach',
      'token': base64Encode(token),
    }));

    _pairSubscription = channel.stream.listen(
      (data) => _handlePairMessage(token, data),
      onError: (error) {
        moatLog('DrawbridgeService: pair WS error: $error');
        _pairAttached = false;
        _pairChannel = null;
        onPairClosed?.call(token, 'error: $error');
      },
      onDone: () {
        moatLog('DrawbridgeService: pair WS closed');
        final wasAttached = _pairAttached;
        _pairAttached = false;
        _pairChannel = null;
        onPairClosed?.call(token, wasAttached ? 'remote closed' : 'closed before paired');
      },
    );
  }

  void _handlePairMessage(Uint8List token, dynamic data) {
    if (data is String) {
      try {
        final msg = jsonDecode(data) as Map<String, dynamic>;
        final type = msg['type'] as String?;
        switch (type) {
          case 'paired':
            _pairAttached = true;
            moatLog('DrawbridgeService: pair WS paired');
            onPairConnected?.call(token);
          case 'error':
            final m = msg['message'];
            moatLog('DrawbridgeService: pair_attach error: $m');
            // Server will close shortly; let onDone surface it.
          default:
            moatLog('DrawbridgeService: unknown pair text type: $type');
        }
      } catch (e) {
        moatLog('DrawbridgeService: pair msg parse error: $e');
      }
      return;
    }
    if (!_pairAttached) {
      moatLog('DrawbridgeService: pair binary frame received before paired — dropping');
      return;
    }
    final Uint8List bytes;
    if (data is Uint8List) {
      bytes = data;
    } else if (data is List<int>) {
      bytes = Uint8List.fromList(data);
    } else {
      moatLog('DrawbridgeService: pair frame unexpected type ${data.runtimeType}');
      return;
    }
    onPairFrame?.call(token, bytes);
  }

  /// Send a binary frame on the pair WS.
  void sendPairBinary(Uint8List data) {
    final channel = _pairChannel;
    if (channel == null || !_pairAttached) {
      moatLog('DrawbridgeService: sendPairBinary dropped — pair WS not paired');
      return;
    }
    channel.sink.add(data);
  }

  /// True iff the /pair WS is connected and has reached `paired`.
  bool get hasPairConnection => _pairAttached;

  /// Drop the pair WS write half (used after session ends or abort).
  Future<void> clearPair() async {
    await _disconnectPair();
  }

  /// Close with a close handshake, after everything already added to the
  /// sink. The subscription is silenced first so our own close does not
  /// report back through [onPairClosed].
  Future<void> _disconnectPair() async {
    _pairAttached = false;
    final subscription = _pairSubscription;
    final channel = _pairChannel;
    _pairSubscription = null;
    _pairChannel = null;
    subscription?.onDone(null);
    subscription?.onError((Object _) {});
    try {
      await channel?.sink
          .close(ws_status.normalClosure)
          .timeout(pairCloseGrace);
    } catch (e) {
      moatLog('DrawbridgeService: pair WS close: $e');
    }
    await subscription?.cancel();
  }

  // -- Tag watching ----------------------------------------------------------

  /// Register tags to watch on own relay. Replaces any previously watched tags.
  void watchTags(List<Uint8List> tags) {
    _watchedTagHexes.clear();
    for (final t in tags) {
      _watchedTagHexes.add(_bytesToHex(t));
    }
    _sendWatchedTags();
  }

  /// Add tags to watch (e.g. after joining a new conversation).
  void addTags(List<Uint8List> tags) {
    final addHexes = <String>[];
    for (final t in tags) {
      final hex = _bytesToHex(t);
      if (_watchedTagHexes.add(hex)) {
        addHexes.add(hex);
      }
    }
    if (addHexes.isNotEmpty) {
      _sendUpdateTags(add: addHexes, remove: []);
    }
  }

  /// Update tags after an MLS epoch change.
  void updateTags({
    required List<Uint8List> add,
    required List<Uint8List> remove,
  }) {
    final addHex = add.map(_bytesToHex).toList();
    final removeHex = remove.map(_bytesToHex).toList();
    _watchedTagHexes.addAll(addHex);
    _watchedTagHexes.removeAll(removeHex);
    _sendUpdateTags(add: addHex, remove: removeHex);
  }

  void _sendWatchedTags() {
    if (!_ownAuthenticated || _ownChannel == null) return;
    if (_watchedTagHexes.isEmpty) return;
    _ownChannel!.sink.add(jsonEncode({
      'type': 'watch_tags',
      'tags': _watchedTagHexes.toList(),
    }));
  }

  void _sendUpdateTags({
    required List<String> add,
    required List<String> remove,
  }) {
    if (!_ownAuthenticated || _ownChannel == null) return;
    _ownChannel!.sink.add(jsonEncode({
      'type': 'update_tags',
      'add': add,
      'remove': remove,
    }));
  }

  // -- Push token registration -----------------------------------------------

  /// Set the push token to register with the Drawbridge relay.
  /// If already authenticated, sends immediately; otherwise sent on next auth.
  void registerPush({
    required String deviceId,
    required String platform,
    required String token,
  }) {
    _pushDeviceId = deviceId;
    _pushPlatform = platform;
    _pushToken = token;
    _sendPushRegistration();
  }

  void unregisterPush(String deviceId) {
    _pushDeviceId = null;
    _pushToken = null;
    _pushPlatform = null;
    if (!_ownAuthenticated || _ownChannel == null) return;
    _ownChannel!.sink.add(jsonEncode({
      'type': 'unregister_push',
      'device_id': deviceId,
    }));
  }

  void _sendPushRegistration() {
    if (!_ownAuthenticated || _ownChannel == null) return;
    final deviceId = _pushDeviceId;
    final token = _pushToken;
    final platform = _pushPlatform;
    if (deviceId == null || token == null || platform == null) return;
    _ownChannel!.sink.add(jsonEncode({
      'type': 'register_push',
      'device_id': deviceId,
      'platform': platform,
      'token': token,
      'tags': _watchedTagHexes.toList(),
    }));
    moatLog('DrawbridgeService: Registered push token for device $deviceId');
  }

  // -- Envelope sending ------------------------------------------------------

  /// Notify own relay that an event was posted, with ciphertext for fan-out.
  ///
  /// The sender DID is included in the envelope so the relay can use it for
  /// PDS verification and rate-limiting without storing it per-connection.
  void notifyEventPosted({
    required Uint8List tag,
    required String rkey,
    required Uint8List payload,
    required List<String> drawbridgeUrls,
  }) {
    if (!_ownAuthenticated || _ownChannel == null) return;
    final tagHex = _bytesToHex(tag);
    _ownChannel!.sink.add(jsonEncode({
      'type': 'event_posted',
      'did': _did,
      'tag': tagHex,
      'rkey': rkey,
      'payload': base64Encode(payload),
      'relay_urls': drawbridgeUrls,
    }));
  }

  // -- Drawbridge config cache -----------------------------------------------

  /// Cache the relay URLs a DID's devices sit on, as just read from its PDS
  /// and normalised.
  void cacheDrawbridgeConfig(String did, List<String> urls) {
    _configCache[did] = _CachedConfig(urls, DateTime.now());
  }

  /// Read the Drawbridges of [dids] from their PDSes, all at once, and cache
  /// them. A DID whose read fails keeps what was cached, and stays stale.
  Future<void> refreshDrawbridgeConfigs(
      AtprotoClient client, Iterable<String> dids) async {
    await Future.wait(dids.toSet().map((did) async {
      try {
        final urls = await client.fetchDrawbridgeConfig(did);
        cacheDrawbridgeConfig(
            did, urls.map(normalizedDrawbridgeUrl).whereType<String>().toSet().toList());
      } catch (e) {
        moatLog('DrawbridgeService: reading the Drawbridges of $did failed: $e');
      }
    }));
  }

  /// The DIDs among [dids] whose relay list is missing or older than [configTtl].
  List<String> staleConfigDids(Iterable<String> dids) {
    final now = DateTime.now();
    return dids.toSet().where((did) {
      final cached = _configCache[did];
      return cached == null || now.difference(cached.fetchedAt) >= configTtl;
    }).toList();
  }

  /// Relay URLs to notify for an event: the union of [participantDids]' relays
  /// and this user's own, less our own relay, which already routed the event
  /// to the devices connected to it.
  List<String> drawbridgeUrlsForParticipants(List<String> participantDids) {
    final urls = <String>{};
    for (final did in {...participantDids, if (_did != null) _did!}) {
      final cached = _configCache[did];
      if (cached != null) {
        urls.addAll(cached.urls);
      }
    }
    urls.remove(_ownUrl);
    return urls.toList();
  }

  // -- Connection management -------------------------------------------------

  void _scheduleReconnect() {
    if (_disposed || _ownUrl == null) return;

    _reconnectAttempts++;
    final delaySecs = (1 << _reconnectAttempts).clamp(1, _maxReconnectDelay.inSeconds);
    final delay = Duration(seconds: delaySecs);
    moatLog('DrawbridgeService: Scheduling reconnect in ${delay.inSeconds}s');

    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(delay, () {
      if (_disposed || _ownUrl == null) return;
      connectOwn(_ownUrl!);
    });
  }

  void disconnectAll() {
    _disposed = true;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    _disconnectOwn();
    _disconnectPair();
  }

  Future<void> _disconnectOwn() async {
    _ownSubscription?.cancel();
    _ownSubscription = null;
    _ownChannel?.sink.close();
    _ownChannel = null;
    _ownAuthenticated = false;
  }

  bool get isOwnConnected => _ownAuthenticated;

  void reset() {
    disconnectAll();
    _watchedTagHexes.clear();
    _configCache.clear();
    unawaited(closeRendezvous());
    _keyBundle = null;
    _did = null;
    _pushDeviceId = null;
    _pushToken = null;
    _pushPlatform = null;
    _reconnectAttempts = 0;
    _disposed = false;
  }

  static String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

class _CachedConfig {
  final List<String> urls;
  final DateTime fetchedAt;

  _CachedConfig(this.urls, this.fetchedAt);
}
