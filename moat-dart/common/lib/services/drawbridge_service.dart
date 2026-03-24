import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:web_socket_channel/web_socket_channel.dart';
import '../rust/api/simple.dart' as ffi;
import 'debug_log.dart';

/// No dart:ui dependency — VoidCallback defined here.
typedef VoidCallback = void Function();

/// Default Drawbridge relay URL.
const defaultDrawbridgeUrl = 'wss://moat-drawbridge.fly.dev/ws';

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

/// Manages a single WebSocket connection to the user's own Drawbridge relay.
///
/// After the ticket/partner architecture was removed, the client only connects
/// to its **own** Drawbridge. Sending uses envelope-based fan-out (payload +
/// relay_urls). Receiving uses tag-based routing on the own relay.
class DrawbridgeService {
  static final DrawbridgeService instance = DrawbridgeService._();
  DrawbridgeService._();

  WebSocketChannel? _ownChannel;
  StreamSubscription? _ownSubscription;
  String? _ownUrl;
  bool _ownAuthenticated = false;

  /// Called when own Drawbridge sends a new_event notification.
  void Function(DrawbridgeNewEvent)? onNewEvent;

  Uint8List? _keyBundle;
  String? _did;
  bool _disposed = false;
  Timer? _reconnectTimer;
  int _reconnectAttempts = 0;
  static const _maxReconnectDelay = Duration(seconds: 60);

  /// Tags currently registered on own relay.
  final Set<String> _watchedTagHexes = {};

  /// Drawbridge config cache: DID → list of relay URLs.
  final Map<String, List<String>> _configCache = {};

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
        case 'new_event':
          _handleNewEvent(msg);
        case 'error':
          moatLog('DrawbridgeService: Own relay error: ${msg['message']}');
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

  // -- Envelope sending ------------------------------------------------------

  /// Notify own relay that an event was posted, with ciphertext for fan-out.
  void notifyEventPosted({
    required Uint8List tag,
    required String rkey,
    required Uint8List payload,
    required List<String> relayUrls,
  }) {
    if (!_ownAuthenticated || _ownChannel == null) return;
    final tagHex = _bytesToHex(tag);
    _ownChannel!.sink.add(jsonEncode({
      'type': 'event_posted',
      'tag': tagHex,
      'rkey': rkey,
      'payload': base64Encode(payload),
      'relay_urls': relayUrls,
    }));
  }

  // -- Drawbridge config cache -----------------------------------------------

  /// Cache a DID's Drawbridge relay URLs.
  void cacheDrawbridgeConfig(String did, List<String> urls) {
    if (urls.isNotEmpty) {
      _configCache[did] = urls;
    }
  }

  /// Get cached relay URLs for a list of participant DIDs.
  /// Returns a flat, deduplicated list of relay URLs.
  List<String> relayUrlsForParticipants(List<String> participantDids) {
    final urls = <String>{};
    for (final did in participantDids) {
      final cached = _configCache[did];
      if (cached != null) {
        urls.addAll(cached);
      }
    }
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
    _keyBundle = null;
    _did = null;
    _reconnectAttempts = 0;
    _disposed = false;
  }

  static String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
