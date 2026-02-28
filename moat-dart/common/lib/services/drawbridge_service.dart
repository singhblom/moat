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

/// Manages WebSocket connections to Drawbridge relays.
class DrawbridgeService {
  static final DrawbridgeService instance = DrawbridgeService._();
  DrawbridgeService._();

  WebSocketChannel? _ownChannel;
  StreamSubscription? _ownSubscription;
  String? _ownUrl;
  bool _ownAuthenticated = false;

  final Map<String, String> _ownTickets = {};
  final Map<String, _PartnerConnection> _partnerConnections = {};

  /// Called when a partner Drawbridge sends a new_event notification.
  VoidCallback? onNewEvent;

  Uint8List? _keyBundle;
  String? _did;
  bool _disposed = false;
  Timer? _reconnectTimer;
  int _reconnectAttempts = 0;
  static const _maxReconnectDelay = Duration(seconds: 60);

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
          _reregisterTickets();
        case 'ticket_registered':
          moatLog('DrawbridgeService: Ticket registered');
        case 'ticket_revoked':
          moatLog('DrawbridgeService: Ticket revoked');
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

  void _reregisterTickets() {
    for (final entry in _ownTickets.entries) {
      _sendRegisterTicket(entry.value);
    }
  }

  void _sendRegisterTicket(String ticketHex) {
    if (!_ownAuthenticated || _ownChannel == null) return;
    _ownChannel!.sink.add(jsonEncode({
      'type': 'register_ticket',
      'ticket': ticketHex,
    }));
  }

  void registerTicket(String groupIdHex, String ticketHex) {
    _ownTickets[groupIdHex] = ticketHex;
    _sendRegisterTicket(ticketHex);
  }

  void notifyEventPosted(Uint8List tag, String rkey) {
    if (!_ownAuthenticated || _ownChannel == null) return;
    final tagHex = tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    _ownChannel!.sink.add(jsonEncode({
      'type': 'event_posted',
      'tag': tagHex,
      'rkey': rkey,
    }));
  }

  Future<void> connectPartner({
    required String url,
    required String ticketHex,
    required List<Uint8List> tags,
  }) async {
    final key = '$url|$ticketHex';
    if (_partnerConnections.containsKey(key)) {
      moatLog('DrawbridgeService: Already connected to partner $url');
      return;
    }

    moatLog('DrawbridgeService: Connecting to partner relay at $url');

    try {
      final wsUrl = Uri.parse(url);
      final channel = WebSocketChannel.connect(wsUrl);
      await channel.ready;

      final conn = _PartnerConnection(
        url: url,
        ticketHex: ticketHex,
        channel: channel,
        tags: tags,
      );

      conn.subscription = channel.stream.listen(
        (data) => _handlePartnerMessage(data as String, conn),
        onError: (error) {
          moatLog('DrawbridgeService: Partner relay $url error: $error');
          _partnerConnections.remove(key);
        },
        onDone: () {
          moatLog('DrawbridgeService: Partner relay $url disconnected');
          _partnerConnections.remove(key);
        },
      );

      _partnerConnections[key] = conn;

      channel.sink.add(jsonEncode({
        'type': 'ticket_auth',
        'ticket': ticketHex,
      }));
    } catch (e) {
      moatLog('DrawbridgeService: Failed to connect to partner relay $url: $e');
    }
  }

  void _handlePartnerMessage(String data, _PartnerConnection conn) {
    try {
      final msg = jsonDecode(data) as Map<String, dynamic>;
      final type = msg['type'] as String?;

      switch (type) {
        case 'ticket_authenticated':
          moatLog('DrawbridgeService: Partner relay ${conn.url} authenticated');
          conn.authenticated = true;
          _sendWatchTags(conn);
        case 'new_event':
          final tag = msg['tag'] as String?;
          final rkey = msg['rkey'] as String?;
          moatLog('DrawbridgeService: new_event from ${conn.url} tag=$tag rkey=$rkey');
          onNewEvent?.call();
        case 'error':
          moatLog('DrawbridgeService: Partner relay ${conn.url} error: ${msg['message']}');
        default:
          moatLog('DrawbridgeService: Unknown partner message type: $type');
      }
    } catch (e) {
      moatLog('DrawbridgeService: Error parsing partner message: $e');
    }
  }

  void _sendWatchTags(_PartnerConnection conn) {
    if (!conn.authenticated) return;
    final tagHexList = conn.tags
        .map((t) => t.map((b) => b.toRadixString(16).padLeft(2, '0')).join())
        .toList();
    conn.channel.sink.add(jsonEncode({
      'type': 'watch_tags',
      'tags': tagHexList,
    }));
  }

  void updatePartnerTags({
    required String url,
    required String ticketHex,
    required List<Uint8List> oldTags,
    required List<Uint8List> newTags,
  }) {
    final key = '$url|$ticketHex';
    final conn = _partnerConnections[key];
    if (conn == null || !conn.authenticated) return;

    final removeHex = oldTags
        .map((t) => t.map((b) => b.toRadixString(16).padLeft(2, '0')).join())
        .toList();
    final addHex = newTags
        .map((t) => t.map((b) => b.toRadixString(16).padLeft(2, '0')).join())
        .toList();

    conn.channel.sink.add(jsonEncode({
      'type': 'update_tags',
      'remove': removeHex,
      'add': addHex,
    }));

    conn.tags = newTags;
  }

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
    for (final conn in _partnerConnections.values) {
      conn.subscription?.cancel();
      conn.channel.sink.close();
    }
    _partnerConnections.clear();
  }

  Future<void> _disconnectOwn() async {
    _ownSubscription?.cancel();
    _ownSubscription = null;
    _ownChannel?.sink.close();
    _ownChannel = null;
    _ownAuthenticated = false;
  }

  Future<void> reconnectPartners(
    List<({String url, String ticketHex, List<Uint8List> tags})> hintsWithTags,
  ) async {
    if (_disposed) return;
    for (final h in hintsWithTags) {
      await connectPartner(
        url: h.url,
        ticketHex: h.ticketHex,
        tags: h.tags,
      );
    }
  }

  bool get isOwnConnected => _ownAuthenticated;
  int get partnerConnectionCount => _partnerConnections.length;

  void reset() {
    disconnectAll();
    _ownTickets.clear();
    _keyBundle = null;
    _did = null;
    _reconnectAttempts = 0;
    _disposed = false;
  }
}

class _PartnerConnection {
  final String url;
  final String ticketHex;
  final WebSocketChannel channel;
  StreamSubscription? subscription;
  List<Uint8List> tags;
  bool authenticated = false;

  _PartnerConnection({
    required this.url,
    required this.ticketHex,
    required this.channel,
    required this.tags,
  });
}
