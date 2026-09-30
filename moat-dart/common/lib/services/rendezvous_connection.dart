import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../rust/api/simple.dart' as ffi;
import 'debug_log.dart';

/// A DID-authenticated main-WS connection to a Drawbridge other than this
/// device's own, held only while a rendezvous is live there: pairing or
/// sync with a device that sits on that Drawbridge. It carries `pair_offer` /
/// `pair_join` and the Drawbridge's replies, never events or tags.
///
/// Mirrors the rendezvous connection in `crates/moat-cli/src/drawbridge.rs`.
class RendezvousConnection {
  final String url;
  final String _did;
  final Uint8List _keyBundle;

  /// The Drawbridge authenticated: an offer or join it has not acknowledged can
  /// be resent.
  final void Function(String drawbridgeUrl) onAuthenticated;

  /// The Drawbridge matched a rendezvous token and named the pair WS.
  final void Function(String drawbridgeUrl, Uint8List token, String pairUrl) onPairReady;

  /// The connection ended, whether the Drawbridge closed it or it failed.
  final void Function(String drawbridgeUrl, String reason) onClosed;

  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  bool _authenticated = false;
  bool _closed = false;

  RendezvousConnection({
    required this.url,
    required String did,
    required Uint8List keyBundle,
    required this.onAuthenticated,
    required this.onPairReady,
    required this.onClosed,
  })  : _did = did,
        _keyBundle = keyBundle;

  bool get isAuthenticated => _authenticated;

  Future<void> connect() async {
    moatLog('RendezvousConnection: connecting to $url');
    try {
      final channel = WebSocketChannel.connect(Uri.parse(url));
      await channel.ready;
      if (_closed) {
        unawaited(channel.sink.close());
        return;
      }
      _channel = channel;
      _subscription = channel.stream.listen(
        (data) => _onMessage(channel, data as String),
        onError: (Object e) => _end('error: $e'),
        onDone: () => _end('connection closed'),
      );
      channel.sink.add(jsonEncode({'type': 'request_challenge'}));
    } catch (e) {
      _end('connect failed: $e');
    }
  }

  /// Send `pair_offer` or `pair_join` for [token]. Dropped until the Drawbridge
  /// has authenticated; [onAuthenticated] is the cue to send again.
  bool send(String type, Uint8List token) {
    final channel = _channel;
    if (!_authenticated || channel == null) return false;
    channel.sink.add(jsonEncode({'type': type, 'token': base64Encode(token)}));
    return true;
  }

  Future<void> close() async {
    _closed = true;
    _authenticated = false;
    final subscription = _subscription;
    final channel = _channel;
    _subscription = null;
    _channel = null;
    subscription?.onDone(null);
    subscription?.onError((Object _) {});
    try {
      await channel?.sink.close().timeout(const Duration(seconds: 5));
    } catch (_) {}
    await subscription?.cancel();
  }

  void _onMessage(WebSocketChannel channel, String data) {
    if (channel != _channel) return;
    try {
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type'] as String?) {
        case 'challenge':
          unawaited(_answer(channel, msg));
        case 'authenticated':
          _authenticated = true;
          moatLog('RendezvousConnection: authenticated to $url');
          onAuthenticated(url);
        case 'pair_ready':
          final pairUrl = msg['pair_url'] as String?;
          final tokenB64 = msg['token'] as String?;
          if (pairUrl == null || tokenB64 == null) return;
          onPairReady(url, base64Decode(tokenB64), pairUrl);
        case 'pair_pending':
          moatLog('RendezvousConnection: pair_pending on $url');
        case 'error':
          // Connection-fatal, as on the own Drawbridge: a `pair_join` that beat the
          // peer's `pair_offer` is answered in-band, and a fresh connection
          // resends it.
          _end('server error: ${msg['message']}');
      }
    } catch (e) {
      moatLog('RendezvousConnection: bad message from $url: $e');
    }
  }

  Future<void> _answer(WebSocketChannel channel, Map<String, dynamic> msg) async {
    final nonce = msg['nonce'] as String?;
    if (nonce == null) return;
    final timestamp = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    try {
      final result = await ffi.signDrawbridgeChallenge(
        keyBundle: _keyBundle,
        message: Uint8List.fromList(utf8.encode('$nonce\n$url\n$timestamp\n')),
      );
      if (channel != _channel) return;
      channel.sink.add(jsonEncode({
        'type': 'challenge_response',
        'did': _did,
        'signature': base64Encode(result.signature),
        'timestamp': timestamp,
        'public_key': base64Encode(result.publicKey),
      }));
    } catch (e) {
      moatLog('RendezvousConnection: signing failed: $e');
    }
  }

  void _end(String reason) {
    if (_closed) return;
    _closed = true;
    _authenticated = false;
    unawaited(_subscription?.cancel());
    _subscription = null;
    _channel = null;
    moatLog('RendezvousConnection: $url ended: $reason');
    onClosed(url, reason);
  }
}
