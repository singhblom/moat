import 'dart:typed_data';

import '../rust/api/simple.dart' as ffi;
import 'debug_log.dart';

/// How a transfer's frames are sealed and opened on the pair channel: ring
/// MLS between established devices, the pairing AEAD for the transfer that
/// follows a pairing.
abstract class SyncChannel {
  Future<Uint8List> seal(Uint8List payload);

  /// The payload, or `null` for a frame to skip. Throws when the channel
  /// cannot continue past this frame.
  Future<Uint8List?> open(Uint8List frame);

  /// The peer as the channel authenticated it, if it names one.
  String? get peerDeviceName;
}

/// Ring-MLS frames, for a sync between established devices.
class RingSyncChannel implements SyncChannel {
  RingSyncChannel({
    required ffi.MoatSessionHandle session,
    required Uint8List ringId,
    required Uint8List keyBundle,
  })  : _session = session,
        _ringId = ringId,
        _keyBundle = keyBundle;

  final ffi.MoatSessionHandle _session;
  final Uint8List _ringId;
  final Uint8List _keyBundle;

  @override
  String? peerDeviceName;

  @override
  Future<Uint8List> seal(Uint8List payload) => _session.encryptSyncApp(
        ringGroupId: _ringId,
        keyBundle: _keyBundle,
        payload: payload,
      );

  @override
  Future<Uint8List?> open(Uint8List frame) async {
    try {
      final opened = await _session.decryptSyncFrame(
        ringGroupId: _ringId,
        ciphertext: frame,
      );
      // A pair channel has exactly one peer, so the latest frame's sender
      // is the peer; every frame carries one.
      peerDeviceName = opened.senderDeviceName ?? peerDeviceName;
      return opened.payload;
    } catch (e) {
      moatLog('SyncService: decryptSyncFrame failed: $e');
      return null;
    }
  }
}

/// The pairing AEAD the pairing exchange ran on, so the new device needs no
/// ring-MLS history for its first transfer.
class PairingSyncChannel implements SyncChannel {
  PairingSyncChannel(this._channel);

  final ffi.PairingFrameChannelHandle _channel;

  @override
  String? get peerDeviceName => null;

  @override
  Future<Uint8List> seal(Uint8List payload) async =>
      _channel.seal(plaintext: payload);

  /// Throws when a frame fails to open: its counter is the nonce, and the
  /// peer sealed the next one expecting it to advance.
  @override
  Future<Uint8List?> open(Uint8List frame) async =>
      _channel.open(ciphertext: frame);
}
