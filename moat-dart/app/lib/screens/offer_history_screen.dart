import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;

import '../services/device_ring_manager.dart';
import '../services/sync_request_manager.dart';

/// A sibling has said it holds none of this account's history, and this
/// device has it.
///
/// Raised on app open and the moment such an advertisement arrives,
/// because a newly added device with nothing on it is exactly when the
/// user cares — telling them a week later is worth much less.
///
/// Answering either way settles it. Sending offers; dismissing sets the
/// flag that stops *this* advertisement asking again, so the prompt
/// cannot become something people learn to swipe away. Only a sibling
/// that later says something different can ask again.
class OfferHistoryScreen extends StatefulWidget {
  const OfferHistoryScreen({
    super.key,
    required this.deviceIdHex,
    required this.authService,
  });

  /// The sibling being offered to, joined back to the ring's credentials
  /// for a name.
  final String deviceIdHex;

  /// Supplies the MLS session the credentials are read from. Passed in
  /// rather than reached for globally, as [DevicesScreen] does.
  final common.AuthService authService;

  @override
  State<OfferHistoryScreen> createState() => _OfferHistoryScreenState();
}

class _OfferHistoryScreenState extends State<OfferHistoryScreen> {
  String? _deviceName;
  bool _isBusy = false;

  @override
  void initState() {
    super.initState();
    _loadName();
  }

  Future<void> _loadName() async {
    final ring = DeviceRingManager.instance.service;
    final ringId = ring == null ? null : await ring.ringGroupId();
    final moat = widget.authService.moatSession;
    if (ringId == null || moat == null) return;
    try {
      final creds = await moat.getGroupMemberCredentials(groupId: ringId);
      for (final c in creds) {
        final hex =
            c.deviceId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
        if (hex == widget.deviceIdHex) {
          if (mounted) {
            setState(() => _deviceName =
                c.deviceName.isEmpty ? 'A new device' : c.deviceName);
          }
          return;
        }
      }
    } catch (_) {
      // A name is a nicety; the offer works without one.
    }
  }

  Uint8List get _deviceId {
    final hex = widget.deviceIdHex;
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

  Future<void> _send() async {
    final service = SyncRequestManager.instance.service;
    if (service == null) return;
    setState(() => _isBusy = true);
    try {
      await service.offerSync(_deviceId);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(() => _isBusy = false);
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$e')));
      }
    }
  }

  Future<void> _dismiss() async {
    // Dismissing is an answer, and it is recorded as one: this same
    // advertisement will not ask again.
    await DeviceRingManager.instance.service?.dismissSiblingSummary(_deviceId);
    if (mounted) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final name = _deviceName ?? 'A new device';
    return Scaffold(
      appBar: AppBar(title: const Text('New Device')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Icon(Icons.devices_other, size: 56),
            const SizedBox(height: 20),
            Text(
              name,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 12),
            const Text(
              'says it has none of your message history.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              'Sending it your history means both devices can show your '
              'conversations. The messages go directly between your devices.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const Spacer(),
            FilledButton.icon(
              onPressed: _isBusy ? null : _send,
              icon: const Icon(Icons.send),
              label: const Text('Send my history'),
            ),
            const SizedBox(height: 8),
            TextButton(
              onPressed: _isBusy ? null : _dismiss,
              child: const Text('Not now'),
            ),
          ],
        ),
      ),
    );
  }
}
