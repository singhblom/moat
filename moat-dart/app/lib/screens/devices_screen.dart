import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;
import '../services/sync_request_manager.dart';

/// One linked device, as read from the ring's MLS leaf credentials, with
/// whatever that device last advertised holding.
class _LinkedDevice {
  final String name;
  final bool isSelf;
  final String deviceIdHex;
  /// `null` when this sibling has not advertised — silence, not an answer.
  final common.SiblingSummaryDto? advertised;
  const _LinkedDevice({
    required this.name,
    required this.isSelf,
    required this.deviceIdHex,
    this.advertised,
  });

  /// Worth offering history to: it has said it holds less than nothing we
  /// know of, and the user has not already answered that. Silence is not
  /// an invitation — a device that has not advertised might hold
  /// everything.
  bool get isOfferable {
    final a = advertised;
    return !isSelf && a != null && !a.dismissed && a.messages == BigInt.zero;
  }
}

/// The linked devices, and what any in-flight sync is doing.
///
/// This is the *requesting* device's surface. Every other sync screen
/// belongs to the device being asked, so before this existed a device that
/// requested history showed nothing at all — not while waiting, not on
/// success, and not on failure. An unanswered request now becomes visible
/// here instead of expiring silently.
///
/// The device list comes from the ring's own member credentials, not from
/// anything a device says about itself, so it is exactly "who can read
/// your messages".
class DevicesScreen extends StatefulWidget {
  const DevicesScreen({
    super.key,
    required this.authService,
    required this.ringService,
  });

  final common.AuthService authService;
  final common.DeviceRingService ringService;

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  List<_LinkedDevice>? _devices;
  bool _isBusy = false;

  @override
  void initState() {
    super.initState();
    SyncRequestManager.instance.service?.state.addListener(_onStateChange);
    _loadDevices();
  }

  @override
  void dispose() {
    SyncRequestManager.instance.service?.state.removeListener(_onStateChange);
    super.dispose();
  }

  void _onStateChange() {
    if (mounted) setState(() {});
  }

  Future<void> _loadDevices() async {
    final session = widget.authService.moatSession;
    final ringId = await widget.ringService.ringGroupId();
    if (session == null || ringId == null) {
      if (mounted) setState(() => _devices = const []);
      return;
    }
    try {
      final creds = await session.getGroupMemberCredentials(groupId: ringId);
      final myDeviceId = _hex(session.deviceId());
      final summaries = {
        for (final s in widget.ringService.siblingSummaries()) s.deviceId: s
      };
      final devices = [
        for (final c in creds)
          _LinkedDevice(
            name: c.deviceName.isEmpty ? 'Unnamed device' : c.deviceName,
            isSelf: _hex(c.deviceId) == myDeviceId,
            deviceIdHex: _hex(c.deviceId),
            advertised: summaries[_hex(c.deviceId)],
          )
      ];
      if (mounted) setState(() => _devices = devices);
    } catch (_) {
      if (mounted) setState(() => _devices = const []);
    }
  }

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  Future<void> _requestSync() async {
    final service = SyncRequestManager.instance.service;
    if (service == null) return;
    setState(() => _isBusy = true);
    try {
      await service.requestSync();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
      }
    }
    if (mounted) setState(() => _isBusy = false);
  }

  Future<void> _offer(_LinkedDevice device) async {
    final service = SyncRequestManager.instance.service;
    if (service == null) return;
    setState(() => _isBusy = true);
    try {
      await service.offerSync(_bytes(device.deviceIdHex));
      await _loadDevices();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
      }
    }
    if (mounted) setState(() => _isBusy = false);
  }

  static Uint8List _bytes(String hex) {
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

  @override
  Widget build(BuildContext context) {
    final devices = _devices;
    // Read through `refresh()` so an expired request reads as failed the
    // moment this screen is looked at, not on the next poll tick.
    final syncState = SyncRequestManager.instance.service?.refresh() ??
        const common.SyncRequestUiStateDto.idle();

    return Scaffold(
      appBar: AppBar(title: const Text('Linked Devices')),
      body: devices == null
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              children: [
                if (devices.isEmpty)
                  const Padding(
                    padding: EdgeInsets.all(24),
                    child: Column(
                      children: [
                        Icon(Icons.devices_other, size: 48),
                        SizedBox(height: 12),
                        Text(
                          'No linked devices',
                          style: TextStyle(fontWeight: FontWeight.bold),
                        ),
                        SizedBox(height: 8),
                        Text(
                          'Show a pairing code on another device to link it. '
                          'Your message history only survives losing this '
                          'device if another one is linked.',
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  )
                else
                  ...devices.map(
                    (d) => ListTile(
                      leading: Icon(
                        d.isSelf ? Icons.smartphone : Icons.devices_other,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      title: Text(d.name),
                      // What that device last said it holds. This is what
                      // turns "ask a device and hope" into a choice:
                      // approve on the one that actually has the history.
                      subtitle: Text(
                        d.isSelf
                            ? 'This device'
                            : common.advertisementText(d.advertised),
                      ),
                      // The offer direction: this device has the history
                      // and that one does not, so the decision can be
                      // made here rather than by walking over there.
                      // Pressing it *is* the approval — the other side
                      // joins without a prompt of its own.
                      trailing: d.isOfferable
                          ? TextButton(
                              onPressed: _isBusy ? null : () => _offer(d),
                              child: const Text('Send history'),
                            )
                          : null,
                    ),
                  ),
                const Divider(),
                _SyncStatusTile(state: syncState),
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: FilledButton.icon(
                    onPressed:
                        _isBusy || devices.length < 2 ? null : _requestSync,
                    icon: const Icon(Icons.history),
                    label: const Text('Ask for history'),
                  ),
                ),
                if (devices.length >= 2)
                  const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 16),
                    child: Text(
                      'Your other devices will ask their user to approve. '
                      'Approve on whichever one has the history you want.',
                      textAlign: TextAlign.center,
                    ),
                  ),
              ],
            ),
    );
  }
}

/// The sync line — the whole reason this screen exists on the requesting
/// side. Failure text is the *requester's* wording; the same underlying
/// reason reads differently on the device that was asked.
class _SyncStatusTile extends StatelessWidget {
  const _SyncStatusTile({required this.state});

  final common.SyncRequestUiStateDto state;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (IconData icon, String text, Color color) = state.when(
      idle: () => (Icons.check_circle_outline, 'No sync in progress.', scheme.outline),
      awaitingPeer: () => (
        Icons.hourglass_empty,
        'Waiting for another device to answer…',
        scheme.tertiary,
      ),
      awaitingApproval: (deviceName) => (
        Icons.help_outline,
        '$deviceName is asking you for history.',
        scheme.tertiary,
      ),
      active: () => (Icons.sync, 'Transferring history…', scheme.primary),
      // An empty tally is a different answer, not a lesser success: it is
      // what tells the user to approve on a different device. It reads as
      // a neutral outcome rather than a triumphant one.
      complete: (tally, deviceName) => (
        tally.messages == BigInt.zero ? Icons.info_outline : Icons.check_circle,
        common.syncCompleteText(tally, deviceName),
        tally.messages == BigInt.zero ? scheme.outline : scheme.primary,
      ),
      failed: (reason) =>
          (Icons.error_outline, common.requesterFailureText(reason), scheme.error),
    );

    return ListTile(
      leading: Icon(icon, color: color),
      title: Text(text, style: TextStyle(color: color)),
    );
  }
}
