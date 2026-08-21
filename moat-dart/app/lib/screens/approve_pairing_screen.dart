import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as ffi show PairingUiStateDto_AwaitingApproval;
import '../services/pairing_manager.dart';

/// Existing device: shown the moment an incoming `Enroll` needs a user
/// decision — pushed by a `state` listener in `main.dart`, mirroring
/// `moat-cli`'s TUI switching straight to `Focus::PairApprove` when
/// `SurfaceApprovalPrompt` arrives.
class ApprovePairingScreen extends StatefulWidget {
  const ApprovePairingScreen({super.key});

  @override
  State<ApprovePairingScreen> createState() => _ApprovePairingScreenState();
}

class _ApprovePairingScreenState extends State<ApprovePairingScreen> {
  bool _isLoading = false;
  String? _error;

  Future<void> _respond(bool approve) async {
    final service = PairingManager.instance.service;
    if (service == null) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      if (approve) {
        await service.approvePending();
      } else {
        await service.rejectPending();
      }
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final service = PairingManager.instance.service;
    final uiState = service?.state.value;
    final pending = uiState is ffi.PairingUiStateDto_AwaitingApproval ? uiState : null;
    final deviceName = pending?.deviceName;
    final did = pending?.did;

    return Scaffold(
      appBar: AppBar(title: const Text('New Device')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const SizedBox(height: 24),
            Icon(
              Icons.devices_other,
              size: 64,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 24),
            Text(
              'A new device wants to join your account',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    deviceName == null || deviceName.isEmpty
                        ? 'Unnamed device'
                        : deviceName,
                    style: Theme.of(context)
                        .textTheme
                        .bodyLarge
                        ?.copyWith(fontWeight: FontWeight.bold),
                  ),
                  if (did != null) ...[
                    const SizedBox(height: 4),
                    Text(
                      did,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Only approve this if you just requested a pairing code on '
              'that device. It will get full access to your conversations.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  _error!,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onErrorContainer,
                  ),
                ),
              ),
            ],
            const Spacer(),
            OutlinedButton(
              onPressed: _isLoading ? null : () => _respond(false),
              child: const Text('Reject'),
            ),
            const SizedBox(height: 8),
            FilledButton(
              onPressed: _isLoading ? null : () => _respond(true),
              child: _isLoading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Colors.white,
                      ),
                    )
                  : const Text('Approve'),
            ),
          ],
        ),
      ),
    );
  }
}
