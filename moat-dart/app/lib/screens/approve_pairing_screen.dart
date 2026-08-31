import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;
import '../services/pairing_manager.dart';

/// Existing device: shown the moment an incoming `Enroll` needs a user
/// decision — pushed by a `state` listener in `main.dart`, mirroring
/// `moat-cli`'s TUI switching straight to `Focus::PairApprove` when
/// `SurfaceApprovalPrompt` arrives.
///
/// Device name/DID come from [PairingService.state]'s `AwaitingApproval`
/// rather than a cached copy. On success (or a plain reject) this unwinds
/// past `EnterPairingCodeScreen` too — both belong to one attempt. On an
/// approve *failure* it stays and renders `Failed { reason }`.
class ApprovePairingScreen extends StatefulWidget {
  const ApprovePairingScreen({super.key});

  @override
  State<ApprovePairingScreen> createState() => _ApprovePairingScreenState();
}

class _ApprovePairingScreenState extends State<ApprovePairingScreen> {
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    // A background failure (e.g. the pair WS drops) can move `state` to
    // `Failed` without going through `_respond()` — rebuild so that's
    // reflected here too, not just from this screen's own button presses.
    PairingManager.instance.service?.state.addListener(_onStateChange);
  }

  @override
  void dispose() {
    PairingManager.instance.service?.state.removeListener(_onStateChange);
    super.dispose();
  }

  void _onStateChange() {
    if (mounted) setState(() {});
  }

  Future<void> _respond(bool approve) async {
    final service = PairingManager.instance.service;
    if (service == null) return;

    setState(() => _isLoading = true);

    try {
      if (approve) {
        await service.approvePending();
      } else {
        await service.rejectPending();
      }
    } catch (_) {
      // `state` already reflects the outcome (including `Failed`, if the
      // underlying FFI call threw) — rendered by `build()` below.
    }
    if (!mounted) return;

    final uiState = service.state.value;
    if (uiState is common.PairingUiStateDto_Failed && approve) {
      // A genuine approve failure: stay put and show the reason.
      setState(() => _isLoading = false);
      return;
    }
    // Success, or a plain reject (the user already knows why) — unwind
    // both this screen and `EnterPairingCodeScreen` beneath it, back to
    // wherever the pairing flow started from.
    Navigator.of(context).pop();
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final service = PairingManager.instance.service;
    final uiState = service?.state.value;
    final pending =
        uiState is common.PairingUiStateDto_AwaitingApproval ? uiState : null;
    final failure =
        uiState is common.PairingUiStateDto_Failed ? uiState : null;
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
              failure != null ? Icons.error_outline : Icons.devices_other,
              size: 64,
              color: failure != null
                  ? Theme.of(context).colorScheme.error
                  : Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 24),
            Text(
              failure != null
                  ? 'Pairing failed'
                  : 'A new device wants to join your account',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 16),
            if (failure == null)
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
              )
            else
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  failure.reason,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onErrorContainer,
                  ),
                ),
              ),
            const SizedBox(height: 8),
            if (failure == null)
              Text(
                'Only approve this if you just requested a pairing code on '
                'that device. It will get full access to your conversations.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
              ),
            const Spacer(),
            if (failure != null)
              FilledButton(
                onPressed: () {
                  Navigator.of(context).pop();
                  Navigator.of(context).pop();
                },
                child: const Text('OK'),
              )
            else ...[
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
          ],
        ),
      ),
    );
  }
}
