import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;
import '../services/pair_channel_manager.dart';

/// A sibling asked for message history. Pushed by a `state` listener in
/// `main.dart` the moment the request arrives, mirroring `moat-cli`'s TUI
/// switching to `Focus::SyncApprove` — the request can land while the user
/// is anywhere in the app.
///
/// The device name comes from [PairChannelService.syncRequestState]'s
/// `AwaitingApproval`, which the protocol takes from the requester's MLS
/// leaf credential rather than from anything it declared about itself.
class ApproveSyncRequestScreen extends StatefulWidget {
  const ApproveSyncRequestScreen({super.key});

  @override
  State<ApproveSyncRequestScreen> createState() =>
      _ApproveSyncRequestScreenState();
}

class _ApproveSyncRequestScreenState extends State<ApproveSyncRequestScreen> {
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    // The request expires on the relay's token TTL, and the pair channel
    // can drop — both move `state` without any button being pressed here.
    PairChannelManager.instance.service?.syncRequestState.addListener(_onStateChange);
  }

  @override
  void dispose() {
    PairChannelManager.instance.service?.syncRequestState.removeListener(_onStateChange);
    super.dispose();
  }

  void _onStateChange() {
    if (mounted) setState(() {});
  }

  Future<void> _respond(bool accept) async {
    final service = PairChannelManager.instance.service;
    if (service == null) return;

    setState(() => _isLoading = true);
    try {
      if (accept) {
        await service.acceptSyncRequest();
      } else {
        await service.declineSyncRequest();
      }
    } catch (_) {
      // `state` already carries the outcome, including any failure.
    }
    if (!mounted) return;

    final uiState = service.syncRequestState.value;
    if (uiState is common.SyncRequestUiStateDto_Failed && accept) {
      // A genuine failure to start sending: stay and show why.
      setState(() => _isLoading = false);
      return;
    }
    // Accepted (the transfer now runs in the background) or declined —
    // either way there is nothing more for the user to do here.
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    // Read through `refresh()` so a prompt whose rendezvous token has died
    // stops offering to send: the join would have nothing to attach to.
    final uiState = PairChannelManager.instance.service?.refreshSyncRequest();
    final pending = uiState is common.SyncRequestUiStateDto_AwaitingApproval
        ? uiState
        : null;
    final failure =
        uiState is common.SyncRequestUiStateDto_Failed ? uiState : null;
    final deviceName = pending?.deviceName;

    return Scaffold(
      appBar: AppBar(title: const Text('Sync Request')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const SizedBox(height: 24),
            Icon(
              failure != null ? Icons.error_outline : Icons.history,
              size: 64,
              color: failure != null
                  ? Theme.of(context).colorScheme.error
                  : Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 24),
            Text(
              failure != null
                  ? 'Sync failed'
                  : 'One of your devices is asking for message history',
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
                child: Text(
                  deviceName == null || deviceName.isEmpty
                      ? 'Unnamed device'
                      : deviceName,
                  style: Theme.of(context)
                      .textTheme
                      .bodyLarge
                      ?.copyWith(fontWeight: FontWeight.bold),
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
                  // This screen belongs to the device that was *asked*, so
                  // it uses the responder wording: "no device answered"
                  // would be nonsense here — this is the device with the
                  // history.
                  common.responderFailureText(failure.reason),
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onErrorContainer,
                  ),
                ),
              ),
            const SizedBox(height: 8),
            if (failure == null)
              Text(
                'Send it the messages it is missing. Only this device and '
                'that one can read them.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
              ),
            const Spacer(),
            if (failure == null) ...[
              FilledButton(
                onPressed: _isLoading ? null : () => _respond(true),
                child: _isLoading
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Send History'),
              ),
              const SizedBox(height: 8),
              TextButton(
                onPressed: _isLoading ? null : () => _respond(false),
                child: const Text('Not Now'),
              ),
            ] else
              FilledButton(
                onPressed: () => Navigator.of(context).pop(),
                child: const Text('Close'),
              ),
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }
}
