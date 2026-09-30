import 'dart:async';

import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;
import 'package:qr_flutter/qr_flutter.dart';
import '../services/pair_channel_manager.dart';
import '../widgets/common_listenable.dart';

/// New device: requests a pairing code and displays it as a QR code (plus
/// raw text as a manual-entry fallback), then waits for the existing
/// device to enter it and approve.
///
/// Renders off [PairChannelService.pairingState] rather than polling. On `Done`,
/// says so and waits to be dismissed, like the TUI — the history that
/// follows shows in the app-wide progress strip. On `Failed`, shows the
/// reason and waits.
class ShowPairingCodeScreen extends StatefulWidget {
  const ShowPairingCodeScreen({super.key});

  /// Whether this screen is up, so a failure it will show itself is not
  /// also reported app-wide.
  static bool get isOpen => _openCount > 0;
  static int _openCount = 0;

  @override
  State<ShowPairingCodeScreen> createState() => _ShowPairingCodeScreenState();
}

class _ShowPairingCodeScreenState extends State<ShowPairingCodeScreen> {
  bool _starting = true;
  String? _startError;

  @override
  void initState() {
    super.initState();
    ShowPairingCodeScreen._openCount++;
    _start();
  }

  Future<void> _start() async {
    final service = PairChannelManager.instance.service;
    if (service == null) {
      setState(() {
        _starting = false;
        _startError = 'Not signed in';
      });
      return;
    }
    try {
      await service.startPairing();
    } catch (e) {
      if (mounted) {
        setState(() {
          _starting = false;
          _startError = e.toString();
        });
      }
      return;
    }
    if (mounted) setState(() => _starting = false);
  }

  /// Abort a still-in-flight pairing when the user backs out — previously
  /// impossible, so a discarded QR left an attempt running invisibly.
  void _cancelIfInFlight() {
    final service = PairChannelManager.instance.service;
    final uiState = service?.pairingState.value;
    if (uiState is common.PairingUiStateDto_ShowingCode) {
      unawaited(service!.cancelPairing().catchError((Object e) {
        // Best-effort: the screen is already gone, nothing left to render.
      }));
    }
  }

  @override
  void dispose() {
    ShowPairingCodeScreen._openCount--;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      onPopInvokedWithResult: (didPop, result) {
        if (didPop) _cancelIfInFlight();
      },
      child: Scaffold(
        appBar: AppBar(title: const Text('Add This Device')),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: _buildBody(),
        ),
      ),
    );
  }

  Widget _buildBody() {
    if (_startError != null) {
      return _ErrorMessage(message: _startError!);
    }
    final service = PairChannelManager.instance.service;
    if (_starting || service == null) {
      return const Center(child: CircularProgressIndicator());
    }
    return ValueListenableBuilder<common.PairingUiStateDto>(
      valueListenable: service.pairingState.asFlutter,
      builder: (context, uiState, _) => _buildForState(context, uiState),
    );
  }

  Widget _buildForState(BuildContext context, common.PairingUiStateDto uiState) {
    if (uiState is common.PairingUiStateDto_Failed) {
      return _FailedView(
        reason: uiState.reason,
        onDismiss: () => Navigator.of(context).pop(),
      );
    }
    if (uiState is common.PairingUiStateDto_Done) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.check_circle_outline,
            size: 48,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 16),
          Text(
            'Paired!',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 24),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Continue'),
          ),
        ],
      );
    }
    if (uiState is! common.PairingUiStateDto_ShowingCode) {
      return const Center(child: CircularProgressIndicator());
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          'On your other device, choose "Enter a pairing code" and '
          'scan this QR code — or type the Drawbridge and code below.',
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
        ),
        const SizedBox(height: 24),
        Center(
          child: Container(
            padding: const EdgeInsets.all(16),
            color: Colors.white,
            child: QrImageView(
              data: uiState.uri,
              version: QrVersions.auto,
              size: 240,
            ),
          ),
        ),
        const SizedBox(height: 24),
        SelectableText(
          uiState.drawbridgeUrl,
          textAlign: TextAlign.center,
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(fontFamily: 'monospace'),
        ),
        const SizedBox(height: 8),
        SelectableText(
          uiState.code,
          textAlign: TextAlign.center,
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(fontFamily: 'monospace'),
        ),
        const SizedBox(height: 24),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
            const SizedBox(width: 12),
            Text(
              'Waiting for the other device…',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ],
        ),
      ],
    );
  }
}

class _ErrorMessage extends StatelessWidget {
  const _ErrorMessage({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.errorContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        message,
        style: TextStyle(color: Theme.of(context).colorScheme.onErrorContainer),
      ),
    );
  }
}

class _FailedView extends StatelessWidget {
  const _FailedView({required this.reason, required this.onDismiss});

  final String reason;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(
          Icons.error_outline,
          size: 48,
          color: Theme.of(context).colorScheme.error,
        ),
        const SizedBox(height: 16),
        Text(
          'Pairing failed',
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        _ErrorMessage(message: reason),
        const SizedBox(height: 24),
        FilledButton(onPressed: onDismiss, child: const Text('OK')),
      ],
    );
  }
}
