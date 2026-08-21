import 'dart:async';

import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as ffi show PairingUiStateDto_ShowingCode, PairingUiStateDto_Done;
import 'package:qr_flutter/qr_flutter.dart';
import '../services/pairing_manager.dart';

// TODO(pairing-ui-state Section D): replace this poll timer with a
// ValueListenableBuilder over `service.state` — this is a minimal
// compile-preserving patch for Section C's PairingService API change, not
// the real rewrite.

/// New device: requests a pairing code and displays it as a QR code (plus
/// raw text as a manual-entry fallback), then waits for the existing
/// device to enter it and approve.
class ShowPairingCodeScreen extends StatefulWidget {
  const ShowPairingCodeScreen({super.key});

  @override
  State<ShowPairingCodeScreen> createState() => _ShowPairingCodeScreenState();
}

class _ShowPairingCodeScreenState extends State<ShowPairingCodeScreen> {
  String? _code;
  String? _qrData;
  String? _error;
  Timer? _pollTimer;

  @override
  void initState() {
    super.initState();
    _start();
  }

  Future<void> _start() async {
    final service = PairingManager.instance.service;
    if (service == null) {
      setState(() => _error = 'Not signed in');
      return;
    }
    try {
      final code = await service.startEnroll();
      if (!mounted) return;
      // The QR carries the `moat-pair:` URI form (qr-pairing.md §2: lets a
      // handler reject foreign QRs cheaply); the text below stays in the
      // bare form since that's what a human types back on the other side.
      final uiState = service.state.value;
      setState(() {
        _code = code;
        _qrData = uiState is ffi.PairingUiStateDto_ShowingCode ? uiState.uri : code;
      });
      _pollTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
        if (service.state.value is ffi.PairingUiStateDto_Done && mounted) {
          _pollTimer?.cancel();
          Navigator.of(context).pop(true);
        }
      });
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    }
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Add This Device')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'On your other device, choose "Enter a pairing code" and '
              'scan this QR code — or type the code below.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
            const SizedBox(height: 24),
            if (_error != null)
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
              )
            else if (_code == null)
              const Center(child: CircularProgressIndicator())
            else ...[
              Center(
                child: Container(
                  padding: const EdgeInsets.all(16),
                  color: Colors.white,
                  child: QrImageView(
                    data: _qrData!,
                    version: QrVersions.auto,
                    size: 240,
                  ),
                ),
              ),
              const SizedBox(height: 24),
              SelectableText(
                _code!,
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
          ],
        ),
      ),
    );
  }
}
