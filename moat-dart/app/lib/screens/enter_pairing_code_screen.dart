import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;
import '../services/pair_channel_manager.dart';
import '../widgets/common_listenable.dart';

/// Existing device: enter a pairing code either by scanning the other
/// device's QR code or by typing it in. Once confirmed, waits for the
/// other device's `Enroll` — which triggers `main.dart`'s `state` listener
/// to push `ApprovePairingScreen` on top of this one — and for the
/// pairing to complete. Renders straight off [PairChannelService.pairingState] via
/// [ValueListenableBuilder] rather than polling.
///
/// Deliberately does *not* pop itself on `Done`: `Navigator.pop()` removes
/// whatever is on top, and `Done` is only reached via a successful approve
/// inside `ApprovePairingScreen` — still on top at that instant. Popping
/// here would remove *that* screen, and its own unwind would then overshoot.
/// `ApprovePairingScreen._respond` is the sole place that unwinds.
class EnterPairingCodeScreen extends StatefulWidget {
  const EnterPairingCodeScreen({super.key});

  @override
  State<EnterPairingCodeScreen> createState() =>
      _EnterPairingCodeScreenState();
}

class _EnterPairingCodeScreenState extends State<EnterPairingCodeScreen> {
  final _formKey = GlobalKey<FormState>();
  final _codeController = TextEditingController();
  final _drawbridgeController = TextEditingController(
    // Devices from one distribution share a Drawbridge, so the common case needs
    // only the code.
    text: PairChannelManager.instance.service?.ownDrawbridgeUrl ?? '',
  );
  bool _isLoading = false;
  bool _confirmed = false;
  String? _confirmError;

  @override
  void dispose() {
    _codeController.dispose();
    _drawbridgeController.dispose();
    super.dispose();
  }

  /// Abort a still-in-flight pairing when the user backs out of this
  /// screen after confirming a code but before it completes.
  void _cancelIfInFlight() {
    final service = PairChannelManager.instance.service;
    final uiState = service?.pairingState.value;
    if (uiState is common.PairingUiStateDto_AwaitingPeer ||
        uiState is common.PairingUiStateDto_AwaitingApproval) {
      unawaited(service!.cancelPairing().catchError((Object e) {
        // Best-effort: the screen is already gone, nothing left to render.
      }));
    }
  }

  Future<void> _scan() async {
    final code = await Navigator.of(context).push<String>(
      MaterialPageRoute(builder: (_) => const _QrScanScreen()),
    );
    if (code != null && mounted) {
      // The QR is `moat-pair:<code>?drawbridge=<url>`: scanning fills both fields.
      final uri = Uri.tryParse(code);
      if (uri != null && uri.scheme == 'moat-pair') {
        _codeController.text = uri.path;
        final drawbridgeUrl = uri.queryParameters['drawbridge'];
        if (drawbridgeUrl != null && drawbridgeUrl.isNotEmpty) _drawbridgeController.text = drawbridgeUrl;
      } else {
        _codeController.text = code;
      }
      unawaited(_confirm());
    }
  }

  Future<void> _confirm() async {
    if (!_formKey.currentState!.validate()) return;
    final service = PairChannelManager.instance.service;
    if (service == null) return;

    setState(() {
      _isLoading = true;
      _confirmError = null;
    });

    try {
      await service.confirmPairingCode(
        _codeController.text.trim(),
        drawbridgeUrl: _drawbridgeController.text.trim(),
      );
      if (!mounted) return;
      setState(() {
        _isLoading = false;
        _confirmed = true;
      });
    } catch (e) {
      setState(() {
        _confirmError = e.toString();
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      onPopInvokedWithResult: (didPop, result) {
        if (didPop) _cancelIfInFlight();
      },
      child: Scaffold(
        appBar: AppBar(title: const Text('Enter Pairing Code')),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: _confirmed ? _buildWaitingOrFailed() : _buildForm(),
        ),
      ),
    );
  }

  Widget _buildForm() {
    return Form(
      key: _formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Enter the Drawbridge and code shown on your other device, or scan its '
            'QR code.',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
          const SizedBox(height: 24),
          TextFormField(
            controller: _drawbridgeController,
            decoration: const InputDecoration(
              labelText: 'Drawbridge',
              hintText: 'wss://drawbridge.example.com/ws',
              border: OutlineInputBorder(),
            ),
            keyboardType: TextInputType.url,
            autocorrect: false,
            enabled: !_isLoading,
            validator: (value) {
              if (value == null || value.trim().isEmpty) {
                return 'Please enter the Drawbridge shown beside the code';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),
          TextFormField(
            controller: _codeController,
            decoration: InputDecoration(
              labelText: 'Pairing code',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: const Icon(Icons.qr_code_scanner),
                tooltip: 'Scan QR code',
                onPressed: _isLoading ? null : _scan,
              ),
            ),
            maxLines: 3,
            enabled: !_isLoading,
            validator: (value) {
              if (value == null || value.trim().isEmpty) {
                return 'Please enter a pairing code';
              }
              return null;
            },
          ),
          const SizedBox(height: 16),
          if (_confirmError != null) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.errorContainer,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                _confirmError!,
                style: TextStyle(
                  color: Theme.of(context).colorScheme.onErrorContainer,
                ),
              ),
            ),
            const SizedBox(height: 16),
          ],
          const Spacer(),
          FilledButton(
            onPressed: _isLoading ? null : _confirm,
            child: _isLoading
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Colors.white,
                    ),
                  )
                : const Text('Continue'),
          ),
        ],
      ),
    );
  }

  Widget _buildWaitingOrFailed() {
    final service = PairChannelManager.instance.service;
    if (service == null) {
      return const Center(child: CircularProgressIndicator());
    }
    return ValueListenableBuilder<common.PairingUiStateDto>(
      valueListenable: service.pairingState.asFlutter,
      builder: (context, uiState, _) {
        if (uiState is common.PairingUiStateDto_Failed) {
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
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  uiState.reason,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onErrorContainer,
                  ),
                ),
              ),
              const SizedBox(height: 24),
              FilledButton(
                onPressed: () => Navigator.of(context).pop(false),
                child: const Text('OK'),
              ),
            ],
          );
        }
        // AwaitingPeer/AwaitingApproval (ApprovePairingScreen is pushed on
        // top for the latter); Done is about to pop via `_onStateChange`.
        return Center(
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              const SizedBox(width: 12),
              Text(
                'Waiting for the other device to approve…',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ],
          ),
        );
      },
    );
  }
}

/// Full-screen QR scanner. Pops with the decoded string on the first
/// successful detection.
class _QrScanScreen extends StatefulWidget {
  const _QrScanScreen();

  @override
  State<_QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<_QrScanScreen> {
  bool _handled = false;

  // Restrict detection to QR codes only — without this, scanning any
  // barcode in view (a poster's URL, a product barcode) silently fills the
  // pairing-code field with junk that only fails once it reaches the Rust
  // codec, instead of the scanner itself ignoring what it can't be.
  final MobileScannerController _controller = MobileScannerController(
    formats: const [BarcodeFormat.qrCode],
  );

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    final value = capture.barcodes.isNotEmpty
        ? capture.barcodes.first.rawValue
        : null;
    if (value == null || value.isEmpty) return;
    _handled = true;
    Navigator.of(context).pop(value);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan QR Code')),
      body: MobileScanner(controller: _controller, onDetect: _onDetect),
    );
  }
}
