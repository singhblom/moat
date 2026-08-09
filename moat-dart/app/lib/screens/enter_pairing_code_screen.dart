import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../services/pairing_manager.dart';

/// Existing device: enter a pairing code either by scanning the other
/// device's QR code or by typing it in. Once confirmed, waits for the
/// other device's `Enroll` (which triggers [PairingManager]'s
/// `onApprovalPending` navigation to `ApprovePairingScreen`, pushed on top
/// of this screen) and for the pairing to complete.
class EnterPairingCodeScreen extends StatefulWidget {
  const EnterPairingCodeScreen({super.key});

  @override
  State<EnterPairingCodeScreen> createState() =>
      _EnterPairingCodeScreenState();
}

class _EnterPairingCodeScreenState extends State<EnterPairingCodeScreen> {
  final _formKey = GlobalKey<FormState>();
  final _codeController = TextEditingController();
  bool _isLoading = false;
  bool _confirmed = false;
  String? _error;
  Timer? _pollTimer;

  @override
  void dispose() {
    _pollTimer?.cancel();
    _codeController.dispose();
    super.dispose();
  }

  Future<void> _scan() async {
    final code = await Navigator.of(context).push<String>(
      MaterialPageRoute(builder: (_) => const _QrScanScreen()),
    );
    if (code != null && mounted) {
      _codeController.text = code;
      unawaited(_confirm());
    }
  }

  Future<void> _confirm() async {
    if (!_formKey.currentState!.validate()) return;
    final service = PairingManager.instance.service;
    if (service == null) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      await service.confirmCode(_codeController.text.trim());
      if (!mounted) return;
      setState(() {
        _isLoading = false;
        _confirmed = true;
      });
      _pollTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
        if (service.isDone && mounted) {
          _pollTimer?.cancel();
          Navigator.of(context).pop(true);
        }
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Enter Pairing Code')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Enter the code shown on your other device, or scan its QR code.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
              ),
              const SizedBox(height: 24),
              TextFormField(
                controller: _codeController,
                decoration: InputDecoration(
                  labelText: 'Pairing code',
                  border: const OutlineInputBorder(),
                  suffixIcon: IconButton(
                    icon: const Icon(Icons.qr_code_scanner),
                    tooltip: 'Scan QR code',
                    onPressed: _isLoading || _confirmed ? null : _scan,
                  ),
                ),
                maxLines: 3,
                enabled: !_isLoading && !_confirmed,
                validator: (value) {
                  if (value == null || value.trim().isEmpty) {
                    return 'Please enter a pairing code';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 16),
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
                ),
              if (_confirmed)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
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
                ),
              const Spacer(),
              if (!_confirmed)
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
        ),
      ),
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
