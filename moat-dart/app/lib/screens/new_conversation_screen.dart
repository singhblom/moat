import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:moat_dart_common/moat_dart_common.dart';
import '../providers/auth_provider.dart';
import '../providers/conversations_provider.dart';

class NewConversationScreen extends StatefulWidget {
  const NewConversationScreen({super.key});

  @override
  State<NewConversationScreen> createState() => _NewConversationScreenState();
}

class _NewConversationScreenState extends State<NewConversationScreen> {
  final _formKey = GlobalKey<FormState>();
  final _handleController = TextEditingController();
  bool _isLoading = false;
  String? _error;
  String? _statusMessage;

  @override
  void dispose() {
    _handleController.dispose();
    super.dispose();
  }

  Future<void> _createConversation() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
      _error = null;
      _statusMessage = 'Creating conversation...';
    });

    try {
      final auth = context.read<AuthProvider>();
      final conversations = context.read<ConversationsProvider>();
      final handle = _handleController.text.trim();

      final conversation = await startConversation(
        recipientHandle: handle,
        authService: auth.service,
        convsService: conversations.service,
      );

      if (mounted) {
        Navigator.of(context).pop(conversation);
      }
    } catch (e) {
      setState(() {
        _error = e.toString();
        _statusMessage = null;
      });
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
          _statusMessage = null;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('New Conversation'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Enter the handle of the person you want to message.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
              ),
              const SizedBox(height: 24),
              TextFormField(
                controller: _handleController,
                decoration: const InputDecoration(
                  labelText: 'Handle',
                  hintText: 'user.bsky.social',
                  prefixIcon: Icon(Icons.alternate_email),
                  border: OutlineInputBorder(),
                ),
                keyboardType: TextInputType.text,
                textInputAction: TextInputAction.done,
                autocorrect: false,
                enabled: !_isLoading,
                validator: (value) {
                  if (value == null || value.trim().isEmpty) {
                    return 'Please enter a handle';
                  }
                  // Basic validation - should contain at least one dot
                  if (!value.contains('.')) {
                    return 'Enter a full handle (e.g., user.bsky.social)';
                  }
                  return null;
                },
                onFieldSubmitted: (_) => _createConversation(),
              ),
              const SizedBox(height: 16),
              if (_error != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.errorContainer,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        Icons.error_outline,
                        color: Theme.of(context).colorScheme.onErrorContainer,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _error!,
                          style: TextStyle(
                            color:
                                Theme.of(context).colorScheme.onErrorContainer,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              if (_statusMessage != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                      const SizedBox(width: 12),
                      Text(_statusMessage!),
                    ],
                  ),
                ),
              const Spacer(),
              FilledButton(
                onPressed: _isLoading ? null : _createConversation,
                child: _isLoading
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Text('Create Conversation'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
