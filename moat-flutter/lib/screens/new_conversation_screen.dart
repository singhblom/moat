import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/conversation.dart';
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
      _statusMessage = 'Resolving handle...';
    });

    try {
      final auth = context.read<AuthProvider>();
      final conversations = context.read<ConversationsProvider>();
      final client = auth.atprotoClient;
      final handle = _handleController.text.trim();

      // 1. Resolve handle to DID
      final recipientDid = await client.resolveDid(handle);

      // Check we're not creating a conversation with ourselves
      if (recipientDid == auth.did) {
        throw Exception('Cannot create a conversation with yourself');
      }

      setState(() {
        _statusMessage = 'Fetching stealth addresses...';
      });

      // 2. Fetch all of the recipient's stealth addresses (one per device)
      final stealthRecords = await client.fetchStealthAddresses(recipientDid);
      if (stealthRecords.isEmpty) {
        throw Exception('Recipient has no stealth address published. They may need to update their Moat client.');
      }

      // Collect all device public keys for multi-recipient encryption
      final stealthPubkeys = stealthRecords.map((r) => r.scanPubkey).toList();

      setState(() {
        _statusMessage = 'Fetching key packages...';
      });

      // 3. Fetch recipient's key packages
      final keyPackages = await client.fetchKeyPackages(recipientDid);
      if (keyPackages.isEmpty) {
        throw Exception('Recipient has no valid key packages');
      }

      // Use the first (most recent) key package
      final recipientKeyPackage = keyPackages.first.keyPackage;

      setState(() {
        _statusMessage = 'Creating encrypted group...';
      });

      // 4. Create conversation via AuthProvider (encrypts for all devices)
      final result = await auth.createConversation(
        recipientDid: recipientDid,
        recipientStealthPubkeys: stealthPubkeys,
        recipientKeyPackage: recipientKeyPackage,
      );

      setState(() {
        _statusMessage = 'Publishing invite...';
      });

      // 5. Publish the stealth-encrypted welcome with random tag
      await client.publishEvent(result.randomTag, result.stealthCiphertext);

      // 6. Register epoch 1 tag for this conversation
      final epoch1Tag = auth.deriveConversationTag(result.groupId, 1);
      await auth.registerTag(epoch1Tag, result.groupId);

      // 7. Create and save conversation locally
      final groupIdHex = result.groupId
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();

      final conversation = Conversation(
        groupId: result.groupId,
        displayName: handle,
        participants: [recipientDid],
        epoch: result.epoch,
        keyBundleRef: 'key_bundle_$groupIdHex',
        createdAt: DateTime.now(),
      );

      await conversations.saveConversation(conversation);

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
