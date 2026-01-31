import 'dart:async';
import 'package:flutter/foundation.dart';
import '../models/conversation.dart';
import '../providers/auth_provider.dart';
import '../providers/conversations_provider.dart';
import '../providers/watch_list_provider.dart';
import 'secure_storage.dart';

/// Service that polls for events from watched DIDs and processes invites
class PollingService {
  final AuthProvider _authProvider;
  final ConversationsProvider _conversationsProvider;
  final WatchListProvider _watchListProvider;
  final SecureStorageService _secureStorage;

  Timer? _pollTimer;
  bool _isPolling = false;

  /// Callback when a new conversation is received
  VoidCallback? onNewConversation;

  PollingService({
    required AuthProvider authProvider,
    required ConversationsProvider conversationsProvider,
    required WatchListProvider watchListProvider,
    SecureStorageService? secureStorage,
  })  : _authProvider = authProvider,
        _conversationsProvider = conversationsProvider,
        _watchListProvider = watchListProvider,
        _secureStorage = secureStorage ?? SecureStorageService();

  /// Start polling for events (every 5 seconds)
  void startPolling() {
    stopPolling();
    _pollTimer = Timer.periodic(const Duration(seconds: 5), (_) => poll());
    // Do an immediate poll
    poll();
  }

  /// Stop polling
  void stopPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  /// Perform a single poll cycle
  Future<void> poll() async {
    if (_isPolling) return;
    if (!_authProvider.isAuthenticated) return;

    _isPolling = true;

    try {
      // Poll our own DID for incoming welcome messages from other devices
      await _pollOwnDid();
      // Poll watched DIDs for invites
      await _pollWatchedDids();
    } catch (e) {
      debugPrint('Polling error: $e');
    } finally {
      _isPolling = false;
    }
  }

  /// Poll our own DID for incoming welcome messages (multi-device sync)
  Future<void> _pollOwnDid() async {
    final myDid = _authProvider.did;
    if (myDid == null) return;

    final client = _authProvider.atprotoClient;

    try {
      // Get last seen rkey for our own DID
      final lastRkey = await _secureStorage.getLastRkey(myDid);

      // Fetch new events from our own PDS
      final events = await client.fetchEvents(myDid, afterRkey: lastRkey);

      if (events.isEmpty) return;

      debugPrint('PollingService: Found ${events.length} events from own DID');

      // Track max rkey for pagination
      String? maxRkey = lastRkey;

      for (final event in events) {
        // Update max rkey
        if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
          maxRkey = event.rkey;
        }

        // Try to decrypt as stealth-encrypted welcome
        final welcomeBytes =
            await _authProvider.tryDecryptStealthPayload(event.ciphertext);

        if (welcomeBytes != null) {
          debugPrint('PollingService: Decrypted welcome from own DID (multi-device sync)');
          // This is a welcome from another device in the same account,
          // or from someone who invited us
          await _processWelcome(welcomeBytes, myDid);

          // Notify listeners
          onNewConversation?.call();
        }
      }

      // Save last rkey for pagination
      if (maxRkey != null) {
        await _secureStorage.saveLastRkey(myDid, maxRkey);
      }
    } catch (e, stack) {
      debugPrint('PollingService: Error polling own DID: $e');
      debugPrint('PollingService: Stack trace: $stack');
    }
  }

  /// Poll events from watched DIDs and try to process as invites
  Future<void> _pollWatchedDids() async {
    final watchedDids = _watchListProvider.dids;
    if (watchedDids.isEmpty) {
      debugPrint('PollingService: No watched DIDs');
      return;
    }

    debugPrint('PollingService: Polling ${watchedDids.length} watched DIDs');
    final client = _authProvider.atprotoClient;

    for (final did in watchedDids) {
      try {
        // Get last seen rkey for this DID
        final lastRkey = await _secureStorage.getLastRkey(did);
        debugPrint('PollingService: Fetching events from $did (afterRkey: $lastRkey)');

        // Fetch new events
        final events = await client.fetchEvents(did, afterRkey: lastRkey);
        debugPrint('PollingService: Found ${events.length} events from $did');

        if (events.isEmpty) continue;

        // Track max rkey for pagination
        String? maxRkey = lastRkey;

        for (final event in events) {
          debugPrint('PollingService: Processing event ${event.rkey}');

          // Update max rkey
          if (maxRkey == null || event.rkey.compareTo(maxRkey) > 0) {
            maxRkey = event.rkey;
          }

          // Try to decrypt as stealth-encrypted welcome
          final welcomeBytes =
              await _authProvider.tryDecryptStealthPayload(event.ciphertext);

          if (welcomeBytes != null) {
            debugPrint('PollingService: Successfully decrypted welcome from $did');
            // Success! This is an invite for us
            await _processWelcome(welcomeBytes, did);

            // Remove from watch list since we successfully joined
            await _watchListProvider.removeDid(did);

            // Notify listeners
            onNewConversation?.call();

            // Don't process more events from this DID - we've joined
            break;
          } else {
            debugPrint('PollingService: Could not decrypt event ${event.rkey} as welcome');
          }
        }

        // Save last rkey for pagination
        if (maxRkey != null) {
          await _secureStorage.saveLastRkey(did, maxRkey);
        }
      } catch (e, stack) {
        debugPrint('PollingService: Error polling DID $did: $e');
        debugPrint('PollingService: Stack trace: $stack');
        // Continue with other DIDs
      }
    }
  }

  /// Process a decrypted Welcome message
  Future<void> _processWelcome(Uint8List welcomeBytes, String senderDid) async {
    // Join the group
    final groupId = await _authProvider.processWelcome(welcomeBytes);

    // Derive and register epoch 1 tag
    final tag = _authProvider.deriveConversationTag(groupId, 1);
    await _authProvider.registerTag(tag, groupId);

    // Get all DIDs in the group to find the other participant(s)
    final groupDids = await _authProvider.getGroupDids(groupId);
    final myDid = _authProvider.did;

    // Filter out our own DID to get the other participant(s)
    final otherDids = groupDids.where((did) => did != myDid).toList();

    // Use the first other participant as the display name, or fall back to sender
    final participantDid = otherDids.isNotEmpty ? otherDids.first : senderDid;

    // Resolve participant handle
    String displayName;
    try {
      displayName = await _authProvider.atprotoClient.resolveHandle(participantDid);
    } catch (_) {
      displayName = participantDid;
    }

    debugPrint('PollingService: Joined group with participants: $groupDids, display: $displayName');

    // Create conversation
    final groupIdHex =
        groupId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    final conversation = Conversation(
      groupId: groupId,
      displayName: displayName,
      participants: otherDids.isNotEmpty ? otherDids : [senderDid],
      epoch: 1,
      keyBundleRef: 'key_bundle_$groupIdHex',
      createdAt: DateTime.now(),
    );

    // Save conversation
    await _conversationsProvider.saveConversation(conversation);
  }

  /// Dispose the service
  void dispose() {
    stopPolling();
  }
}
