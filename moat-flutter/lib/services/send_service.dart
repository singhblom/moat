import 'dart:convert';
import 'dart:typed_data';
import '../models/conversation.dart';
import '../models/message.dart';
import '../providers/auth_provider.dart';
import '../src/rust/api/simple.dart';
import 'debug_log.dart';

/// Service for sending encrypted messages
class SendService {
  final AuthProvider _authProvider;

  SendService({required AuthProvider authProvider})
      : _authProvider = authProvider;

  /// Send a message to a conversation
  /// Returns the sent message with its final ID and status
  Future<Message> sendMessage({
    required Conversation conversation,
    required String text,
    required String localId,
  }) async {
    final session = _authProvider.moatSession;
    final myDid = _authProvider.did;
    final deviceName = _authProvider.deviceName;

    if (session == null || myDid == null || deviceName == null) {
      throw SendException('Not authenticated');
    }

    final keyBundle = await _authProvider.getKeyBundle();
    if (keyBundle == null) {
      throw SendException('No key bundle available');
    }

    // Get current epoch from MLS session (the source of truth)
    final mlsEpoch = await session.getGroupEpoch(groupId: conversation.groupId);
    moatLog('SendService: Sending message to ${conversation.groupIdHex}');
    moatLog('SendService: Conversation model epoch: ${conversation.epoch}');
    moatLog('SendService: MLS session epoch: $mlsEpoch');

    // Warn if epochs don't match - this could cause issues
    if (mlsEpoch != null && mlsEpoch != BigInt.from(conversation.epoch)) {
      moatLog('SendService: WARNING - Epoch mismatch! MLS=$mlsEpoch, model=${conversation.epoch}');
      moatLog('SendService: The conversation model may be stale. Consider refreshing before send.');
    }

    // Create event DTO with raw plaintext (moat-core handles padding internally)
    final plaintext = utf8.encode(text);

    final event = EventDto(
      kind: EventKindDto.message,
      groupId: conversation.groupId,
      epoch: BigInt.from(conversation.epoch),
      payload: plaintext,
    );

    // Encrypt via FFI
    final result = await session.encryptEvent(
      groupId: conversation.groupId,
      keyBundle: keyBundle,
      event: event,
    );

    moatLog('SendService: Message encrypted');
    moatLog('SendService: Tag used: ${_bytesToHex(result.tag)}');
    moatLog('SendService: Ciphertext length: ${result.ciphertext.length}');

    // Save updated MLS state
    await _authProvider.saveMlsState();
    moatLog('SendService: MLS state saved');

    // Publish to PDS
    moatLog('SendService: Publishing to PDS with tag ${_bytesToHex(result.tag)}');
    final uri = await _authProvider.atprotoClient.publishEvent(
      result.tag,
      result.ciphertext,
    );

    moatLog('SendService: Message published: $uri');
    moatLog('SendService: Send complete for localId=$localId');

    // Extract rkey from URI
    final rkey = _extractRkey(uri);

    // Create the final message (include messageId for reaction targeting)
    final message = Message(
      id: '${conversation.groupIdHex}_$rkey',
      localId: localId,
      groupId: conversation.groupId,
      senderDid: myDid,
      senderDeviceId: '$myDid/$deviceName',
      content: text,
      timestamp: DateTime.now(),
      isOwn: true,
      epoch: conversation.epoch,
      status: MessageStatus.sent,
      messageId: result.messageId != null ? Uint8List.fromList(result.messageId!) : null,
    );

    return message;
  }

  /// Send a reaction to a message in a conversation
  Future<void> sendReaction({
    required Conversation conversation,
    required List<int> targetMessageId,
    required String emoji,
  }) async {
    final session = _authProvider.moatSession;
    final myDid = _authProvider.did;
    final deviceName = _authProvider.deviceName;

    if (session == null || myDid == null || deviceName == null) {
      throw SendException('Not authenticated');
    }

    final keyBundle = await _authProvider.getKeyBundle();
    if (keyBundle == null) {
      throw SendException('No key bundle available');
    }

    // Construct the reaction payload JSON matching serde's serialization of ReactionPayload
    final reactionPayloadJson = jsonEncode({
      'emoji': emoji,
      'target_message_id': targetMessageId,
    });
    final payload = utf8.encode(reactionPayloadJson);

    final event = EventDto(
      kind: EventKindDto.reaction,
      groupId: conversation.groupId,
      epoch: BigInt.from(conversation.epoch),
      payload: payload,
    );

    // Encrypt via FFI
    final result = await session.encryptEvent(
      groupId: conversation.groupId,
      keyBundle: keyBundle,
      event: event,
    );

    moatLog('SendService: Reaction encrypted, tag: ${_bytesToHex(result.tag)}');

    // Save updated MLS state
    await _authProvider.saveMlsState();

    // Publish to PDS
    await _authProvider.atprotoClient.publishEvent(
      result.tag,
      result.ciphertext,
    );

    moatLog('SendService: Reaction "$emoji" published');
  }

  /// Extract rkey from AT URI (at://did:plc:xxx/social.moat.event/rkey)
  String _extractRkey(String uri) {
    return uri.split('/').last;
  }

  String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

/// Exception thrown by send operations
class SendException implements Exception {
  final String message;

  SendException(this.message);

  @override
  String toString() => 'SendException: $message';
}
