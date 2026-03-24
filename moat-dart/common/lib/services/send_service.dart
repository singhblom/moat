import 'dart:convert';
import 'dart:typed_data';
import '../models/conversation.dart';
import '../models/message.dart';
import '../rust/api/simple.dart';
import '../utils/message_payload.dart';
import 'auth_service.dart';
import 'drawbridge_service.dart';
import 'debug_log.dart';

/// Service for sending encrypted messages.
class SendService {
  final AuthService _authService;

  SendService({required AuthService authService})
      : _authService = authService;

  /// Send a message to a conversation.
  Future<Message> sendMessage({
    required Conversation conversation,
    required String text,
    required String localId,
  }) async {
    final session = _authService.moatSession;
    final myDid = _authService.did;
    final deviceName = _authService.deviceName;

    if (session == null || myDid == null || deviceName == null) {
      throw SendException('Not authenticated');
    }

    final keyBundle = await _authService.getKeyBundle();
    if (keyBundle == null) {
      throw SendException('No key bundle available');
    }

    final mlsEpoch = await session.getGroupEpoch(groupId: conversation.groupId);
    moatLog('SendService: Sending message to ${conversation.groupIdHex}');
    moatLog('SendService: Conversation model epoch: ${conversation.epoch}');
    moatLog('SendService: MLS session epoch: $mlsEpoch');

    if (mlsEpoch != null && mlsEpoch != BigInt.from(conversation.epoch)) {
      moatLog('SendService: WARNING - Epoch mismatch! MLS=$mlsEpoch, model=${conversation.epoch}');
    }

    final structuredPayload = encodeTextMessagePayload(text);
    final preview = renderMessagePreview(structuredPayload);

    final event = EventDto(
      kind: EventKindDto.message,
      groupId: conversation.groupId,
      epoch: BigInt.from(conversation.epoch),
      payload: structuredPayload,
    );

    final result = await session.encryptEvent(
      groupId: conversation.groupId,
      keyBundle: keyBundle,
      event: event,
    );

    moatLog('SendService: Message encrypted, tag: ${_bytesToHex(result.tag)}');

    await _authService.saveMlsState();

    final uri = await _authService.atprotoClient.publishEvent(
      result.tag,
      result.ciphertext,
    );

    moatLog('SendService: Message published: $uri');

    final rkey = _extractRkey(uri);

    final relayUrls = DrawbridgeService.instance
        .relayUrlsForParticipants(conversation.participants);
    DrawbridgeService.instance.notifyEventPosted(
      tag: result.tag,
      rkey: rkey,
      payload: result.ciphertext,
      relayUrls: relayUrls,
    );

    return Message(
      id: '${conversation.groupIdHex}_$rkey',
      localId: localId,
      groupId: conversation.groupId,
      senderDid: myDid,
      senderDeviceId: '$myDid/$deviceName',
      content: preview,
      timestamp: DateTime.now(),
      isOwn: true,
      epoch: conversation.epoch,
      status: MessageStatus.sent,
      messageId: result.messageId != null ? Uint8List.fromList(result.messageId!) : null,
    );
  }

  /// Send a reaction to a message in a conversation.
  Future<void> sendReaction({
    required Conversation conversation,
    required List<int> targetMessageId,
    required String emoji,
  }) async {
    final session = _authService.moatSession;
    final myDid = _authService.did;
    final deviceName = _authService.deviceName;

    if (session == null || myDid == null || deviceName == null) {
      throw SendException('Not authenticated');
    }

    final keyBundle = await _authService.getKeyBundle();
    if (keyBundle == null) {
      throw SendException('No key bundle available');
    }

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

    final result = await session.encryptEvent(
      groupId: conversation.groupId,
      keyBundle: keyBundle,
      event: event,
    );

    moatLog('SendService: Reaction encrypted, tag: ${_bytesToHex(result.tag)}');

    await _authService.saveMlsState();

    final uri = await _authService.atprotoClient.publishEvent(
      result.tag,
      result.ciphertext,
    );

    final rkey = _extractRkey(uri);
    final relayUrls = DrawbridgeService.instance
        .relayUrlsForParticipants(conversation.participants);
    DrawbridgeService.instance.notifyEventPosted(
      tag: result.tag,
      rkey: rkey,
      payload: result.ciphertext,
      relayUrls: relayUrls,
    );

    moatLog('SendService: Reaction "$emoji" published');
  }

  String _extractRkey(String uri) {
    return uri.split('/').last;
  }

  String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

/// Exception thrown by send operations.
class SendException implements Exception {
  final String message;

  SendException(this.message);

  @override
  String toString() => 'SendException: $message';
}
