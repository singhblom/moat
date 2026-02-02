import 'dart:convert';
import 'dart:typed_data';
import '../models/message.dart';
import '../models/conversation.dart';
import '../services/atproto_client.dart';
import '../services/message_storage.dart';
import '../services/debug_log.dart';
import '../src/rust/api/simple.dart';

/// Service for decrypting and processing MLS messages
class MessageService {
  final MessageStorage _messageStorage;
  MoatSessionHandle? _session;
  String? _myDid;

  MessageService({
    MessageStorage? messageStorage,
  }) : _messageStorage = messageStorage ?? MessageStorage();

  /// Initialize with session and user info
  Future<void> init(MoatSessionHandle session, String myDid) async {
    _session = session;
    _myDid = myDid;
  }

  /// Decrypt an event and return a Message if it's a displayable message
  /// Returns null for commits, welcomes, checkpoints, or on decryption failure
  Future<DecryptEventResult?> decryptEvent(
    EventRecord record,
    Conversation conversation,
  ) async {
    if (_session == null) {
      moatLog('MessageService: Session not initialized');
      return null;
    }

    try {
      // Decrypt the event
      final result = await _session!.decryptEvent(
        groupId: conversation.groupId,
        ciphertext: record.ciphertext,
      );

      // Handle by event kind
      switch (result.event.kind) {
        case EventKindDto.message:
          // Unpad and decode text
          final plaintext = unpad(padded: result.event.payload);
          final text = utf8.decode(plaintext);

          // Get sender info from MLS credential (extracted during decryption)
          final senderDid = result.sender?.did ?? 'unknown';
          final senderDeviceName = result.sender?.deviceName;
          final isOwn = senderDid == _myDid;

          final message = Message(
            id: '${conversation.groupIdHex}_${record.rkey}',
            groupId: conversation.groupId,
            senderDid: senderDid,
            senderDeviceId: senderDeviceName,
            content: text,
            timestamp: record.createdAt,
            isOwn: isOwn,
            epoch: result.event.epoch.toInt(),
          );

          return DecryptEventResult(
            message: message,
            newGroupState: result.newGroupState,
            newEpoch: null, // No epoch change for regular messages
          );

        case EventKindDto.commit:
          // Epoch advanced - need to update tag map
          final newEpoch = result.event.epoch.toInt();
          moatLog('MessageService: Commit received, new epoch: $newEpoch');

          return DecryptEventResult(
            message: null,
            newGroupState: result.newGroupState,
            newEpoch: newEpoch,
          );

        case EventKindDto.welcome:
        case EventKindDto.checkpoint:
          // Not displayable, but still update state
          return DecryptEventResult(
            message: null,
            newGroupState: result.newGroupState,
            newEpoch: null,
          );
      }
    } catch (e) {
      moatLog('MessageService: Failed to decrypt event ${record.rkey}: $e');
      return null;
    }
  }

  /// Load messages for a conversation
  Future<List<Message>> loadMessages(String groupIdHex) async {
    return await _messageStorage.loadMessages(groupIdHex);
  }

  /// Save a message to storage
  Future<void> saveMessage(String groupIdHex, Message message) async {
    await _messageStorage.appendMessage(groupIdHex, message);
  }

  /// Save multiple messages to storage
  Future<void> saveMessages(String groupIdHex, List<Message> messages) async {
    await _messageStorage.appendMessages(groupIdHex, messages);
  }
}

/// Result of decrypting an event
class DecryptEventResult {
  /// The decrypted message, if this was a message event
  final Message? message;

  /// Updated MLS group state (must be persisted)
  final Uint8List newGroupState;

  /// New epoch if this was a commit event
  final int? newEpoch;

  DecryptEventResult({
    required this.message,
    required this.newGroupState,
    required this.newEpoch,
  });
}
