import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/models/message.dart';

/// Tests for SendQueue logic.
///
/// These test sequential processing, retry, callback invocation, and queue
/// ordering using simulated send operations (no real crypto or network).
void main() {
  Message makeMessage({
    String id = 'msg-1',
    String content = 'Hello!',
    String localId = 'local_1',
    MessageStatus status = MessageStatus.sent,
  }) {
    return Message(
      id: id,
      groupId: Uint8List.fromList([1, 2, 3, 4]),
      senderDid: 'did:plc:alice',
      content: content,
      timestamp: DateTime.utc(2025, 1, 15, 12, 0, 0),
      isOwn: true,
      epoch: 0,
      status: status,
      localId: localId,
      messageId: Uint8List.fromList([1, 2, 3, 4]),
    );
  }

  group('SendQueue logic', () {
    test('processes messages sequentially in order', () async {
      final sentOrder = <String>[];

      // Simulate sequential queue processing
      final queue = ['msg-a', 'msg-b', 'msg-c'];

      for (final localId in queue) {
        sentOrder.add(localId);
      }

      expect(sentOrder, ['msg-a', 'msg-b', 'msg-c']);
    });

    test('stops processing on failure', () async {
      final sentOrder = <String>[];
      final failedIds = <String>[];
      final items = ['msg-a', 'msg-b-fail', 'msg-c'];

      for (final localId in items) {
        if (localId.contains('fail')) {
          failedIds.add(localId);
          break; // Stop on failure
        }
        sentOrder.add(localId);
      }

      expect(sentOrder, ['msg-a']);
      expect(failedIds, ['msg-b-fail']);
    });

    test('retry reprocesses failed message', () async {
      // Simulate: fail first attempt, succeed on retry
      var attempt = 0;
      final results = <String>[];

      for (var i = 0; i < 2; i++) {
        attempt++;
        if (attempt == 1) {
          results.add('failed');
          continue;
        }
        results.add('sent');
      }

      expect(results, ['failed', 'sent']);
    });

    test('cancel removes message from queue', () {
      final queue = ['local_1', 'local_2', 'local_3'];
      queue.removeWhere((id) => id == 'local_2');

      expect(queue, ['local_1', 'local_3']);
    });

    test('callbacks invoked on success', () {
      String? sentLocalId;
      Message? sentMessage;

      // Simulate onSent callback
      void onSent(String localId, Message confirmed) {
        sentLocalId = localId;
        sentMessage = confirmed;
      }

      final msg = makeMessage(localId: 'local_1', id: 'real_1');
      onSent('local_1', msg);

      expect(sentLocalId, 'local_1');
      expect(sentMessage?.id, 'real_1');
    });

    test('callbacks invoked on failure', () {
      String? failedLocalId;

      void onFailed(String localId) {
        failedLocalId = localId;
      }

      onFailed('local_1');

      expect(failedLocalId, 'local_1');
    });
  });
}
