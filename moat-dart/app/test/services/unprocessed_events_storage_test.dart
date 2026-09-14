import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// The retry buffer is persisted because the polling cursor has already
/// moved past the events in it: losing the buffer loses the events.
void main() {
  late Directory dir;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('moat_unprocessed_');
  });

  tearDown(() {
    dir.deleteSync(recursive: true);
  });

  SecureStorageService openStorage() =>
      SecureStorageService(storage: FileStorageBackend(dir));

  UnprocessedEvent event(String rkey, {int attempts = 0}) => UnprocessedEvent(
        sourceDid: 'did:plc:bob',
        record: EventRecord(
          uri: 'at://did:plc:bob/social.moat.event/$rkey',
          rkey: rkey,
          tag: Uint8List.fromList(List.filled(16, 7)),
          ciphertext: Uint8List.fromList([1, 2, 3]),
          createdAt: DateTime.utc(2026, 9, 13, 8),
        ),
        firstSeenMs: 1234,
        attempts: attempts,
      );

  test('the retry buffer survives a restart with its retry state', () async {
    await openStorage().saveUnprocessedEvents([event('a', attempts: 2)]);

    final loaded = await openStorage().loadUnprocessedEvents();

    expect(loaded, hasLength(1));
    final e = loaded.single;
    expect(e.sourceDid, 'did:plc:bob');
    expect(e.record.rkey, 'a');
    expect(e.record.uri, 'at://did:plc:bob/social.moat.event/a');
    expect(e.record.tag, List.filled(16, 7));
    expect(e.record.ciphertext, [1, 2, 3]);
    expect(e.record.createdAt, DateTime.utc(2026, 9, 13, 8));
    expect(e.firstSeenMs, 1234);
    expect(e.attempts, 2);
  });

  test('saving an empty buffer clears it', () async {
    final storage = openStorage();
    await storage.saveUnprocessedEvents([event('a')]);
    await storage.saveUnprocessedEvents([]);

    expect(await openStorage().loadUnprocessedEvents(), isEmpty);
  });
}
