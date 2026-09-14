import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// The session inbox's parked events are persisted because the polling
/// cursor has already moved past them: losing them loses the events.
void main() {
  late Directory dir;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('moat_parked_');
  });

  tearDown(() {
    dir.deleteSync(recursive: true);
  });

  SecureStorageService openStorage() =>
      SecureStorageService(storage: FileStorageBackend(dir));

  test('nothing is parked on a fresh device', () async {
    expect(await openStorage().loadParkedEvents(), isNull);
  });

  test('parked events survive a restart', () async {
    final bytes = Uint8List.fromList([0, 1, 2, 250, 255]);
    await openStorage().saveParkedEvents(bytes);

    expect(await openStorage().loadParkedEvents(), bytes);
  });
}
