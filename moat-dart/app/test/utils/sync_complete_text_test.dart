import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// The Flutter half of a wording pair: core carries the counts, each host
/// supplies the words. The Rust half is tested in
/// `crates/moat-cli/src/ui.rs`, and these cases mirror it one for one —
/// the two runtimes should not disagree about what a finished sync says.
SyncTallyDto tally(int messages, int conversations) => SyncTallyDto(
      messages: BigInt.from(messages),
      conversations: BigInt.from(conversations),
    );

void main() {
  group('syncCompleteText', () {
    test('an empty tally says the device had nothing new', () {
      expect(
        syncCompleteText(tally(0, 0), 'Pixel 8'),
        "Nothing new — Pixel 8 didn't have more than you.",
      );
    });

    test('a transfer reports what it moved and where from', () {
      expect(
        syncCompleteText(tally(412, 6), 'Pixel 8'),
        'Received 412 messages across 6 conversations from Pixel 8.',
      );
    });

    test('singular counts read as singular', () {
      expect(
        syncCompleteText(tally(1, 1), 'Laptop'),
        'Received 1 message across 1 conversation from Laptop.',
      );
    });

    test('an unnamed peer still reads as a sentence', () {
      expect(
        syncCompleteText(tally(0, 0), null),
        "Nothing new — that device didn't have more than you.",
      );
    });
  });
}
