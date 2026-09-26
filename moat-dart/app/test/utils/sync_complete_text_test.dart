import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

/// The Flutter half of a wording pair: core carries the counts, each host
/// supplies the words. The Rust half is tested in
/// `crates/moat-cli/src/ui.rs`, and these cases mirror it one for one —
/// the two runtimes should not disagree about what a finished sync says.
SyncTallyDto tally(int messages, int conversations,
        {int sentMessages = 0, int sentConversations = 0}) =>
    SyncTallyDto(
      messages: BigInt.from(messages),
      conversations: BigInt.from(conversations),
      sentMessages: BigInt.from(sentMessages),
      sentConversations: BigInt.from(sentConversations),
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

    test('a donor reports what it sent', () {
      expect(
        syncCompleteText(
            tally(0, 0, sentMessages: 424, sentConversations: 1), 'bob3'),
        'Sent 424 messages across 1 conversation to bob3.',
      );
    });

    test('a two-way transfer reports both directions', () {
      expect(
        syncCompleteText(
            tally(3, 1, sentMessages: 1, sentConversations: 1), 'Laptop'),
        'Received 3 messages across 1 conversation from Laptop, and sent 1 message.',
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
