import '../rust/api/simple.dart' as ffi;

/// How a [ffi.SyncFailureDto] reads on the device that *asked* for history.
///
/// Core carries the fact, not the words: the same failure means different
/// things to each side, so a single message would be wrong on one of them.
/// Its counterpart is [responderFailureText]. Mirrors
/// `requester_failure_text` in `crates/moat-cli/src/ui.rs`.
String requesterFailureText(ffi.SyncFailureDto reason) {
  return reason.when(
    noAnswer: () => 'No device answered. Open Moat on the device that has '
        'your history and try again.',
    channelClosed: (detail) =>
        'The connection closed before the transfer finished ($detail).',
    publishFailed: (detail) => 'The request could not be sent ($detail).',
    // Responder-side outcomes. Rendered rather than hidden so a logic slip
    // surfaces instead of showing a blank failure.
    requestExpired: () => 'This request expired.',
    declined: () => 'Declined on this device.',
  );
}

/// How a [ffi.SyncFailureDto] reads on the device that was *asked* for
/// history — the one that already holds it.
String responderFailureText(ffi.SyncFailureDto reason) {
  return reason.when(
    requestExpired: () => 'The request expired before you answered it.',
    declined: () => 'You declined this request.',
    channelClosed: (detail) =>
        'The connection closed before the transfer finished ($detail).',
    // Cannot arise on this side; see the note above.
    noAnswer: () => 'The other device stopped waiting.',
    publishFailed: (detail) => 'The request could not be sent ($detail).',
  );
}

/// How a finished sync reads, on either side of it.
///
/// An empty tally is not a lesser success, it is a different answer: with
/// one donor per gesture it is what tells the user to go and approve on a
/// *different* device. Naming that device is the other half — "no more
/// than you" is only actionable once you know which sibling said it.
///
/// Core carries the counts, not the words. Mirrors `sync_complete_text`
/// in `crates/moat-cli/src/ui.rs`.
String syncCompleteText(ffi.SyncTallyDto tally, String? deviceName) {
  final device = deviceName ?? 'that device';
  if (tally.messages == BigInt.zero) {
    return 'Nothing new — $device didn\'t have more than you.';
  }
  final messages = _plural(tally.messages, 'message', 'messages');
  final conversations =
      _plural(tally.conversations, 'conversation', 'conversations');
  return 'Received $messages across $conversations from $device.';
}

String _plural(BigInt n, String one, String many) =>
    '$n ${n == BigInt.one ? one : many}';

/// What a sibling last advertised holding, for its line on the Devices
/// screen.
///
/// A hint, never a verdict: two devices can hold a hundred *different*
/// messages each and advertise the same count, so this narrows where to
/// ask rather than saying anyone is in sync. It states what was said, and
/// claims nothing further.
///
/// `null` means the sibling has not advertised at all, which is silence
/// rather than an answer — not the same as advertising nothing.
///
/// Mirrors `advertisement_text` in `crates/moat-cli/src/ui.rs`.
String advertisementText(ffi.SiblingSummaryDto? advertised) {
  if (advertised == null) return "hasn't said what it has yet";
  if (advertised.messages == BigInt.zero) return 'says it has no history';
  final messages = _plural(advertised.messages, 'message', 'messages');
  final conversations =
      _plural(advertised.conversations, 'conversation', 'conversations');
  return 'says it has $messages across $conversations';
}
