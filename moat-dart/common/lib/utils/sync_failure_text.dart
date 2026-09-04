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
