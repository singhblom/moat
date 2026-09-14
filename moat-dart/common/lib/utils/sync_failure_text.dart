import '../rust/api/simple.dart' as ffi;

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
