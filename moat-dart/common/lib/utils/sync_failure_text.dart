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
  final received = _plural(tally.messages, 'message', 'messages');
  final convs = _plural(tally.conversations, 'conversation', 'conversations');
  final sent = _plural(tally.sentMessages, 'message', 'messages');
  final sentConvs =
      _plural(tally.sentConversations, 'conversation', 'conversations');
  return switch ((tally.messages > BigInt.zero, tally.sentMessages > BigInt.zero)) {
    (false, false) => 'Nothing new — $device didn\'t have more than you.',
    (false, true) => 'Sent $sent across $sentConvs to $device.',
    (true, false) => 'Received $received across $convs from $device.',
    (true, true) =>
      'Received $received across $convs from $device, and sent $sent.',
  };
}

/// A running transfer, naming each direction that is moving something —
/// the Dart half of `sync_progress_text` in moat-cli's `ui.rs`.
String syncProgressText(ffi.SyncProgressDto p) {
  if (p is! ffi.SyncProgressDto_Transferring) return 'Preparing history sync…';
  final parts = <String>[
    if (p.receiveTotal > BigInt.zero) '${p.received} of ${p.receiveTotal} received',
    if (p.sendTotal > BigInt.zero) '${p.sent} of ${p.sendTotal} sent',
  ];
  return parts.isEmpty
      ? 'Syncing history…'
      : 'Syncing history: ${parts.join(', ')}';
}

String _plural(BigInt n, String one, String many) =>
    '$n ${n == BigInt.one ? one : many}';
