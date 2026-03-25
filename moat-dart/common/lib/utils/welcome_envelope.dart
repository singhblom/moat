import 'dart:typed_data';

/// Welcome envelope magic bytes: "MWE1".
const _magic = [0x4D, 0x57, 0x45, 0x31];

/// Encode a Welcome into an envelope: `[MWE1][4-byte welcome_len BE][welcome][hints_json]`.
///
/// Matches the Rust CLI's `encode_welcome_envelope` format.
Uint8List encodeWelcomeEnvelope(Uint8List welcome) {
  const hintsJson = [0x5B, 0x5D]; // "[]"
  final len = welcome.length;
  final buf = Uint8List(4 + 4 + len + hintsJson.length);
  buf.setAll(0, _magic);
  buf[4] = (len >> 24) & 0xFF;
  buf[5] = (len >> 16) & 0xFF;
  buf[6] = (len >> 8) & 0xFF;
  buf[7] = len & 0xFF;
  buf.setAll(8, welcome);
  buf.setAll(8 + len, hintsJson);
  return buf;
}

/// Decode a Welcome envelope, stripping the header.
///
/// If the data doesn't start with the magic, throws a [FormatException].
Uint8List decodeWelcomeEnvelope(Uint8List data) {
  if (data.length < 8 ||
      data[0] != _magic[0] ||
      data[1] != _magic[1] ||
      data[2] != _magic[2] ||
      data[3] != _magic[3]) {
    throw FormatException('Invalid welcome envelope: missing MWE1 magic');
  }
  final welcomeLen = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
  if (data.length < 8 + welcomeLen) {
    throw FormatException('Invalid welcome envelope: truncated');
  }
  return data.sublist(8, 8 + welcomeLen);
}
