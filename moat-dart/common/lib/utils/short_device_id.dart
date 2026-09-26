/// A hex device id shortened the way git shortens a commit.
///
/// The device id has to be the discriminator: every device of one user
/// shares the DID, and the device name is kind + hostname, so two devices
/// of the same kind are identical without it. Mirrors `short_id` in
/// `crates/moat-cli/src/ui.rs`.
String shortDeviceId(String hexId) {
  const shortLen = 8;
  if (hexId.isEmpty) return '?';
  return hexId.length <= shortLen ? hexId : hexId.substring(0, shortLen);
}
