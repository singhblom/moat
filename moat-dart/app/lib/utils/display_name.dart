import '../providers/profile_provider.dart';

/// Resolve the best display name for a DID from the profile cache.
/// Fallback chain: displayName > handle > truncated DID.
String resolveDidDisplayName(ProfileProvider profileProvider, String did) {
  final profile = profileProvider.getCachedProfile(did);
  if (profile != null) {
    final dn = profile.displayName;
    if (dn != null && dn.isNotEmpty) return dn;
    return profile.handle;
  }
  if (did.startsWith('did:plc:')) {
    final short = did.substring(8);
    return short.length > 8 ? short.substring(0, 8) : short;
  }
  return did.isNotEmpty ? did : 'unknown';
}
