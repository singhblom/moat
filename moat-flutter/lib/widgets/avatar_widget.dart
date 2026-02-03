import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../providers/profile_provider.dart';

/// Avatar widget that displays a profile picture or fallback initials
class AvatarWidget extends StatelessWidget {
  final String did;
  final double size;
  final String? fallbackText;

  const AvatarWidget({
    super.key,
    required this.did,
    this.size = 40,
    this.fallbackText,
  });

  @override
  Widget build(BuildContext context) {
    final profileProvider = context.watch<ProfileProvider>();
    final profile = profileProvider.getCachedProfile(did);
    final avatarUrl = profile?.avatarUrl;
    final displayText = fallbackText ??
        profile?.displayName?.characters.first.toUpperCase() ??
        profile?.handle.characters.first.toUpperCase() ??
        '?';

    return CircleAvatar(
      radius: size / 2,
      backgroundColor: Theme.of(context).colorScheme.primaryContainer,
      backgroundImage: avatarUrl != null ? NetworkImage(avatarUrl) : null,
      onBackgroundImageError: avatarUrl != null ? (_, _) {} : null,
      child: avatarUrl == null
          ? Text(
              displayText,
              style: TextStyle(
                color: Theme.of(context).colorScheme.onPrimaryContainer,
                fontSize: size * 0.4,
              ),
            )
          : null,
    );
  }
}
