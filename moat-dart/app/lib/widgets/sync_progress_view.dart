import 'package:flutter/material.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;

import '../services/pair_channel_manager.dart';
import 'common_listenable.dart';

/// Puts a progress strip under every screen while a transfer runs. Both
/// devices keep working during a sync, and the approving one has already
/// left the screen that started it, so the progress can't live on any one
/// screen. Stands aside while the keyboard is up, rather than leave the
/// screen above it padding for a keyboard it no longer sits against.
class SyncProgressFrame extends StatelessWidget {
  const SyncProgressFrame({super.key, required this.child});

  final Widget child;

  /// Stands in while logged out, so the tree keeps one shape across logins.
  static final _idle = ValueNotifier<common.SyncProgressDto?>(null);

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<common.PairChannelService?>(
      valueListenable: PairChannelManager.instance.listenable,
      builder: (context, service, _) =>
          ValueListenableBuilder<common.SyncProgressDto?>(
        valueListenable: service?.progress.asFlutter ?? _idle,
        builder: _frame,
      ),
    );
  }

  Widget _frame(
      BuildContext context, common.SyncProgressDto? progress, Widget? _) {
    final show = progress != null && MediaQuery.viewInsetsOf(context).bottom == 0;
    // One shape whether or not the strip shows: re-parenting the child
    // would rebuild the navigator and lose its stack.
    return Column(
      children: [
        Expanded(
          // When shown, the strip below takes the bottom safe area.
          child: MediaQuery.removePadding(
            context: context,
            removeBottom: show,
            child: child,
          ),
        ),
        if (show)
          Material(
            color: Theme.of(context).colorScheme.surfaceContainerHigh,
            child: SafeArea(
              top: false,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                child: _SyncProgressView(progress: progress),
              ),
            ),
          ),
      ],
    );
  }
}

/// What has moved, over a bar that fills against the known totals, or
/// sweeps while they are still being worked out.
class _SyncProgressView extends StatelessWidget {
  const _SyncProgressView({required this.progress});

  final common.SyncProgressDto progress;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          common.syncProgressText(progress),
          style: Theme.of(context).textTheme.bodyMedium,
        ),
        const SizedBox(height: 8),
        LinearProgressIndicator(
          value: switch (progress) {
            common.SyncProgressDto_Transferring(:final fraction) => fraction,
            _ => null,
          },
        ),
      ],
    );
  }
}
