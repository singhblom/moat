import 'package:flutter/widgets.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;

/// Bridges a `moat_dart_common` [common.ValueListenable] — Flutter-
/// independent, since `common` has no Flutter dependency (it's shared with
/// the headless `moat_dart_server`, which runs under plain `dart run`) —
/// into a widget that rebuilds on change. Same shape and behavior as
/// Flutter's real `ValueListenableBuilder`, just typed against `common`'s
/// stand-in instead.
class CommonValueListenableBuilder<T> extends StatefulWidget {
  const CommonValueListenableBuilder({
    super.key,
    required this.valueListenable,
    required this.builder,
  });

  final common.ValueListenable<T> valueListenable;
  final Widget Function(BuildContext context, T value) builder;

  @override
  State<CommonValueListenableBuilder<T>> createState() =>
      _CommonValueListenableBuilderState<T>();
}

class _CommonValueListenableBuilderState<T>
    extends State<CommonValueListenableBuilder<T>> {
  @override
  void initState() {
    super.initState();
    widget.valueListenable.addListener(_onChange);
  }

  @override
  void didUpdateWidget(covariant CommonValueListenableBuilder<T> oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.valueListenable != widget.valueListenable) {
      oldWidget.valueListenable.removeListener(_onChange);
      widget.valueListenable.addListener(_onChange);
    }
  }

  void _onChange() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    widget.valueListenable.removeListener(_onChange);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return widget.builder(context, widget.valueListenable.value);
  }
}
