import 'package:flutter/foundation.dart' as flutter;
import 'package:flutter/widgets.dart';
import 'package:provider/provider.dart';
import 'package:moat_dart_common/moat_dart_common.dart' as common;

/// `ListenableProvider` for a moat_dart_common model: dependents rebuild when
/// [listenable] changes.
class CommonListenableProvider<T> extends InheritedProvider<T> {
  CommonListenableProvider.value({
    super.key,
    required super.value,
    required common.ValueListenable<Object?> Function(T value) listenable,
    super.child,
  }) : super.value(
          startListening: (element, value) {
            final source = listenable(value);
            source.addListener(element.markNeedsNotifyDependents);
            return () =>
                source.removeListener(element.markNeedsNotifyDependents);
          },
        );
}

/// Adapts a moat_dart_common [common.ValueListenable] for Flutter widgets.
extension AsFlutterListenable<T> on common.ValueListenable<T> {
  flutter.ValueListenable<T> get asFlutter => _FlutterValueListenable(this);
}

class _FlutterValueListenable<T> implements flutter.ValueListenable<T> {
  _FlutterValueListenable(this._source);

  final common.ValueListenable<T> _source;

  @override
  T get value => _source.value;

  @override
  void addListener(VoidCallback listener) => _source.addListener(listener);

  @override
  void removeListener(VoidCallback listener) => _source.removeListener(listener);

  // Adapters over the same source are equal, so a rebuild keeps its listener.
  @override
  bool operator ==(Object other) =>
      other is _FlutterValueListenable<T> && identical(other._source, _source);

  @override
  int get hashCode => identityHashCode(_source);
}
