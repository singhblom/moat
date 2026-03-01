import 'package:flutter/foundation.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

export 'package:moat_dart_common/moat_dart_common.dart' show WatchListEntry;

/// Provider for managing the watch list of DIDs to poll for invites.
/// Thin [ChangeNotifier] wrapper around [WatchListService].
class WatchListProvider extends ChangeNotifier {
  final WatchListService _service;

  // Local error state — provider owns dismissal lifecycle.
  String? _error;

  WatchListProvider({required WatchListService service}) : _service = service;

  List<WatchListEntry> get entries => _service.entries;
  List<String> get dids => _service.dids;
  bool get isLoading => _service.isLoading;
  String? get error => _error;
  bool get isEmpty => _service.isEmpty;

  Future<void> init() async {
    _error = null;
    await _service.init();
    _error = _service.error;
    notifyListeners();
  }

  Future<void> addHandle(String handle) async {
    _error = null;
    await _service.addHandle(handle);
    _error = _service.error;
    notifyListeners();
  }

  Future<void> removeDid(String did) async {
    await _service.removeDid(did);
    notifyListeners();
  }

  bool isWatching(String did) => _service.isWatching(did);

  void clearError() {
    _error = null;
    notifyListeners();
  }
}
