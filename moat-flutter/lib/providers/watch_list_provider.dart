import 'package:flutter/foundation.dart';
import '../services/secure_storage.dart';
import '../services/atproto_client.dart';

/// Entry in the watch list with DID and resolved handle
class WatchListEntry {
  final String did;
  final String handle;
  final DateTime addedAt;

  WatchListEntry({
    required this.did,
    required this.handle,
    required this.addedAt,
  });

  Map<String, dynamic> toJson() => {
        'did': did,
        'handle': handle,
        'addedAt': addedAt.toIso8601String(),
      };

  factory WatchListEntry.fromJson(Map<String, dynamic> json) => WatchListEntry(
        did: json['did'] as String,
        handle: json['handle'] as String,
        addedAt: DateTime.parse(json['addedAt'] as String),
      );
}

/// Provider for managing the watch list of DIDs to poll for invites
class WatchListProvider extends ChangeNotifier {
  final SecureStorageService _secureStorage;
  final AtprotoClient _atprotoClient;

  List<WatchListEntry> _entries = [];
  bool _isLoading = false;
  String? _error;

  WatchListProvider({
    required AtprotoClient atprotoClient,
    SecureStorageService? secureStorage,
  })  : _atprotoClient = atprotoClient,
        _secureStorage = secureStorage ?? SecureStorageService();

  List<WatchListEntry> get entries => List.unmodifiable(_entries);
  List<String> get dids => _entries.map((e) => e.did).toList();
  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get isEmpty => _entries.isEmpty;

  /// Initialize and load watch list from storage
  Future<void> init() async {
    _isLoading = true;
    notifyListeners();

    try {
      final storedDids = await _secureStorage.loadWatchList();
      // For now, we store just DIDs - handles need to be resolved
      // In a more complete implementation, we'd store full entries
      _entries = [];
      for (final did in storedDids) {
        try {
          final handle = await _atprotoClient.resolveHandle(did);
          _entries.add(WatchListEntry(
            did: did,
            handle: handle,
            addedAt: DateTime.now(),
          ));
        } catch (_) {
          // If we can't resolve handle, use DID as display
          _entries.add(WatchListEntry(
            did: did,
            handle: did,
            addedAt: DateTime.now(),
          ));
        }
      }
      _error = null;
    } catch (e) {
      debugPrint('Failed to load watch list: $e');
      _error = e.toString();
    }

    _isLoading = false;
    notifyListeners();
  }

  /// Add a handle to the watch list (resolves to DID)
  Future<void> addHandle(String handle) async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      // Resolve handle to DID
      final did = await _atprotoClient.resolveDid(handle);

      // Check for duplicates
      if (_entries.any((e) => e.did == did)) {
        _error = 'Already watching this user';
        _isLoading = false;
        notifyListeners();
        return;
      }

      // Add to list
      final entry = WatchListEntry(
        did: did,
        handle: handle,
        addedAt: DateTime.now(),
      );
      _entries.add(entry);

      // Persist
      await _secureStorage.saveWatchList(dids);
      _error = null;
    } catch (e) {
      debugPrint('Failed to add to watch list: $e');
      _error = e.toString();
    }

    _isLoading = false;
    notifyListeners();
  }

  /// Remove a DID from the watch list
  Future<void> removeDid(String did) async {
    _entries.removeWhere((e) => e.did == did);
    await _secureStorage.saveWatchList(dids);
    notifyListeners();
  }

  /// Check if a DID is being watched
  bool isWatching(String did) {
    return _entries.any((e) => e.did == did);
  }

  /// Clear error
  void clearError() {
    _error = null;
    notifyListeners();
  }
}
