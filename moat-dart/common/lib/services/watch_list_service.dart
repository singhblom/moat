import 'atproto_client.dart';
import 'secure_storage.dart';
import 'debug_log.dart';

/// Entry in the watch list with DID and resolved handle.
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

/// Service for managing the watch list of DIDs to poll for invites.
/// No Flutter dependency — pure Dart extracted from WatchListProvider.
class WatchListService {
  final SecureStorageService _secureStorage;
  final AtprotoClient _atprotoClient;

  List<WatchListEntry> _entries = [];
  bool _isLoading = false;
  String? _error;

  WatchListService({
    required AtprotoClient atprotoClient,
    required SecureStorageService secureStorage,
  })  : _atprotoClient = atprotoClient,
        _secureStorage = secureStorage;

  List<WatchListEntry> get entries => List.unmodifiable(_entries);
  List<String> get dids => _entries.map((e) => e.did).toList();
  bool get isLoading => _isLoading;
  String? get error => _error;
  bool get isEmpty => _entries.isEmpty;

  /// Initialize and load watch list from storage.
  Future<void> init() async {
    _isLoading = true;

    try {
      final storedDids = await _secureStorage.loadWatchList();
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
          _entries.add(WatchListEntry(
            did: did,
            handle: did,
            addedAt: DateTime.now(),
          ));
        }
      }
      _error = null;
    } catch (e) {
      moatLog('WatchListService: Failed to load watch list: $e');
      _error = e.toString();
    }

    _isLoading = false;
  }

  /// Add a handle to the watch list (resolves to DID).
  Future<void> addHandle(String handle) async {
    _isLoading = true;
    _error = null;

    try {
      final did = await _atprotoClient.resolveDid(handle);

      if (_entries.any((e) => e.did == did)) {
        _error = 'Already watching this user';
        _isLoading = false;
        return;
      }

      final entry = WatchListEntry(
        did: did,
        handle: handle,
        addedAt: DateTime.now(),
      );
      _entries.add(entry);

      await _secureStorage.saveWatchList(dids);
      _error = null;
    } catch (e) {
      moatLog('WatchListService: Failed to add to watch list: $e');
      _error = e.toString();
    }

    _isLoading = false;
  }

  /// Remove a DID from the watch list.
  Future<void> removeDid(String did) async {
    _entries.removeWhere((e) => e.did == did);
    await _secureStorage.saveWatchList(dids);
  }

  /// Check if a DID is being watched.
  bool isWatching(String did) {
    return _entries.any((e) => e.did == did);
  }
}
