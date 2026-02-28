/// Abstract storage backend for key-value data.
///
/// Implementations: [FileStorageBackend] (server), FlutterStorageBackend (app).
abstract class StorageBackend {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
  Future<void> deleteAll();
}
