import 'dart:io';
import 'storage_backend.dart';

/// File-based storage backend for the headless server.
///
/// Each key maps to a file at `<dir>/secure/<sanitized-key>.txt`.
/// Values are stored as plain text (SecureStorageService handles encoding above).
class FileStorageBackend implements StorageBackend {
  final Directory _dir;

  FileStorageBackend(Directory dir) : _dir = dir;

  Directory get _secureDir => Directory('${_dir.path}/secure');

  String _sanitizeKey(String key) =>
      key.replaceAll(RegExp(r'[^a-zA-Z0-9_\-]'), '_');

  File _fileFor(String key) {
    final name = _sanitizeKey(key);
    return File('${_secureDir.path}/$name.txt');
  }

  @override
  Future<String?> read(String key) async {
    final file = _fileFor(key);
    if (!await file.exists()) return null;
    return file.readAsString();
  }

  @override
  Future<void> write(String key, String value) async {
    await _secureDir.create(recursive: true);
    await _fileFor(key).writeAsString(value);
  }

  @override
  Future<void> delete(String key) async {
    final file = _fileFor(key);
    if (await file.exists()) await file.delete();
  }

  @override
  Future<void> deleteAll() async {
    if (await _secureDir.exists()) {
      await _secureDir.delete(recursive: true);
    }
  }
}
