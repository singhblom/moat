import 'dart:io';

/// Abstract backend for document (file-like) storage.
///
/// Implementations: [IoDocumentBackend] (server + native app), and
/// LocalStorageDocumentBackend in the Flutter app (web).
///
/// All paths are relative to a root (e.g. "conversations/conversations.json").
abstract class DocumentBackend {
  Future<String?> read(String path);
  Future<void> write(String path, String content);
  Future<void> delete(String path);
  /// List all file paths under [directoryPath], returned as full relative paths
  /// (e.g. list("messages") → ["messages/abc.json", "messages/def.json"]).
  Future<List<String>> list(String directoryPath);
}

/// [DocumentBackend] backed by [dart:io] [File] under a root [Directory].
class IoDocumentBackend implements DocumentBackend {
  final Directory _root;

  IoDocumentBackend(this._root);

  File _file(String path) => File('${_root.path}/$path');

  @override
  Future<String?> read(String path) async {
    final file = _file(path);
    if (!await file.exists()) return null;
    return file.readAsString();
  }

  @override
  Future<void> write(String path, String content) async {
    final file = _file(path);
    await file.parent.create(recursive: true);
    await file.writeAsString(content);
  }

  @override
  Future<void> delete(String path) async {
    final file = _file(path);
    if (await file.exists()) await file.delete();
  }

  @override
  Future<List<String>> list(String directoryPath) async {
    final dir = Directory('${_root.path}/$directoryPath');
    if (!await dir.exists()) return [];
    final entities = await dir.list().toList();
    final rootLen = _root.path.length;
    return entities
        .whereType<File>()
        .map((f) => f.path.substring(rootLen + 1))
        .toList();
  }
}
