import 'package:web/web.dart' as web;
import 'package:moat_dart_common/moat_dart_common.dart';

/// [DocumentBackend] backed by [window.localStorage] for the web platform.
///
/// Keys are stored as "moat:<path>" (e.g. "moat:conversations/conversations.json").
/// [list] returns full relative paths (e.g. "messages/abc.json") by scanning
/// all localStorage keys with the given directory prefix.
class LocalStorageDocumentBackend implements DocumentBackend {
  static const _prefix = 'moat:';

  String _key(String path) => '$_prefix$path';

  @override
  Future<String?> read(String path) async {
    return web.window.localStorage.getItem(_key(path));
  }

  @override
  Future<void> write(String path, String content) async {
    web.window.localStorage.setItem(_key(path), content);
  }

  @override
  Future<void> delete(String path) async {
    web.window.localStorage.removeItem(_key(path));
  }

  @override
  Future<List<String>> list(String directoryPath) async {
    final dirPrefix = _key(
      directoryPath.endsWith('/') ? directoryPath : '$directoryPath/',
    );
    final storage = web.window.localStorage;
    final result = <String>[];
    for (var i = 0; i < storage.length; i++) {
      final key = storage.key(i);
      if (key != null && key.startsWith(dirPrefix)) {
        result.add(key.substring(_prefix.length));
      }
    }
    return result;
  }
}
