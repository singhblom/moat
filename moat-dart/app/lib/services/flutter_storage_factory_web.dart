import 'package:moat_dart_common/moat_dart_common.dart';
import 'local_storage_document_backend.dart';

Future<DocumentBackend> createDocumentBackend() async {
  return LocalStorageDocumentBackend();
}
