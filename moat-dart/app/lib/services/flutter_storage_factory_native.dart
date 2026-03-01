import 'package:path_provider/path_provider.dart';
import 'package:moat_dart_common/moat_dart_common.dart';

Future<DocumentBackend> createDocumentBackend() async {
  final dir = await getApplicationDocumentsDirectory();
  return IoDocumentBackend(dir);
}
