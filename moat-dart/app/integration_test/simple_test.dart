import 'package:flutter_test/flutter_test.dart';
import 'package:moat_dart_common/moat_dart_common.dart' show RustLib;
import 'package:moat_flutter/main.dart';
import 'package:moat_flutter/services/flutter_storage_backend.dart';
import 'package:moat_flutter/services/flutter_storage_factory.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());
  testWidgets('App starts', (WidgetTester tester) async {
    final docBackend = await createDocumentBackend();
    final storageBackend = FlutterStorageBackend();
    await tester.pumpWidget(
        MoatApp(docBackend: docBackend, storageBackend: storageBackend));
    // App should show loading initially, then login screen
    await tester.pumpAndSettle();
    expect(find.text('Moat'), findsOneWidget);
  });
}
