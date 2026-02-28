import 'package:flutter_test/flutter_test.dart';
import 'package:moat_flutter/main.dart';
import 'package:moat_flutter/src/rust/frb_generated.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());
  testWidgets('App starts', (WidgetTester tester) async {
    await tester.pumpWidget(const MoatApp());
    // App should show loading initially, then login screen
    await tester.pumpAndSettle();
    expect(find.text('Moat'), findsOneWidget);
  });
}
