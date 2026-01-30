import 'package:flutter/material.dart';
import 'package:moat_flutter/src/rust/api/simple.dart';
import 'package:moat_flutter/src/rust/frb_generated.dart';

Future<void> main() async {
  await RustLib.init();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    final session = MoatSessionHandle.newSession();
    final deviceId = session.deviceId();
    final hexId = deviceId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('Moat')),
        body: Center(
          child: Text('Device ID: $hexId'),
        ),
      ),
    );
  }
}
