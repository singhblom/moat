import 'dart:io';
import 'package:args/args.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:moat_dart_common/moat_dart_common.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import '../lib/http/server.dart';

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addOption('http', mandatory: true, help: 'Listen address (host:port)')
    ..addOption('storage-dir', mandatory: true, help: 'State directory path')
    ..addOption('pds-url', help: 'PDS endpoint override URL')
    ..addOption('drawbridge-url', help: 'Drawbridge WebSocket URL')
    ..addOption('lib-path',
        mandatory: true, help: 'Path to librust_lib_moat_flutter.dylib');

  final ArgResults results;
  try {
    results = parser.parse(args);
  } catch (e) {
    stderr.writeln('Error: $e');
    stderr.writeln(parser.usage);
    exit(1);
  }

  final httpAddr = results['http'] as String;
  final storageDirPath = results['storage-dir'] as String;
  final pdsUrl = results['pds-url'] as String?;
  final drawbridgeUrl = results['drawbridge-url'] as String?;
  final libPath = results['lib-path'] as String;

  // Create storage directories.
  final storageDir = Directory(storageDirPath);
  await storageDir.create(recursive: true);

  // Initialize Rust FFI library.
  await RustLib.init(externalLibrary: ExternalLibrary.open(libPath));
  moatLog('Server: Rust FFI initialized from $libPath');

  // Set up storage.
  final storageBackend = FileStorageBackend(storageDir);
  final secureStorage = SecureStorageService(storage: storageBackend);
  final docBackend = IoDocumentBackend(storageDir);
  final convStorage = ConversationStorage(backend: docBackend);
  final msgStorage = MessageStorage(backend: docBackend);

  // Create services.
  final atprotoClient = AtprotoClient(pdsOverride: pdsUrl);
  final authService = AuthService(
    atprotoClient: atprotoClient,
    secureStorage: secureStorage,
  );
  final convsService = ConversationsService(storage: convStorage);
  final watchListService = WatchListService(
    atprotoClient: atprotoClient,
    secureStorage: secureStorage,
  );
  final pollingService = PollingService(
    authService: authService,
    conversationsService: convsService,
    watchListService: watchListService,
    secureStorage: secureStorage,
  );

  // Wire ConversationManager.
  ConversationManager.instance.init(
    authService: authService,
    storage: msgStorage,
  );

  // Wire Drawbridge push notifications to trigger polling.
  if (drawbridgeUrl != null) {
    DrawbridgeService.instance.onNewEvent = (_) {
      pollingService.pollOnce();
    };
  }

  // Build HTTP handler.
  final handler = buildRouter(
    authService: authService,
    convsService: convsService,
    watchListService: watchListService,
    pollingService: pollingService,
  );

  // Parse address.
  final colonIdx = httpAddr.lastIndexOf(':');
  final host = colonIdx >= 0 ? httpAddr.substring(0, colonIdx) : httpAddr;
  final port = colonIdx >= 0 ? int.parse(httpAddr.substring(colonIdx + 1)) : 8080;

  final server = await shelf_io.serve(handler, host, port);
  moatLog('Server: Listening on ${server.address.host}:${server.port}');
  print('moat-dart-server listening on ${server.address.host}:${server.port}');

  // Keep running until interrupted.
  await ProcessSignal.sigint.watch().first;
  moatLog('Server: Shutting down');
  await server.close();
}
