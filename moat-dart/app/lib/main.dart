import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:moat_dart_common/moat_dart_common.dart' hide DebugLog;
import 'providers/auth_provider.dart';
import 'providers/conversations_provider.dart';
import 'providers/profile_provider.dart';
import 'providers/theme_provider.dart';
import 'providers/watch_list_provider.dart';
import 'screens/login_screen.dart';
import 'screens/conversations_screen.dart';
import 'services/flutter_storage_backend.dart';
import 'services/flutter_storage_factory.dart';
import 'services/debug_log.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  debugPrint('[moat] main() started');
  await DebugLog.instance.init();
  debugPrint('[moat] DebugLog initialized');
  try {
    await RustLib.init();
    debugPrint('[moat] Rust library initialized');
  } catch (e) {
    debugPrint('[moat] Failed to initialize Rust library: $e');
  }

  final docBackend = await createDocumentBackend();
  final storageBackend = FlutterStorageBackend();

  debugPrint('[moat] Starting app...');
  runApp(MoatApp(docBackend: docBackend, storageBackend: storageBackend));
}

/// Apply custom fonts to the text theme.
TextTheme _applyFonts(TextTheme base) {
  const platypi = 'Platypi';

  TextStyle? withPlatypi(TextStyle? s, double weight) =>
      s?.copyWith(fontFamily: platypi, fontVariations: [FontVariation.weight(weight)]);

  return base.copyWith(
    displayLarge: withPlatypi(base.displayLarge, 400),
    displayMedium: withPlatypi(base.displayMedium, 400),
    displaySmall: withPlatypi(base.displaySmall, 400),
    headlineLarge: withPlatypi(base.headlineLarge, 600),
    headlineMedium: withPlatypi(base.headlineMedium, 600),
    headlineSmall: withPlatypi(base.headlineSmall, 600),
    titleLarge: withPlatypi(base.titleLarge, 600),
    titleMedium: withPlatypi(base.titleMedium, 500),
    titleSmall: withPlatypi(base.titleSmall, 500),
  );
}

class MoatApp extends StatelessWidget {
  final DocumentBackend docBackend;
  final StorageBackend storageBackend;

  const MoatApp({
    super.key,
    required this.docBackend,
    required this.storageBackend,
  });

  @override
  Widget build(BuildContext context) {
    final secureStorage = SecureStorageService(storage: storageBackend);
    final atprotoClient = AtprotoClient();
    final authService = AuthService(
      atprotoClient: atprotoClient,
      secureStorage: secureStorage,
    );
    final authProvider = AuthProvider(service: authService)..init();

    final convStorage = ConversationStorage(backend: docBackend);
    final convsService = ConversationsService(storage: convStorage);
    final conversationsProvider = ConversationsProvider(service: convsService)
      ..init();

    final msgStorage = MessageStorage(backend: docBackend);

    final profileCacheService =
        ProfileCacheService(client: atprotoClient, backend: docBackend);

    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => ThemeProvider()),
        ChangeNotifierProvider.value(value: authProvider),
        ChangeNotifierProvider.value(value: conversationsProvider),
        ChangeNotifierProxyProvider<AuthProvider, WatchListProvider>(
          create: (context) {
            final watchListService = WatchListService(
              atprotoClient: authProvider.atprotoClient,
              secureStorage: secureStorage,
            );
            return WatchListProvider(service: watchListService);
          },
          update: (context, auth, previous) {
            if (previous == null) {
              final watchListService = WatchListService(
                atprotoClient: auth.atprotoClient,
                secureStorage: secureStorage,
              );
              final provider = WatchListProvider(service: watchListService);
              if (auth.isAuthenticated) {
                provider.init();
              }
              return provider;
            }
            if (auth.isAuthenticated && previous.isEmpty) {
              previous.init();
            }
            return previous;
          },
        ),
        ChangeNotifierProxyProvider<AuthProvider, ProfileProvider>(
          create: (context) {
            final provider = ProfileProvider(cacheService: profileCacheService);
            provider.init();
            return provider;
          },
          update: (context, auth, previous) {
            if (previous == null) {
              final provider =
                  ProfileProvider(cacheService: profileCacheService);
              provider.init();
              return provider;
            }
            return previous;
          },
        ),
      ],
      child: Builder(
        builder: (context) {
          final themeMode = context.watch<ThemeProvider>().themeMode;
          return MaterialApp(
            title: 'Moat',
            debugShowCheckedModeBanner: false,
            themeMode: themeMode,
            theme: ThemeData(
              colorScheme: ColorScheme.fromSeed(
                seedColor: Color.fromRGBO(74, 232, 205, 255),
                brightness: Brightness.light,
              ),
              textTheme: _applyFonts(ThemeData.light().textTheme),
              useMaterial3: true,
            ),
            darkTheme: ThemeData(
              colorScheme: ColorScheme.fromSeed(
                seedColor: Color.fromRGBO(19, 144, 123, 255),
                brightness: Brightness.dark,
              ),
              textTheme: _applyFonts(ThemeData.dark().textTheme),
              useMaterial3: true,
            ),
            home: AuthGate(
              msgStorage: msgStorage,
              secureStorage: secureStorage,
            ),
          );
        },
      ),
    );
  }
}

class AuthGate extends StatefulWidget {
  final MessageStorage msgStorage;
  final SecureStorageService secureStorage;

  const AuthGate({
    super.key,
    required this.msgStorage,
    required this.secureStorage,
  });

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> with WidgetsBindingObserver {
  PollingService? _pollingService;
  bool _pollingStarted = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _pollingService?.dispose();
    DrawbridgeService.instance.disconnectAll();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        DrawbridgeService.instance.disconnectAll();
        _pollingService?.stopPolling();
        debugPrint('App backgrounded: Drawbridge disconnected, polling stopped');
      case AppLifecycleState.resumed:
        _pollingService?.startPolling();
        final auth = context.read<AuthProvider>();
        if (auth.isAuthenticated) {
          _initDrawbridge(auth);
        }
        debugPrint('App resumed: reconnecting Drawbridge, polling restarted');
      default:
        break;
    }
  }

  void _registerAllTags() {
    final auth = context.read<AuthProvider>();
    final conversations = context.read<ConversationsProvider>().conversations;
    if (!auth.isAuthenticated) return;

    final session = auth.moatSession;
    if (session == null) return;

    final allTags = <Uint8List>[];
    for (final conv in conversations) {
      final tags = session.populateCandidateTags(groupId: conv.groupId);
      allTags.addAll(tags.map((t) => Uint8List.fromList(t)));
    }

    DrawbridgeService.instance.watchTags(allTags);
  }

  void _startPollingIfNeeded(AuthProvider auth) {
    if (auth.isAuthenticated && !_pollingStarted) {
      _pollingStarted = true;
      _pollingService = PollingService(
        authService: auth.service,
        conversationsService: context.read<ConversationsProvider>().service,
        watchListService: context.read<WatchListProvider>().service,
        secureStorage: widget.secureStorage,
      );
      ConversationManager.instance.init(
        authService: auth.service,
        storage: widget.msgStorage,
      );

      _pollingService!.onNewConversation = () {
        context.read<ConversationsProvider>().refresh();
      };
      _pollingService!.startPolling();
      debugPrint('PollingService started');

      _initDrawbridge(auth);
    } else if (!auth.isAuthenticated && _pollingStarted) {
      _pollingService?.dispose();
      _pollingService = null;
      _pollingStarted = false;
      ConversationManager.instance.clear();
      DrawbridgeService.instance.reset();
      debugPrint('PollingService stopped, Drawbridge reset');
    }
  }

  Future<void> _initDrawbridge(AuthProvider auth) async {
    final keyBundle = await auth.getKeyBundle();
    if (keyBundle == null || auth.did == null) return;

    final db = DrawbridgeService.instance;
    db.init(did: auth.did!, keyBundle: Uint8List.fromList(keyBundle));

    db.onNewEvent = (event) {
      // For now, trigger a poll on any new event notification.
      // Inline decryption using event.payload can be added later.
      _pollingService?.poll();
    };

    await db.connectOwn(defaultDrawbridgeUrl);
    _registerAllTags();

    // Publish own drawbridge config.
    try {
      await auth.service.atprotoClient
          .publishDrawbridgeConfig(defaultDrawbridgeUrl);
    } catch (e) {
      debugPrint('Failed to publish drawbridge config: $e');
    }

    // Fetch partner drawbridge configs for all conversations.
    final conversations = context.read<ConversationsProvider>().conversations;
    final client = auth.service.atprotoClient;
    final participantDids = <String>{};
    for (final conv in conversations) {
      participantDids.addAll(conv.participants);
    }
    for (final did in participantDids) {
      if (!mounted) return;
      try {
        final urls = await client.fetchDrawbridgeConfig(did);
        db.cacheDrawbridgeConfig(did, urls);
      } catch (_) {}
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthProvider>();

    WidgetsBinding.instance.addPostFrameCallback((_) {
      _startPollingIfNeeded(auth);
    });

    if (auth.isLoading) {
      return Scaffold(
        body: Stack(
          children: [
            Container(
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surface,
                image: DecorationImage(
                  image: AssetImage('assets/tile_pattern.png'),
                  repeat: ImageRepeat.repeat,
                  opacity: 0.1,
                  colorFilter: ColorFilter.mode(
                    Theme.of(context).colorScheme.primary,
                    BlendMode.srcIn,
                  ),
                ),
              ),
            ),
            Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    'Moat',
                    style: Theme.of(context).textTheme.headlineLarge?.copyWith(
                          fontVariations: [FontVariation.weight(800)],
                        ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Messaging on ATProto',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context)
                              .colorScheme
                              .onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 32),
                  const CircularProgressIndicator(),
                ],
              ),
            ),
          ],
        ),
      );
    }

    if (auth.isAuthenticated) {
      return const ConversationsScreen();
    }

    return const LoginScreen();
  }
}
