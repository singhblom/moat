import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'providers/auth_provider.dart';
import 'providers/conversations_provider.dart';
import 'providers/profile_provider.dart';
import 'providers/watch_list_provider.dart';
import 'screens/login_screen.dart';
import 'screens/conversations_screen.dart';
import 'services/polling_service.dart';
import 'services/message_notifier.dart';
import 'services/debug_log.dart';
import 'src/rust/frb_generated.dart';

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
  debugPrint('[moat] Starting app...');
  runApp(const MoatApp());
}

/// Apply custom fonts to the text theme.
/// Platypi is used for display/headline/title styles.
/// Body/label styles use default Roboto (bundled for web COEP compatibility).
/// For emoji rendering, use [emojiTextStyle] on pure-emoji widgets only —
/// CanvasKit's greedy font matching means NotoColorEmoji cannot be mixed
/// with Roboto without breaking space/digit metrics.
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
  const MoatApp({super.key});

  @override
  Widget build(BuildContext context) {
    // Create AuthProvider first since others depend on it
    final authProvider = AuthProvider()..init();
    final conversationsProvider = ConversationsProvider()..init();

    return MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: authProvider),
        ChangeNotifierProvider.value(value: conversationsProvider),
        ChangeNotifierProxyProvider<AuthProvider, WatchListProvider>(
          create: (context) => WatchListProvider(
            atprotoClient: authProvider.atprotoClient,
          ),
          update: (context, auth, previous) {
            if (previous == null) {
              final provider = WatchListProvider(
                atprotoClient: auth.atprotoClient,
              );
              if (auth.isAuthenticated) {
                provider.init();
              }
              return provider;
            }
            // Re-initialize when auth state changes
            if (auth.isAuthenticated && previous.entries.isEmpty) {
              previous.init();
            }
            return previous;
          },
        ),
        ChangeNotifierProxyProvider<AuthProvider, ProfileProvider>(
          create: (context) => ProfileProvider(
            atprotoClient: authProvider.atprotoClient,
          ),
          update: (context, auth, previous) {
            if (previous == null) {
              final provider = ProfileProvider(
                atprotoClient: auth.atprotoClient,
              );
              provider.init();
              return provider;
            }
            return previous;
          },
        ),
      ],
      child: MaterialApp(
        title: 'Moat',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: Color.fromRGBO(74, 232, 205, 255),
            brightness: Brightness.dark,
          ),
          textTheme: _applyFonts(ThemeData.dark().textTheme),
          useMaterial3: true,
        ),
        darkTheme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: Color.fromRGBO(19, 144, 123, 255),
            brightness: Brightness.light,
          ),
          textTheme: _applyFonts(ThemeData.light().textTheme),
          useMaterial3: true,
        ),
        home: const AuthGate(),
      ),
    );
  }
}

/// Gate that shows login or main app based on auth state
class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  PollingService? _pollingService;
  bool _pollingStarted = false;

  @override
  void dispose() {
    _pollingService?.dispose();
    super.dispose();
  }

  void _startPollingIfNeeded(AuthProvider auth) {
    if (auth.isAuthenticated && !_pollingStarted) {
      _pollingStarted = true;
      // Start polling when authenticated
      _pollingService = PollingService(
        authProvider: auth,
        conversationsProvider: context.read<ConversationsProvider>(),
        watchListProvider: context.read<WatchListProvider>(),
      );
      _pollingService!.onNewConversation = () {
        // Refresh conversations when a new one is received
        context.read<ConversationsProvider>().refresh();
      };
      _pollingService!.onNewMessages = (groupIdHex, messages) {
        // Route messages to active MessagesProvider (if any)
        MessageNotifier.instance.notify(groupIdHex, messages);
      };
      _pollingService!.startPolling();
      debugPrint('PollingService started');
    } else if (!auth.isAuthenticated && _pollingStarted) {
      // Stop polling when logged out
      _pollingService?.dispose();
      _pollingService = null;
      _pollingStarted = false;
      debugPrint('PollingService stopped');
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthProvider>();

    // Start/stop polling based on auth state
    // Use addPostFrameCallback to avoid calling during build
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
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
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
