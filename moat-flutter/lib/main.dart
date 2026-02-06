import 'package:flutter/foundation.dart';
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
  if (!kIsWeb) {
    try {
      await RustLib.init();
      debugPrint('[moat] Rust library initialized');
    } catch (e) {
      debugPrint('[moat] Failed to initialize Rust library: $e');
    }
  } else {
    debugPrint('[moat] Skipping RustLib.init() on web for now');
  }
  debugPrint('[moat] Starting app...');
  runApp(const MoatApp());
}

TextTheme _applyPlatypiHeaders(TextTheme base) {
  const platypi = 'Platypi';
  return base.copyWith(
    displayLarge: base.displayLarge?.copyWith(fontFamily: platypi),
    displayMedium: base.displayMedium?.copyWith(fontFamily: platypi),
    displaySmall: base.displaySmall?.copyWith(fontFamily: platypi),
    headlineLarge: base.headlineLarge?.copyWith(fontFamily: platypi),
    headlineMedium: base.headlineMedium?.copyWith(fontFamily: platypi),
    headlineSmall: base.headlineSmall?.copyWith(fontFamily: platypi),
    titleLarge: base.titleLarge?.copyWith(fontFamily: platypi),
    titleMedium: base.titleMedium?.copyWith(fontFamily: platypi),
    titleSmall: base.titleSmall?.copyWith(fontFamily: platypi),
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
          fontFamily: 'Roboto',
          colorScheme: ColorScheme.fromSeed(
            seedColor: Color.fromRGBO(74, 232, 205, 255),
            brightness: Brightness.dark,
          ),
          textTheme: _applyPlatypiHeaders(ThemeData.dark().textTheme),
          useMaterial3: true,
        ),
        darkTheme: ThemeData(
          fontFamily: 'Roboto',
          colorScheme: ColorScheme.fromSeed(
            seedColor: Color.fromRGBO(19, 144, 123, 255),
            brightness: Brightness.light,
          ),
          textTheme: _applyPlatypiHeaders(ThemeData.light().textTheme),
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
      return const Scaffold(
        body: Center(
          child: CircularProgressIndicator(),
        ),
      );
    }

    if (auth.isAuthenticated) {
      return const ConversationsScreen();
    }

    return const LoginScreen();
  }
}
