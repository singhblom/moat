import 'auth_service.dart';
import 'conversation_manager.dart';
import 'conversations_service.dart';
import 'device_ring_service.dart';
import 'document_backend.dart';
import 'drawbridge_service.dart';
import 'message_storage.dart';
import 'pair_channel_service.dart';
import 'polling_service.dart';
import 'secure_storage.dart';
import 'watch_list_service.dart';

/// All post-login services that both the Flutter app and the headless
/// server need, wired identically.
///
/// Hosts call [createServiceBundle] once per login to get a bundle, then
/// do host-specific wiring (Flutter UI listeners, Drawbridge event
/// handlers, app-specific ConversationManagers) on the returned services.
class ServiceBundle {
  final DeviceRingService ring;
  final PairChannelService pairChannel;
  final PollingService polling;

  ServiceBundle._({
    required this.ring,
    required this.pairChannel,
    required this.polling,
  });
}

/// Construct and wire all shared post-login services.
///
/// Both the Flutter app and the headless server call this once per
/// login. The returned [ServiceBundle] contains fully-wired services
/// ready for host-specific additions (UI listeners, Drawbridge event
/// handlers, etc.).
///
/// Mirrors every service construction and property injection that
/// previously lived independently in `moat_dart_server.dart` and
/// `main.dart`'s `_startPollingIfNeeded` — a single site means a
/// missing injection can't diverge between hosts.
Future<ServiceBundle> createServiceBundle({
  required AuthService auth,
  required DrawbridgeService drawbridge,
  required DocumentBackend docBackend,
  required ConversationsService conversationsService,
  required WatchListService watchListService,
  required SecureStorageService secureStorage,
  required MessageStorage messageStorage,
}) async {
  final ring = DeviceRingService(
    auth: auth,
    backend: docBackend,
  );
  await ring.init();
  ring.convsService = conversationsService;

  final pairChannel = PairChannelService(
    auth: auth,
    drawbridge: drawbridge,
    ring: ring,
    conversationsService: conversationsService,
    messageStorage: messageStorage,
  );

  final polling = PollingService(
    authService: auth,
    conversationsService: conversationsService,
    watchListService: watchListService,
    secureStorage: secureStorage,
    ringService: ring,
  );
  polling.onRingMessage = pairChannel.onRingMessage;
  polling.onPollTick = pairChannel.expireIfDue;

  ConversationManager.instance.init(
    authService: auth,
    storage: messageStorage,
    ringService: ring,
  );

  return ServiceBundle._(
    ring: ring,
    pairChannel: pairChannel,
    polling: polling,
  );
}
