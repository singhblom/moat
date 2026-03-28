/// Moat Dart Common — shared business logic for moat-flutter and moat-dart-server.
library moat_dart_common;

// Models
export 'models/conversation.dart';
export 'models/message.dart';
export 'models/bluesky_profile.dart';

// Utils
export 'utils/message_payload.dart';
export 'utils/welcome_envelope.dart';

// Storage
export 'services/storage_backend.dart';
export 'services/file_storage_backend.dart';
export 'services/secure_storage.dart';
export 'services/document_backend.dart';
export 'services/conversation_storage.dart';
export 'services/message_storage.dart';
export 'services/debug_log.dart';

// ATProto
export 'services/atproto_client.dart';
export 'services/blob_service.dart';

// Core services
export 'services/auth_service.dart';
export 'services/conversations_service.dart';
export 'services/watch_list_service.dart';
export 'services/polling_service.dart';
export 'services/send_service.dart';
export 'services/send_queue.dart';
export 'services/conversation_repository.dart';
export 'services/conversation_manager.dart';
export 'services/conversation_starter.dart';
export 'services/member_adder.dart';
export 'services/drawbridge_service.dart';
export 'services/profile_cache_service.dart';

// FRB bindings
export 'rust/api/simple.dart';
export 'rust/frb_generated.dart';
