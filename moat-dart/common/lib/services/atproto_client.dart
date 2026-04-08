import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

import '../models/bluesky_profile.dart';
import 'debug_log.dart';

/// Decode an ATProto IPLD bytes field: `{"$bytes": "<base64>"}`.
///
/// The real ATProto PDS (and Postern) returns unpadded base64 per the DAG-JSON
/// spec.  `base64.normalize()` re-adds the `=` padding that `base64Decode`
/// requires before decoding.
Uint8List _decodeBytesField(dynamic field) {
  if (field is Map) {
    final b64 = field[r'$bytes'] as String?;
    if (b64 != null) return base64Decode(base64.normalize(b64));
  }
  throw FormatException('Expected ATProto bytes field {"\$bytes": "..."}, got: $field');
}

/// ATProto lexicon NSIDs
const keyPackageNsid = 'social.moat.keyPackage';
const eventNsid = 'social.moat.event';
const stealthAddressNsid = 'social.moat.stealthAddress';
const drawbridgeConfigNsid = 'social.moat.drawbridgeConfig';

/// MLS ciphersuite identifier
const mlsCiphersuite = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';

/// Default PDS URL (Bluesky)
const defaultPdsUrl = 'https://bsky.social';

/// PLC Directory URL for DID resolution
const plcDirectoryUrl = 'https://plc.directory';

/// Bluesky public API URL (for profile fetching, no auth required)
const blueskyPublicApiUrl = 'https://public.api.bsky.app';

/// HTTP timeout duration
const httpTimeout = Duration(seconds: 30);

/// ATProto blob reference, embedded in records to pin a blob to permanent storage.
///
/// Per the ATProto spec, a blob only moves from temporary to permanent storage
/// when referenced in a successfully created record. Always uses
/// `application/octet-stream` as the MIME type since blobs are encrypted.
class BlobRef {
  final String cid;
  final String mimeType;
  final int size;

  const BlobRef({
    required this.cid,
    required this.mimeType,
    required this.size,
  });

  /// Serialise to the ATProto blob ref JSON format required in records.
  Map<String, dynamic> toAtProtoJson() => {
    r'$type': 'blob',
    'ref': {r'$link': cid},
    'mimeType': mimeType,
    'size': size,
  };
}

/// Exception thrown by ATProto operations
class AtprotoException implements Exception {
  final String message;
  final int? statusCode;

  AtprotoException(this.message, {this.statusCode});

  @override
  String toString() => 'AtprotoException: $message';
}

/// ATProto session data
class AtprotoSession {
  final String did;
  final String handle;
  final String accessJwt;
  final String refreshJwt;
  final String pdsUrl;

  AtprotoSession({
    required this.did,
    required this.handle,
    required this.accessJwt,
    required this.refreshJwt,
    required this.pdsUrl,
  });

  Map<String, dynamic> toJson() => {
        'did': did,
        'handle': handle,
        'accessJwt': accessJwt,
        'refreshJwt': refreshJwt,
        'pdsUrl': pdsUrl,
      };

  factory AtprotoSession.fromJson(Map<String, dynamic> json) => AtprotoSession(
        did: json['did'] as String,
        handle: json['handle'] as String,
        accessJwt: json['accessJwt'] as String,
        refreshJwt: json['refreshJwt'] as String,
        pdsUrl: json['pdsUrl'] as String,
      );
}

/// Key package record fetched from PDS
class KeyPackageRecord {
  final String ciphersuite;
  final Uint8List keyPackage;
  final DateTime expiresAt;
  final DateTime createdAt;

  KeyPackageRecord({
    required this.ciphersuite,
    required this.keyPackage,
    required this.expiresAt,
    required this.createdAt,
  });

  factory KeyPackageRecord.fromJson(Map<String, dynamic> json) {
    return KeyPackageRecord(
      ciphersuite: json['ciphersuite'] as String,
      keyPackage: _decodeBytesField(json['keyPackage']),
      expiresAt: DateTime.parse(json['expiresAt'] as String),
      createdAt: DateTime.parse(json['createdAt'] as String),
    );
  }

  bool get isExpired => DateTime.now().isAfter(expiresAt);
}

/// Stealth address record fetched from PDS (v2: multi-device)
class StealthAddressRecord {
  final Uint8List scanPubkey;
  final String deviceName;

  StealthAddressRecord({
    required this.scanPubkey,
    required this.deviceName,
  });
}

/// Event record fetched from PDS
class EventRecord {
  final String uri;
  final String rkey;
  final Uint8List tag;
  final Uint8List ciphertext;
  final DateTime createdAt;

  EventRecord({
    required this.uri,
    required this.rkey,
    required this.tag,
    required this.ciphertext,
    required this.createdAt,
  });

  factory EventRecord.fromJson(Map<String, dynamic> json) {
    final uri = json['uri'] as String;
    final rkey = uri.split('/').last;
    final value = json['value'] as Map<String, dynamic>;
    return EventRecord(
      uri: uri,
      rkey: rkey,
      tag: _decodeBytesField(value['tag']),
      ciphertext: _decodeBytesField(value['ciphertext']),
      createdAt: DateTime.parse(value['createdAt'] as String),
    );
  }
}

/// ATProto client for Moat operations.
///
/// [pdsOverride]: when set, [resolvePdsEndpoint] returns this URL for all DIDs.
/// Used in integration tests where all participants are on the same local PDS.
class AtprotoClient {
  final http.Client _httpClient;
  AtprotoSession? _session;

  /// When set, overrides PDS endpoint resolution for all DIDs.
  final String? pdsOverride;

  /// Called after a successful automatic token refresh so the caller can
  /// persist the new session tokens.
  void Function(AtprotoSession)? onSessionRefreshed;

  AtprotoClient({http.Client? httpClient, this.pdsOverride})
      : _httpClient = httpClient ?? http.Client();

  AtprotoSession? get session => _session;
  bool get isLoggedIn => _session != null;
  String? get did => _session?.did;

  void restoreSession(AtprotoSession session) {
    _session = session;
  }

  Future<AtprotoSession> login(String handle, String password,
      {String? pdsUrl}) async {
    final effectivePdsUrl = pdsUrl ?? pdsOverride ?? defaultPdsUrl;
    final response = await _post(
      '$effectivePdsUrl/xrpc/com.atproto.server.createSession',
      body: {
        'identifier': handle,
        'password': password,
      },
    );

    _session = AtprotoSession(
      did: response['did'] as String,
      handle: response['handle'] as String,
      accessJwt: response['accessJwt'] as String,
      refreshJwt: response['refreshJwt'] as String,
      pdsUrl: effectivePdsUrl,
    );

    return _session!;
  }

  Future<void> refreshSession() async {
    if (_session == null) {
      throw AtprotoException('No session to refresh');
    }

    final response = await _post(
      '${_session!.pdsUrl}/xrpc/com.atproto.server.refreshSession',
      authToken: _session!.refreshJwt,
    );

    _session = AtprotoSession(
      did: response['did'] as String,
      handle: response['handle'] as String,
      accessJwt: response['accessJwt'] as String,
      refreshJwt: response['refreshJwt'] as String,
      pdsUrl: _session!.pdsUrl,
    );
  }

  void logout() {
    _session = null;
  }

  /// Calls `com.atproto.server.describeServer` on [pdsUrl] and returns the
  /// drawbridge endpoint advertised under `services['social.moat.drawbridge']`,
  /// or null if the PDS does not advertise one or the call fails.
  Future<String?> describeServerDrawbridgeUrl(String pdsUrl) async {
    try {
      final response = await _get(
        '$pdsUrl/xrpc/com.atproto.server.describeServer',
      );
      final services = response['services'];
      if (services is Map) {
        final entry = services['social.moat.drawbridge'];
        if (entry is Map) {
          final endpoint = entry['endpoint'];
          if (endpoint is String && endpoint.isNotEmpty) {
            return endpoint;
          }
        }
      }
    } catch (e) {
      moatLog('AtprotoClient: describeServer drawbridge lookup failed: $e');
    }
    return null;
  }

  Future<String> resolveDid(String handle) async {
    _requireSession();

    final response = await _get(
      '${_session!.pdsUrl}/xrpc/com.atproto.identity.resolveHandle',
      queryParams: {'handle': handle},
    );

    return response['did'] as String;
  }

  Future<String> resolveHandle(String did) async {
    final docUrl = pdsOverride != null ? '$pdsOverride/$did' : '$plcDirectoryUrl/$did';
    final response = await _get(docUrl);

    final alsoKnownAs = response['alsoKnownAs'] as List<dynamic>?;
    if (alsoKnownAs != null) {
      for (final alias in alsoKnownAs) {
        final s = alias as String;
        if (s.startsWith('at://')) {
          return s.substring(5);
        }
      }
    }

    return did;
  }

  /// Resolve a DID's PDS endpoint.
  /// When [pdsOverride] is set, returns it directly (used in test environments).
  Future<String> resolvePdsEndpoint(String did) async {
    if (pdsOverride != null) return pdsOverride!;

    final response = await _get('$plcDirectoryUrl/$did');

    final services = response['service'] as List<dynamic>?;
    if (services == null) {
      throw AtprotoException('DID document has no services');
    }

    for (final service in services) {
      final svc = service as Map<String, dynamic>;
      if (svc['type'] == 'AtprotoPersonalDataServer') {
        final endpoint = svc['serviceEndpoint'] as String?;
        if (endpoint != null) {
          return endpoint;
        }
      }
    }

    throw AtprotoException('No PDS endpoint found for $did');
  }

  Future<String> publishKeyPackage(Uint8List keyPackage) async {
    _requireSession();

    final now = DateTime.now().toUtc();
    final expiresAt = now.add(const Duration(days: 30));

    final record = {
      'v': 1,
      'ciphersuite': mlsCiphersuite,
      'keyPackage': {r'$bytes': base64Encode(keyPackage)},
      'expiresAt': expiresAt.toIso8601String(),
      'createdAt': now.toIso8601String(),
    };

    final response = await _authedPost(
      '${_session!.pdsUrl}/xrpc/com.atproto.repo.createRecord',
      body: {
        'repo': _session!.did,
        'collection': keyPackageNsid,
        'record': record,
      },
    );

    return response['uri'] as String;
  }

  Future<List<KeyPackageRecord>> fetchKeyPackages(String did) async {
    final pdsUrl = await resolvePdsEndpoint(did);

    final response = await _get(
      '$pdsUrl/xrpc/com.atproto.repo.listRecords',
      queryParams: {
        'repo': did,
        'collection': keyPackageNsid,
        'limit': '100',
      },
    );

    final records = <KeyPackageRecord>[];
    final items = response['records'] as List<dynamic>? ?? [];

    for (final item in items) {
      final value = item['value'] as Map<String, dynamic>;
      final record = KeyPackageRecord.fromJson(value);
      if (!record.isExpired) {
        records.add(record);
      }
    }

    return records;
  }

  Future<String> publishStealthAddress(Uint8List scanPubkey, String deviceName) async {
    _requireSession();

    if (scanPubkey.length != 32) {
      throw AtprotoException('Stealth public key must be 32 bytes');
    }

    final now = DateTime.now().toUtc();
    final record = {
      'v': 2,
      'scanPubkey': {r'$bytes': base64Encode(scanPubkey)},
      'deviceName': deviceName,
      'createdAt': now.toIso8601String(),
    };

    final response = await _authedPost(
      '${_session!.pdsUrl}/xrpc/com.atproto.repo.createRecord',
      body: {
        'repo': _session!.did,
        'collection': stealthAddressNsid,
        'record': record,
      },
    );

    return response['uri'] as String;
  }

  /// Publish (upsert) our Drawbridge config record.
  Future<void> publishDrawbridgeConfig(String url) async {
    _requireSession();

    final record = {
      'drawbridges': [
        {'url': url, 'priority': 1},
      ],
    };

    await _authedPost(
      '${_session!.pdsUrl}/xrpc/com.atproto.repo.putRecord',
      body: {
        'repo': _session!.did,
        'collection': drawbridgeConfigNsid,
        'rkey': 'self',
        'record': record,
      },
    );
  }

  /// Fetch a user's Drawbridge config. Returns relay URLs in priority order,
  /// or empty list if not published.
  Future<List<String>> fetchDrawbridgeConfig(String did) async {
    try {
      final pdsUrl = await resolvePdsEndpoint(did);
      final response = await _get(
        '$pdsUrl/xrpc/com.atproto.repo.getRecord',
        queryParams: {
          'repo': did,
          'collection': drawbridgeConfigNsid,
          'rkey': 'self',
        },
      );

      final value = response['value'] as Map<String, dynamic>?;
      if (value == null) return [];

      final drawbridges = value['drawbridges'] as List<dynamic>? ?? [];
      final entries = drawbridges
          .map((e) => e as Map<String, dynamic>)
          .toList()
        ..sort((a, b) =>
            (a['priority'] as int? ?? 99)
                .compareTo(b['priority'] as int? ?? 99));

      return entries
          .map((e) => e['url'] as String)
          .toList();
    } catch (e) {
      moatLog('Failed to fetch drawbridge config for $did: $e');
      return [];
    }
  }

  Future<List<StealthAddressRecord>> fetchStealthAddresses(String did) async {
    final pdsUrl = await resolvePdsEndpoint(did);

    final response = await _get(
      '$pdsUrl/xrpc/com.atproto.repo.listRecords',
      queryParams: {
        'repo': did,
        'collection': stealthAddressNsid,
        'limit': '100',
      },
    );

    final records = <StealthAddressRecord>[];
    final items = response['records'] as List<dynamic>? ?? [];

    for (final item in items) {
      final value = item['value'] as Map<String, dynamic>;
      final v = value['v'] as int?;
      if (v == 2) {
        final scanPubkey = _decodeBytesField(value['scanPubkey']);
        final deviceName = value['deviceName'] as String? ?? 'Unknown';
        records.add(StealthAddressRecord(
          scanPubkey: scanPubkey,
          deviceName: deviceName,
        ));
      }
    }

    return records;
  }

  /// Publish an encrypted event to the PDS.
  ///
  /// If [blobRef] is provided it is embedded in the record, which causes the
  /// PDS to promote the blob from temporary to permanent storage. This must be
  /// set for any event that carries an image attachment.
  Future<String> publishEvent(
    Uint8List tag,
    Uint8List ciphertext, {
    BlobRef? blobRef,
  }) async {
    _requireSession();

    if (tag.length != 16) {
      throw AtprotoException('Event tag must be 16 bytes');
    }

    final now = DateTime.now().toUtc();
    final record = <String, dynamic>{
      'v': 1,
      'tag': {r'$bytes': base64Encode(tag)},
      'ciphertext': {r'$bytes': base64Encode(ciphertext)},
      'createdAt': now.toIso8601String(),
    };

    if (blobRef != null) {
      record['blob'] = blobRef.toAtProtoJson();
    }

    final response = await _authedPost(
      '${_session!.pdsUrl}/xrpc/com.atproto.repo.createRecord',
      body: {
        'repo': _session!.did,
        'collection': eventNsid,
        'record': record,
      },
    );

    return response['uri'] as String;
  }

  Future<List<EventRecord>> fetchEvents(String did, {String? afterRkey}) async {
    final pdsUrl = await resolvePdsEndpoint(did);

    final allRecords = <EventRecord>[];
    String? cursor;

    do {
      final queryParams = <String, String>{
        'repo': did,
        'collection': eventNsid,
        'limit': '100',
      };

      if (afterRkey != null) {
        queryParams['rkeyStart'] = afterRkey;
      }

      if (cursor != null) {
        queryParams['cursor'] = cursor;
      }

      final response = await _get(
        '$pdsUrl/xrpc/com.atproto.repo.listRecords',
        queryParams: queryParams,
      );

      final items = response['records'] as List<dynamic>? ?? [];

      for (final item in items) {
        try {
          final record = EventRecord.fromJson(item as Map<String, dynamic>);
          if (afterRkey != null && record.rkey.compareTo(afterRkey) <= 0) {
            continue;
          }
          allRecords.add(record);
        } catch (e) {
          moatLog('Failed to parse event record: $e');
        }
      }

      cursor = response['cursor'] as String?;
    } while (cursor != null);

    allRecords.sort((a, b) => a.rkey.compareTo(b.rkey));
    return allRecords;
  }

  /// Upload an encrypted blob to the user's PDS.
  /// Returns the CID string (e.g. "bafkrei...").
  Future<String> uploadBlob(Uint8List data) async {
    _requireSession();

    final uri = Uri.parse(
        '${_session!.pdsUrl}/xrpc/com.atproto.repo.uploadBlob');
    final headers = <String, String>{
      'Content-Type': 'application/octet-stream',
      'Accept': 'application/json',
      'Authorization': 'Bearer ${_session!.accessJwt}',
    };

    http.Response response;
    try {
      response = await _httpClient
          .post(uri, headers: headers, body: data)
          .timeout(httpTimeout);
    } on AtprotoException {
      rethrow;
    } catch (e) {
      throw AtprotoException('blob upload request failed: $e');
    }

    if (response.statusCode == 401) {
      await refreshSession();
      onSessionRefreshed?.call(_session!);
      headers['Authorization'] = 'Bearer ${_session!.accessJwt}';
      response = await _httpClient
          .post(uri, headers: headers, body: data)
          .timeout(httpTimeout);
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw AtprotoException(
          'uploadBlob returned ${response.statusCode}: ${response.body}',
          statusCode: response.statusCode);
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final cid = (json['blob'] as Map<String, dynamic>?)?['ref']
        ?[r'$link'] as String?;
    if (cid == null) {
      throw AtprotoException('uploadBlob response missing blob.ref.\$link');
    }
    return cid;
  }

  /// Fetch a blob from a user's PDS by DID and CID.
  /// Returns the raw encrypted bytes (nonce || ciphertext).
  Future<Uint8List> fetchBlob(String did, String cid) async {
    final pdsUrl = await resolvePdsEndpoint(did);
    final uri = Uri.parse(
        '$pdsUrl/xrpc/com.atproto.sync.getBlob?did=$did&cid=$cid');

    final response =
        await _httpClient.get(uri).timeout(httpTimeout);

    if (response.statusCode == 404) {
      throw AtprotoException('blob not found: did=$did cid=$cid',
          statusCode: 404);
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw AtprotoException(
          'getBlob returned ${response.statusCode}: ${response.body}',
          statusCode: response.statusCode);
    }

    return response.bodyBytes;
  }

  Future<BlueskyProfile?> getProfile(String actorDidOrHandle) async {
    try {
      final response = await _get(
        '$blueskyPublicApiUrl/xrpc/app.bsky.actor.getProfile',
        queryParams: {'actor': actorDidOrHandle},
      );
      return BlueskyProfile.fromApiResponse(response);
    } catch (e) {
      moatLog('Failed to fetch profile for $actorDidOrHandle: $e');
      return null;
    }
  }

  Future<List<BlueskyProfile>> getProfiles(List<String> actors) async {
    if (actors.isEmpty) return [];

    final results = <BlueskyProfile>[];

    for (var i = 0; i < actors.length; i += 25) {
      final batch = actors.skip(i).take(25).toList();

      try {
        final uri = Uri.parse('$blueskyPublicApiUrl/xrpc/app.bsky.actor.getProfiles');
        final queryUri = uri.replace(queryParameters: {
          'actors': batch,
        });

        final response = await _httpClient
            .get(queryUri, headers: {'Accept': 'application/json'})
            .timeout(httpTimeout);

        if (response.statusCode >= 200 && response.statusCode < 300) {
          final json = jsonDecode(response.body) as Map<String, dynamic>;
          final profiles = json['profiles'] as List<dynamic>? ?? [];

          for (final profileJson in profiles) {
            results.add(BlueskyProfile.fromApiResponse(
              profileJson as Map<String, dynamic>,
            ));
          }
        }
      } catch (e) {
        moatLog('Failed to fetch profiles batch: $e');
      }
    }

    return results;
  }

  void _requireSession() {
    if (_session == null) {
      throw AtprotoException('Not logged in');
    }
  }

  Future<Map<String, dynamic>> _authedPost(
    String url, {
    Map<String, dynamic>? body,
  }) async {
    try {
      return await _post(url, body: body, authToken: _session!.accessJwt);
    } on AtprotoException catch (e) {
      if (e.statusCode == 401 || (e.message.contains('Token') && e.message.contains('expired'))) {
        await refreshSession();
        onSessionRefreshed?.call(_session!);
        return await _post(url, body: body, authToken: _session!.accessJwt);
      }
      rethrow;
    }
  }

  Future<Map<String, dynamic>> _get(
    String url, {
    Map<String, String>? queryParams,
    String? authToken,
  }) async {
    var uri = Uri.parse(url);
    if (queryParams != null) {
      uri = uri.replace(queryParameters: queryParams);
    }

    final headers = <String, String>{
      'Accept': 'application/json',
    };
    if (authToken != null) {
      headers['Authorization'] = 'Bearer $authToken';
    }

    final response = await _httpClient
        .get(uri, headers: headers)
        .timeout(httpTimeout);

    return _handleResponse(response);
  }

  Future<Map<String, dynamic>> _post(
    String url, {
    Map<String, dynamic>? body,
    String? authToken,
  }) async {
    final headers = <String, String>{
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    if (authToken != null) {
      headers['Authorization'] = 'Bearer $authToken';
    }

    final response = await _httpClient
        .post(
          Uri.parse(url),
          headers: headers,
          body: body != null ? jsonEncode(body) : null,
        )
        .timeout(httpTimeout);

    return _handleResponse(response);
  }

  Map<String, dynamic> _handleResponse(http.Response response) {
    if (response.statusCode >= 200 && response.statusCode < 300) {
      if (response.body.isEmpty) {
        return {};
      }
      return jsonDecode(response.body) as Map<String, dynamic>;
    }

    String message;
    try {
      final error = jsonDecode(response.body) as Map<String, dynamic>;
      message = error['message'] as String? ?? error['error'] as String? ?? 'Unknown error';
    } catch (_) {
      message = 'HTTP ${response.statusCode}: ${response.reasonPhrase}';
    }

    throw AtprotoException(message, statusCode: response.statusCode);
  }
}
