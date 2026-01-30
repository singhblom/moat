import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

/// ATProto lexicon NSIDs
const keyPackageNsid = 'social.moat.keyPackage';
const eventNsid = 'social.moat.event';
const stealthAddressNsid = 'social.moat.stealthAddress';

/// MLS ciphersuite identifier
const mlsCiphersuite = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';

/// Default PDS URL (Bluesky)
const defaultPdsUrl = 'https://bsky.social';

/// PLC Directory URL for DID resolution
const plcDirectoryUrl = 'https://plc.directory';

/// HTTP timeout duration
const httpTimeout = Duration(seconds: 30);

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
      keyPackage: base64Decode(json['keyPackage'] as String),
      expiresAt: DateTime.parse(json['expiresAt'] as String),
      createdAt: DateTime.parse(json['createdAt'] as String),
    );
  }

  bool get isExpired => DateTime.now().isAfter(expiresAt);
}

/// ATProto client for Moat operations
class AtprotoClient {
  final http.Client _httpClient;
  AtprotoSession? _session;

  AtprotoClient({http.Client? httpClient})
      : _httpClient = httpClient ?? http.Client();

  /// Get the current session
  AtprotoSession? get session => _session;

  /// Check if logged in
  bool get isLoggedIn => _session != null;

  /// Get the authenticated user's DID
  String? get did => _session?.did;

  /// Restore a session from stored data
  void restoreSession(AtprotoSession session) {
    _session = session;
  }

  /// Login to ATProto with handle and app password
  Future<AtprotoSession> login(String handle, String password,
      {String pdsUrl = defaultPdsUrl}) async {
    final response = await _post(
      '$pdsUrl/xrpc/com.atproto.server.createSession',
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
      pdsUrl: pdsUrl,
    );

    return _session!;
  }

  /// Refresh the access token
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

  /// Logout and clear session
  void logout() {
    _session = null;
  }

  /// Resolve a handle to a DID
  Future<String> resolveDid(String handle) async {
    _requireSession();

    final response = await _get(
      '${_session!.pdsUrl}/xrpc/com.atproto.identity.resolveHandle',
      queryParams: {'handle': handle},
    );

    return response['did'] as String;
  }

  /// Resolve a DID to a handle via PLC directory
  Future<String> resolveHandle(String did) async {
    final response = await _get('$plcDirectoryUrl/$did');

    final alsoKnownAs = response['alsoKnownAs'] as List<dynamic>?;
    if (alsoKnownAs != null) {
      for (final alias in alsoKnownAs) {
        final s = alias as String;
        if (s.startsWith('at://')) {
          return s.substring(5);
        }
      }
    }

    return did; // Fallback to DID if no handle found
  }

  /// Resolve a DID's PDS endpoint from PLC directory
  Future<String> resolvePdsEndpoint(String did) async {
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

  /// Publish a key package to the PDS
  Future<String> publishKeyPackage(Uint8List keyPackage) async {
    _requireSession();

    final now = DateTime.now().toUtc();
    final expiresAt = now.add(const Duration(days: 30));

    final record = {
      'v': 1,
      'ciphersuite': mlsCiphersuite,
      'keyPackage': base64Encode(keyPackage),
      'expiresAt': expiresAt.toIso8601String(),
      'createdAt': now.toIso8601String(),
    };

    final response = await _post(
      '${_session!.pdsUrl}/xrpc/com.atproto.repo.createRecord',
      body: {
        'repo': _session!.did,
        'collection': keyPackageNsid,
        'record': record,
      },
      authToken: _session!.accessJwt,
    );

    return response['uri'] as String;
  }

  /// Fetch key packages for a given DID
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
      try {
        final value = item['value'] as Map<String, dynamic>;
        final record = KeyPackageRecord.fromJson(value);
        if (!record.isExpired) {
          records.add(record);
        }
      } catch (_) {
        // Skip malformed records
      }
    }

    return records;
  }

  /// Publish a stealth address to the PDS (singleton record with rkey "self")
  Future<String> publishStealthAddress(Uint8List scanPubkey) async {
    _requireSession();

    if (scanPubkey.length != 32) {
      throw AtprotoException('Stealth public key must be 32 bytes');
    }

    final now = DateTime.now().toUtc();
    final record = {
      'v': 1,
      'scanPubkey': base64Encode(scanPubkey),
      'createdAt': now.toIso8601String(),
    };

    final response = await _post(
      '${_session!.pdsUrl}/xrpc/com.atproto.repo.createRecord',
      body: {
        'repo': _session!.did,
        'collection': stealthAddressNsid,
        'rkey': 'self',
        'record': record,
      },
      authToken: _session!.accessJwt,
    );

    return response['uri'] as String;
  }

  /// Fetch a user's stealth address
  Future<Uint8List?> fetchStealthAddress(String did) async {
    final pdsUrl = await resolvePdsEndpoint(did);

    final response = await _get(
      '$pdsUrl/xrpc/com.atproto.repo.listRecords',
      queryParams: {
        'repo': did,
        'collection': stealthAddressNsid,
        'limit': '1',
      },
    );

    final records = response['records'] as List<dynamic>? ?? [];
    if (records.isEmpty) {
      return null;
    }

    try {
      final value = records.first['value'] as Map<String, dynamic>;
      final scanPubkey = value['scanPubkey'] as String;
      return base64Decode(scanPubkey);
    } catch (_) {
      return null;
    }
  }

  /// Publish an encrypted event to the PDS
  Future<String> publishEvent(Uint8List tag, Uint8List ciphertext) async {
    _requireSession();

    if (tag.length != 16) {
      throw AtprotoException('Event tag must be 16 bytes');
    }

    final now = DateTime.now().toUtc();
    final record = {
      'v': 1,
      'tag': base64Encode(tag),
      'ciphertext': base64Encode(ciphertext),
      'createdAt': now.toIso8601String(),
    };

    final response = await _post(
      '${_session!.pdsUrl}/xrpc/com.atproto.repo.createRecord',
      body: {
        'repo': _session!.did,
        'collection': eventNsid,
        'record': record,
      },
      authToken: _session!.accessJwt,
    );

    return response['uri'] as String;
  }

  void _requireSession() {
    if (_session == null) {
      throw AtprotoException('Not logged in');
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
