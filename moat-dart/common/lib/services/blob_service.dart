import 'dart:convert';
import 'dart:typed_data';
import 'atproto_client.dart';
import 'document_backend.dart';
import '../rust/api/simple.dart';

/// Result of encrypting and uploading a blob.
class BlobUploadResult {
  final String cid;
  final Uint8List key;
  final Uint8List ciphertextHash;
  final int ciphertextSize;
  final Uint8List contentHash;

  const BlobUploadResult({
    required this.cid,
    required this.key,
    required this.ciphertextHash,
    required this.ciphertextSize,
    required this.contentHash,
  });
}

/// Service for encrypting, uploading, downloading, decrypting, and caching blobs.
///
/// Blobs are cached at `blobs/{hex(contentHash)}` in the document backend.
class BlobService {
  final AtprotoClient _atprotoClient;
  final DocumentBackend _backend;

  BlobService({
    required AtprotoClient atprotoClient,
    required DocumentBackend backend,
  })  : _atprotoClient = atprotoClient,
        _backend = backend;

  /// Encrypt and upload an image blob to the user's PDS.
  /// Returns metadata needed for the MediaMessage payload.
  Future<BlobUploadResult> encryptAndUpload(Uint8List plaintext) async {
    final result = await blobEncrypt(plaintext: plaintext);
    final blob = Uint8List.fromList(result.blob);
    final cid = await _atprotoClient.uploadBlob(blob);
    return BlobUploadResult(
      cid: cid,
      key: Uint8List.fromList(result.key),
      ciphertextHash: Uint8List.fromList(result.ciphertextHash),
      ciphertextSize: blob.length,
      contentHash: Uint8List.fromList(result.contentHash),
    );
  }

  /// Fetch, decrypt, verify, and cache a blob.
  /// Returns decrypted plaintext, using the cache if available.
  Future<Uint8List> fetchAndDecrypt({
    required String uri,
    required Uint8List key,
    required Uint8List ciphertextHash,
    required Uint8List contentHash,
  }) async {
    // Check cache first.
    final cached = await getCachedAsync(contentHash);
    if (cached != null) return cached;

    // Parse "at://did/cid"
    final withoutAt = uri.replaceFirst('at://', '');
    final slashIdx = withoutAt.indexOf('/');
    if (slashIdx < 0) {
      throw ArgumentError('Invalid blob URI: $uri');
    }
    final did = withoutAt.substring(0, slashIdx);
    final cid = withoutAt.substring(slashIdx + 1);

    final blob = await _atprotoClient.fetchBlob(did, cid);

    final plaintext = await blobDecrypt(
      blob: blob,
      key: key,
      ciphertextHash: ciphertextHash,
      contentHash: contentHash,
    );
    final plaintextBytes = Uint8List.fromList(plaintext);

    // Cache the decrypted plaintext.
    final hexHash = contentHash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    await _backend.write('blobs/$hexHash', base64Encode(plaintextBytes));

    return plaintextBytes;
  }

  /// Return cached plaintext for a blob by its content hash, or null on miss.
  Future<Uint8List?> getCachedAsync(Uint8List contentHash) async {
    final hexHash = contentHash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final stored = await _backend.read('blobs/$hexHash');
    if (stored == null) return null;
    return base64Decode(stored);
  }
}
