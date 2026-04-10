import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Stateless SHA-256 hashing service.
///
/// Wraps pointycastle's [SHA256Digest] so the rest of the app
/// has no direct dependency on the crypto library.
class Sha256Service {
  /// Hash [input] as UTF-8 and return a 64-character lowercase hex string.
  static String hash(String input) {
    final digest = SHA256Digest();
    final bytes = Uint8List.fromList(utf8.encode(input));
    final hashBytes = digest.process(bytes);
    return _toHex(hashBytes);
  }

  static String _toHex(Uint8List bytes) {
    return bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }
}
