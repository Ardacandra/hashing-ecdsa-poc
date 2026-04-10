import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:pointycastle/macs/hmac.dart';

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

/// Thrown by [EcdsaService] for guard and validation failures.
/// The [message] matches the exact error text specified in the requirements.
class EcdsaException implements Exception {
  final String message;
  const EcdsaException(this.message);

  @override
  String toString() => message;
}

// ---------------------------------------------------------------------------
// Keypair value object
// ---------------------------------------------------------------------------

/// Holds a generated (or reconstructed) P-256 keypair.
///
/// [publicKeyHex]  — uncompressed point (04 ‖ X ‖ Y), 130 lowercase hex chars.
/// [privateKeyHex] — scalar d, 64 lowercase hex chars (display only).
/// [ecPrivateKey]  — the live [ECPrivateKey] used for signing.
class EcdsaKeypair {
  final String publicKeyHex;
  final String privateKeyHex;
  final ECPrivateKey ecPrivateKey;

  const EcdsaKeypair({
    required this.publicKeyHex,
    required this.privateKeyHex,
    required this.ecPrivateKey,
  });

  /// Reconstruct a keypair from a known private key hex scalar.
  ///
  /// Derives the public key via scalar multiplication (d·G).
  /// Used in tests to exercise RFC 6979 deterministic vectors.
  factory EcdsaKeypair.fromPrivateKeyHex(String privateKeyHex) {
    final domainParams = ECCurve_secp256r1();
    final d = BigInt.parse(privateKeyHex, radix: 16);

    // Derive public key: Q = d · G
    final Q = domainParams.G * d;

    // Each coordinate must be zero-padded to 32 bytes (64 hex chars).
    // toRadixString(16) alone drops leading zeros — padLeft is mandatory.
    final x = Q!.x!.toBigInteger()!.toRadixString(16).padLeft(64, '0');
    final y = Q.y!.toBigInteger()!.toRadixString(16).padLeft(64, '0');

    return EcdsaKeypair(
      publicKeyHex: '04$x$y',
      privateKeyHex: d.toRadixString(16).padLeft(64, '0'),
      ecPrivateKey: ECPrivateKey(d, domainParams),
    );
  }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Stateless ECDSA P-256 service.
///
/// All methods are static. The UI widget holds the [EcdsaKeypair] state.
class EcdsaService {
  // -------------------------------------------------------------------------
  // Key generation
  // -------------------------------------------------------------------------

  /// Generate a fresh P-256 keypair.
  ///
  /// Uses [FortunaRandom] seeded from [Random.secure] (OS CSPRNG / /dev/urandom).
  static EcdsaKeypair generateKeypair() {
    final domainParams = ECCurve_secp256r1();

    // Seed FortunaRandom with 32 bytes of OS entropy
    final secureRandom = Random.secure();
    final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => secureRandom.nextInt(256)),
    );
    final random = FortunaRandom()..seed(KeyParameter(seed));

    final keyGen = ECKeyGenerator()
      ..init(ParametersWithRandom(ECKeyGeneratorParameters(domainParams), random));

    final pair = keyGen.generateKeyPair();
    final pubKey = pair.publicKey as ECPublicKey;
    final privKey = pair.privateKey as ECPrivateKey;

    // Public key: uncompressed point (04 ‖ X ‖ Y)
    // padLeft(64, '0') is mandatory — toRadixString(16) drops leading zeros.
    final x = pubKey.Q!.x!.toBigInteger()!.toRadixString(16).padLeft(64, '0');
    final y = pubKey.Q!.y!.toBigInteger()!.toRadixString(16).padLeft(64, '0');

    // Private key: scalar d, zero-padded to 32 bytes
    final privateKeyHex = privKey.d!.toRadixString(16).padLeft(64, '0');

    return EcdsaKeypair(
      publicKeyHex: '04$x$y',
      privateKeyHex: privateKeyHex,
      ecPrivateKey: privKey,
    );
  }

  // -------------------------------------------------------------------------
  // Sign
  // -------------------------------------------------------------------------

  /// Sign [message] (UTF-8) with the private key in [keypair].
  ///
  /// Uses RFC 6979 deterministic k via [HMacDSAKCalculator] so that signing
  /// the same message twice with the same key produces the same signature.
  ///
  /// Returns a 128-character lowercase hex string (r ‖ s, each 32 bytes /
  /// 64 hex chars, zero-padded).
  ///
  /// Throws [EcdsaException] if [keypair] is null (FR-3.5).
  static String sign(String message, EcdsaKeypair? keypair) {
    if (keypair == null) {
      throw const EcdsaException(
        'No keypair loaded. Generate a keypair before signing.',
      );
    }

    final signer =
        ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
    signer.init(true, PrivateKeyParameter<ECPrivateKey>(keypair.ecPrivateKey));

    final messageBytes = Uint8List.fromList(utf8.encode(message));
    final sig = signer.generateSignature(messageBytes) as ECSignature;

    // r and s must each be zero-padded to 32 bytes (64 hex chars).
    // toRadixString(16) alone produces fewer chars when the high byte is 0.
    final r = sig.r.toRadixString(16).padLeft(64, '0');
    final s = sig.s.toRadixString(16).padLeft(64, '0');
    return r + s;
  }

  // -------------------------------------------------------------------------
  // Verify
  // -------------------------------------------------------------------------

  /// Verify [signatureHex] against [message] using [publicKeyHex].
  ///
  /// Guard and validation checks (FR-4.2 – FR-4.5) throw [EcdsaException]
  /// with the exact message strings required by the spec.
  ///
  /// Returns `true` if the signature is valid, `false` if invalid.
  static bool verify(String message, String signatureHex, String publicKeyHex) {
    // FR-4.2: no keypair loaded (public key field is empty)
    if (publicKeyHex.trim().isEmpty) {
      throw const EcdsaException(
        'No keypair loaded. Generate a keypair before verifying.',
      );
    }
    // FR-4.3: signature field is empty
    if (signatureHex.trim().isEmpty) {
      throw const EcdsaException(
        'No signature to verify. Sign a message first.',
      );
    }
    // FR-4.4: signature must be exactly 128 lowercase hex characters
    if (!RegExp(r'^[0-9a-f]{128}$').hasMatch(signatureHex)) {
      throw const EcdsaException(
        'Invalid signature: must be 128 hex characters (raw r||s).',
      );
    }
    // FR-4.5: public key must be 130 hex chars starting with '04'
    if (!RegExp(r'^04[0-9a-f]{128}$').hasMatch(publicKeyHex)) {
      throw const EcdsaException('Invalid public key format.');
    }

    try {
      // Reconstruct ECPublicKey from hex
      final xHex = publicKeyHex.substring(2, 66);
      final yHex = publicKeyHex.substring(66, 130);
      final x = BigInt.parse(xHex, radix: 16);
      final y = BigInt.parse(yHex, radix: 16);
      final domainParams = ECCurve_secp256r1();
      final point = domainParams.curve.createPoint(x, y);
      final publicKey = ECPublicKey(point, domainParams);

      // Reconstruct ECSignature from hex
      final r = BigInt.parse(signatureHex.substring(0, 64), radix: 16);
      final s = BigInt.parse(signatureHex.substring(64, 128), radix: 16);

      final verifier =
          ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
      verifier.init(false, PublicKeyParameter<ECPublicKey>(publicKey));

      final messageBytes = Uint8List.fromList(utf8.encode(message));
      return verifier.verifySignature(messageBytes, ECSignature(r, s));
    } catch (_) {
      // Treat any crypto error during actual verification as an invalid result.
      return false;
    }
  }
}
