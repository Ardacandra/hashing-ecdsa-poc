import 'package:flutter_test/flutter_test.dart';
import 'package:hashing_ecdsa_mobile/crypto/ecdsa_service.dart';
import 'package:hashing_ecdsa_mobile/crypto/sha256_service.dart';

/// RFC 6979 §A.2.5 private key (P-256 with SHA-256)
const _rfcPrivKey =
    'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';

/// Corresponding uncompressed public key (04 ‖ X ‖ Y)
const _rfcPubKey =
    '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6'
    '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299';

void main() {
  // ==========================================================================
  // SHA-256 — NIST FIPS 180-4 test vectors
  // ==========================================================================

  group('Sha256Service', () {
    test('V-H1: empty string', () {
      expect(
        Sha256Service.hash(''),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    test('V-H2: "abc"', () {
      expect(
        Sha256Service.hash('abc'),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('output is exactly 64 lowercase hex chars', () {
      expect(Sha256Service.hash('test'), matches(RegExp(r'^[0-9a-f]{64}$')));
    });
  });

  // ==========================================================================
  // EcdsaService.generateKeypair — structure checks
  // ==========================================================================

  group('EcdsaService.generateKeypair', () {
    test('public key is 65 bytes: starts with 04, followed by 64-char X and Y', () {
      final kp = EcdsaService.generateKeypair();
      expect(kp.publicKeyHex.length, 130);
      expect(kp.publicKeyHex.startsWith('04'), isTrue);
      expect(RegExp(r'^04[0-9a-f]{128}$').hasMatch(kp.publicKeyHex), isTrue);
    });

    test('private key is 32 bytes (64 hex chars)', () {
      final kp = EcdsaService.generateKeypair();
      expect(kp.privateKeyHex.length, 64);
      expect(RegExp(r'^[0-9a-f]{64}$').hasMatch(kp.privateKeyHex), isTrue);
    });
  });

  // ==========================================================================
  // Sign + verify — round-trip tests (RT-1, RT-2)
  // ==========================================================================

  group('EcdsaService.sign + verify — round-trip', () {
    late EcdsaKeypair keypair;

    setUp(() => keypair = EcdsaService.generateKeypair());

    test('RT-1: sign "hello" then verify with same key → true', () {
      final sig = EcdsaService.sign('hello', keypair);
      expect(EcdsaService.verify('hello', sig, keypair.publicKeyHex), isTrue);
    });

    test('signature is exactly 128 lowercase hex chars', () {
      final sig = EcdsaService.sign('hello', keypair);
      expect(sig.length, 128);
      expect(RegExp(r'^[0-9a-f]{128}$').hasMatch(sig), isTrue);
    });

    test('RT-2: verify with wrong message "Hell0" → false', () {
      final sig = EcdsaService.sign('hello', keypair);
      expect(EcdsaService.verify('Hell0', sig, keypair.publicKeyHex), isFalse);
    });
  });

  // ==========================================================================
  // RFC 6979 deterministic k — leading-zero padding
  // ==========================================================================

  group('RFC 6979 deterministic vectors', () {
    test('EcdsaKeypair.fromPrivateKeyHex derives correct public key', () {
      final kp = EcdsaKeypair.fromPrivateKeyHex(_rfcPrivKey);
      // Collapse the two-line hex from verification.md into one string
      expect(kp.publicKeyHex, _rfcPubKey.replaceAll('\n', ''));
    });

    test(
      'sign "test" with RFC 6979 key → s component is 64 chars starting with "01"',
      () {
        final kp = EcdsaKeypair.fromPrivateKeyHex(_rfcPrivKey);
        final sig = EcdsaService.sign('test', kp);

        expect(sig.length, 128);
        final s = sig.substring(64);
        expect(
          s.startsWith('01'),
          isTrue,
          reason:
              'Leading-zero padding: padLeft(64,"0") must keep the 01 prefix. '
              'Actual s: $s',
        );
      },
    );

    test('sign "test" with RFC 6979 key → exact deterministic signature', () {
      final kp = EcdsaKeypair.fromPrivateKeyHex(_rfcPrivKey);
      final sig = EcdsaService.sign('test', kp);

      const expectedR =
          'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367';
      const expectedS =
          '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083';
      expect(sig, '$expectedR$expectedS');
    });

    test('sign "sample" with RFC 6979 key → round-trip verifies correctly', () {
      final kp = EcdsaKeypair.fromPrivateKeyHex(_rfcPrivKey);
      final sig = EcdsaService.sign('sample', kp);
      expect(sig.length, 128);
      expect(EcdsaService.verify('sample', sig, kp.publicKeyHex), isTrue);
    });
  });

  // ==========================================================================
  // Guard and validation (GV-1 – GV-6)
  // ==========================================================================

  group('Guard and validation', () {
    late EcdsaKeypair keypair;

    setUp(() => keypair = EcdsaService.generateKeypair());

    // GV-1
    test('sign with null keypair throws EcdsaException (FR-3.5)', () {
      expect(
        () => EcdsaService.sign('hello', null),
        throwsA(
          isA<EcdsaException>().having(
            (e) => e.message,
            'message',
            'No keypair loaded. Generate a keypair before signing.',
          ),
        ),
      );
    });

    // GV-2
    test('verify with empty public key throws EcdsaException (FR-4.2)', () {
      final sig = EcdsaService.sign('hello', keypair);
      expect(
        () => EcdsaService.verify('hello', sig, ''),
        throwsA(
          isA<EcdsaException>().having(
            (e) => e.message,
            'message',
            'No keypair loaded. Generate a keypair before verifying.',
          ),
        ),
      );
    });

    // GV-3
    test('verify with empty signature throws EcdsaException (FR-4.3)', () {
      expect(
        () => EcdsaService.verify('hello', '', keypair.publicKeyHex),
        throwsA(
          isA<EcdsaException>().having(
            (e) => e.message,
            'message',
            'No signature to verify. Sign a message first.',
          ),
        ),
      );
    });

    // GV-4
    test('verify with 127-char signature throws EcdsaException (FR-4.4)', () {
      final sig = EcdsaService.sign('hello', keypair);
      expect(
        () => EcdsaService.verify(
          'hello',
          sig.substring(0, 127),
          keypair.publicKeyHex,
        ),
        throwsA(
          isA<EcdsaException>().having(
            (e) => e.message,
            'message',
            'Invalid signature: must be 128 hex characters (raw r||s).',
          ),
        ),
      );
    });

    // GV-5
    test('verify with non-hex char in signature throws EcdsaException (FR-4.4)',
        () {
      final sig = EcdsaService.sign('hello', keypair);
      // Replace position 64 with 'z' — still 128 chars but fails hex regex
      final bad = '${sig.substring(0, 64)}z${sig.substring(65)}';
      expect(
        () => EcdsaService.verify('hello', bad, keypair.publicKeyHex),
        throwsA(
          isA<EcdsaException>().having(
            (e) => e.message,
            'message',
            'Invalid signature: must be 128 hex characters (raw r||s).',
          ),
        ),
      );
    });

    // GV-6
    test('verify with truncated public key throws EcdsaException (FR-4.5)', () {
      final sig = EcdsaService.sign('hello', keypair);
      expect(
        () => EcdsaService.verify(
          'hello',
          sig,
          keypair.publicKeyHex.substring(0, 128),
        ),
        throwsA(
          isA<EcdsaException>().having(
            (e) => e.message,
            'message',
            'Invalid public key format.',
          ),
        ),
      );
    });
  });
}
