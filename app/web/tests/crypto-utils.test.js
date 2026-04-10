'use strict';

/**
 * crypto-utils.test.js
 *
 * Jest test suite covering all cases from verification.md §5 (Web App).
 * Run from app/web/:  npm test
 *
 * Requires Node.js 18+ (Web Crypto API available via globalThis.crypto,
 * initialised by tests/setup.js).
 */

const {
  sha256Hash,
  generateKeypair,
  signMessage,
  verifySignature,
} = require('../crypto-utils.js');

// ============================================================
// SHA-256 — known NIST FIPS 180-4 test vectors
// ============================================================
describe('sha256Hash', () => {
  test('V-H1: empty string', async () => {
    expect(await sha256Hash('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  test('V-H2: "abc"', async () => {
    expect(await sha256Hash('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  test('V-H3: NIST long string', async () => {
    expect(
      await sha256Hash('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  test('V-H4: quick brown fox', async () => {
    expect(
      await sha256Hash('The quick brown fox jumps over the lazy dog')
    ).toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
  });

  test('output is exactly 64 lowercase hex characters', async () => {
    expect(await sha256Hash('some random input')).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ============================================================
// generateKeypair — structure and encoding checks
// ============================================================
describe('generateKeypair', () => {
  test('public key is 130 hex chars starting with "04"', async () => {
    const { publicKeyHex } = await generateKeypair();
    expect(publicKeyHex).toMatch(/^04[0-9a-f]{128}$/);
  });

  test('private key is exactly 64 lowercase hex chars', async () => {
    const { privateKeyHex } = await generateKeypair();
    expect(privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ============================================================
// signMessage + verifySignature — round-trip tests (RT-1 – RT-4)
// ============================================================
describe('signMessage + verifySignature — round-trip', () => {
  let keypair;

  beforeAll(async () => {
    keypair = await generateKeypair();
  });

  test('RT-1: sign then verify with same key and message → true', async () => {
    const sig = await signMessage('hello world', keypair.cryptoKeyPair);
    expect(await verifySignature('hello world', sig, keypair.publicKeyHex)).toBe(true);
  });

  test('signature is exactly 128 lowercase hex chars', async () => {
    const sig = await signMessage('hello world', keypair.cryptoKeyPair);
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
  });

  test('RT-2: tampered message → false', async () => {
    const sig = await signMessage('hello world', keypair.cryptoKeyPair);
    // Change case of first letter — different UTF-8 bytes
    expect(await verifySignature('Hello world', sig, keypair.publicKeyHex)).toBe(false);
  });

  test('RT-3: flip one hex char in signature → false', async () => {
    const sig = await signMessage('hello world', keypair.cryptoKeyPair);
    // Flip the first nibble (0↔1 is always safe because sig[0] ∈ [0-9a-f])
    const flipped = (sig[0] === '0' ? '1' : '0') + sig.slice(1);
    expect(await verifySignature('hello world', flipped, keypair.publicKeyHex)).toBe(false);
  });

  test('RT-4: verify with a different keypair public key → false', async () => {
    const keypair2 = await generateKeypair();
    const sig = await signMessage('hello world', keypair.cryptoKeyPair);
    expect(await verifySignature('hello world', sig, keypair2.publicKeyHex)).toBe(false);
  });
});

// ============================================================
// Guard and validation tests (GV-1 – GV-6)
// ============================================================
describe('guard and validation', () => {
  let keypair;

  beforeAll(async () => {
    keypair = await generateKeypair();
  });

  // GV-1: signMessage with no keypair
  test('GV-1: signMessage(null keypair) returns FR-3.5 error string', async () => {
    const result = await signMessage('hello', null);
    expect(result).toBe('No keypair loaded. Generate a keypair before signing.');
  });

  // GV-2: verifySignature with empty public key
  test('GV-2: verifySignature(empty public key) returns FR-4.2 error string', async () => {
    const sig = await signMessage('hello', keypair.cryptoKeyPair);
    const result = await verifySignature('hello', sig, '');
    expect(result).toBe('No keypair loaded. Generate a keypair before verifying.');
  });

  // GV-3: verifySignature with empty signature
  test('GV-3: verifySignature(empty signature) returns FR-4.3 error string', async () => {
    const result = await verifySignature('hello', '', keypair.publicKeyHex);
    expect(result).toBe('No signature to verify. Sign a message first.');
  });

  // GV-4: signature is 127 chars (one short)
  test('GV-4: verifySignature(127-char signature) returns FR-4.4 error string', async () => {
    const sig = await signMessage('hello', keypair.cryptoKeyPair);
    const result = await verifySignature('hello', sig.slice(0, 127), keypair.publicKeyHex);
    expect(result).toBe('Invalid signature: must be 128 hex characters (raw r||s).');
  });

  // GV-5: non-hex character in signature
  test('GV-5: verifySignature(non-hex char in signature) returns FR-4.4 error string', async () => {
    const sig = await signMessage('hello', keypair.cryptoKeyPair);
    // Replace char at position 64 with 'Z' — still 128 chars but fails hex regex
    const bad = sig.slice(0, 64) + 'Z' + sig.slice(65);
    const result = await verifySignature('hello', bad, keypair.publicKeyHex);
    expect(result).toBe('Invalid signature: must be 128 hex characters (raw r||s).');
  });

  // GV-6: public key truncated to 128 chars (not 130)
  test('GV-6: verifySignature(truncated public key) returns FR-4.5 error string', async () => {
    const sig = await signMessage('hello', keypair.cryptoKeyPair);
    const result = await verifySignature('hello', sig, keypair.publicKeyHex.slice(0, 128));
    expect(result).toBe('Invalid public key format.');
  });
});
