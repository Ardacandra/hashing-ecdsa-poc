'use strict';

/**
 * crypto-utils.js
 *
 * Pure async crypto functions for SHA-256 hashing and ECDSA P-256 sign/verify.
 * Uses the Web Crypto API (crypto.subtle) — available natively in all modern
 * browsers and Node.js 18+.
 *
 * All binary outputs are returned as lowercase hex strings with no separators:
 *   SHA-256 digest  : 64 chars
 *   P-256 public key: 130 chars (04 || X || Y, uncompressed)
 *   P-256 private key scalar: 64 chars
 *   ECDSA signature (r || s)  : 128 chars
 */

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/**
 * Hash a UTF-8 string with SHA-256.
 * @param {string} text  Any string, including empty.
 * @returns {Promise<string>} 64-character lowercase hex digest.
 */
async function sha256Hash(text) {
  const buf = new TextEncoder().encode(text);
  const hashBuf = await globalThis.crypto.subtle.digest('SHA-256', buf);
  return _bufToHex(hashBuf);
}

// ---------------------------------------------------------------------------
// ECDSA P-256 — key generation
// ---------------------------------------------------------------------------

/**
 * Generate a fresh ECDSA P-256 keypair.
 *
 * Public key  : exported as raw (uncompressed point 04 || X || Y) → 130 hex chars.
 * Private key : exported as PKCS#8, then the 32-byte scalar is sliced from the
 *               fixed offset 36–68 of the 138-byte P-256 PKCS#8 DER structure.
 *               The buffer length is asserted before slicing so that malformed
 *               output surfaces an explicit error rather than silent data corruption.
 *
 * @returns {Promise<{publicKeyHex: string, privateKeyHex: string, cryptoKeyPair: CryptoKeyPair}>}
 * @throws {Error} If the exported PKCS#8 buffer is not exactly 138 bytes.
 */
async function generateKeypair() {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  // Public key: raw export gives the 65-byte uncompressed EC point (04 || X || Y)
  const pubRaw = await globalThis.crypto.subtle.exportKey('raw', keyPair.publicKey);
  const publicKeyHex = _bufToHex(pubRaw); // 130 hex chars

  // Private key: PKCS#8 export, then extract the 32-byte scalar
  const privPkcs8 = await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  if (privPkcs8.byteLength !== 138) {
    throw new Error(
      'Unexpected PKCS#8 length: ' + privPkcs8.byteLength +
      '. Cannot safely extract private key scalar.'
    );
  }
  // Bytes 36–67 (inclusive) of the standard P-256 PKCS#8 DER structure hold the
  // 32-byte private scalar d. slice(36, 68) extracts exactly those bytes.
  const privateKeyHex = _bufToHex(privPkcs8.slice(36, 68)); // 64 hex chars

  return { publicKeyHex, privateKeyHex, cryptoKeyPair: keyPair };
}

// ---------------------------------------------------------------------------
// ECDSA P-256 — sign
// ---------------------------------------------------------------------------

/**
 * Sign a UTF-8 message with the private CryptoKey from a generated keypair.
 *
 * The Web Crypto API returns a 64-byte IEEE P1363 signature (r || s).
 * Each of r and s is a 32-byte big-endian integer; the browser guarantees
 * correct zero-padding, so no manual padLeft is needed here (unlike Dart).
 *
 * @param {string}      message       Plaintext to sign (UTF-8).
 * @param {CryptoKeyPair|null} cryptoKeyPair  The keypair returned by generateKeypair().
 * @returns {Promise<string>} 128-char lowercase hex signature, or an error
 *   string if no keypair is loaded (matches FR-3.5).
 */
async function signMessage(message, cryptoKeyPair) {
  if (!cryptoKeyPair) {
    return 'No keypair loaded. Generate a keypair before signing.';
  }
  const buf = new TextEncoder().encode(message);
  const sigBuf = await globalThis.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    cryptoKeyPair.privateKey,
    buf
  );
  return _bufToHex(sigBuf); // 128 hex chars
}

// ---------------------------------------------------------------------------
// ECDSA P-256 — verify
// ---------------------------------------------------------------------------

/**
 * Verify a P-256 ECDSA signature against a UTF-8 message and a public key hex string.
 *
 * Guard and validation checks (FR-4.2 – FR-4.5) are performed before any crypto
 * call so that the caller can display the exact error message to the user.
 *
 * The public key hex is re-imported from the UI field on every call, which means
 * the user can paste an arbitrary public key into the field and verify against it.
 *
 * @param {string} message       The original plaintext (UTF-8).
 * @param {string} signatureHex  The signature to verify (must be 128 lowercase hex chars).
 * @param {string} publicKeyHex  The public key (must be 130 hex chars starting with '04').
 * @returns {Promise<boolean|string>}
 *   - true  : signature is valid
 *   - false : signature is invalid (crypto result)
 *   - string: a human-readable error message for guard or validation failures
 */
async function verifySignature(message, signatureHex, publicKeyHex) {
  // FR-4.2: no keypair loaded (public key field empty)
  if (!publicKeyHex || publicKeyHex.trim().length === 0) {
    return 'No keypair loaded. Generate a keypair before verifying.';
  }
  // FR-4.3: signature field is empty
  if (!signatureHex || signatureHex.trim().length === 0) {
    return 'No signature to verify. Sign a message first.';
  }
  // FR-4.4: signature must be exactly 128 lowercase hex characters
  if (!/^[0-9a-f]{128}$/.test(signatureHex)) {
    return 'Invalid signature: must be 128 hex characters (raw r||s).';
  }
  // FR-4.5: public key must be exactly 130 hex chars starting with '04'
  if (!/^04[0-9a-f]{128}$/.test(publicKeyHex)) {
    return 'Invalid public key format.';
  }

  try {
    const pubKeyBuf = _hexToBuf(publicKeyHex);
    const publicKey = await globalThis.crypto.subtle.importKey(
      'raw',
      pubKeyBuf,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const msgBuf = new TextEncoder().encode(message);
    const sigBuf = _hexToBuf(signatureHex);
    return await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBuf,
      msgBuf
    );
  } catch (err) {
    return 'Verification error: ' + err.message;
  }
}

// ---------------------------------------------------------------------------
// Helpers (private)
// ---------------------------------------------------------------------------

/** @param {ArrayBuffer} buf */
function _bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(function (b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

/** @param {string} hex */
function _hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes.buffer;
}

// ---------------------------------------------------------------------------
// CommonJS export — used by Jest / Node.js test runner.
// The typeof guard is safe in strict mode; it does not execute in browsers
// where `module` is undefined.
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { sha256Hash, generateKeypair, signMessage, verifySignature };
}
