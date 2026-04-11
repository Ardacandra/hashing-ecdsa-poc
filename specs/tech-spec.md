# Technical Specification

## 1. Overview

Two self-contained apps share the same feature set: SHA-256 hashing and ECDSA P-256 sign/verify. Each targets a different platform but uses platform-native cryptographic primitives to avoid third-party crypto code.

---

## 2. Assignment 1 — Web App

### 2.1 Technology Choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Runtime | Browser (static HTML + JS) | Zero install; runs from `file://` or any local server |
| Crypto | `window.crypto.subtle` (Web Crypto API) | Built-in, FIPS-validated in major browsers; native P-256 and SHA-256 support |
| UI | Vanilla HTML / CSS / JS | No build step; no framework dependency; easiest to audit |
| Local server (optional) | `python3 -m http.server` or `npx serve` | One-liner; no install beyond Python or Node |

Web Crypto API support: Chrome 37+, Firefox 34+, Safari 11+, Edge 12+. All current browsers qualify.

### 2.2 Architecture

```
index.html
├── <style>          — inline or linked CSS
└── <script>         — app.js (or inline)
    ├── sha256Hash(text) → hex string
    ├── generateKeypair() → { publicKeyHex, privateKeyHex, cryptoKeyPair }
    ├── signMessage(message, cryptoKeyPair) → signatureHex
    └── verifySignature(message, signatureHex, publicCryptoKey) → boolean
```

All state (keypair, last message, last signature) is held in JS module-level variables. Nothing is written to `localStorage` or cookies.

### 2.3 Key Flows

#### SHA-256 Hash
1. Read input string → encode as UTF-8 (`TextEncoder`).
2. Call `crypto.subtle.digest("SHA-256", buffer)`.
3. Convert `ArrayBuffer` result to lowercase hex string.
4. Display in output field.

#### Keypair Generation
1. Call `crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])`.
2. Export public key: `crypto.subtle.exportKey("raw", publicKey)` — returns 65-byte uncompressed point.
3. Export private key: `crypto.subtle.exportKey("pkcs8", privateKey)` — extract the 32-byte scalar from the PKCS#8 DER structure (bytes 36–68 of the standard P-256 PKCS#8 encoding). Before slicing, assert that the exported buffer is exactly 138 bytes; if not, throw `Error("Unexpected PKCS#8 length: " + buf.byteLength + ". Cannot safely extract private key scalar.")` and surface it to the user rather than silently returning garbage.
4. Display both as hex.

> **Why raw for public key?** The `"raw"` export format for EC keys gives the uncompressed point directly (04 || X || Y), which is the most readable and standard representation for display purposes.

#### Sign
1. Guard: if no keypair is loaded, display "No keypair loaded. Generate a keypair before signing." and abort.
2. Encode message as UTF-8.
3. Call `crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, buffer)`.
4. The result is a 64-byte IEEE P1363 signature (r || s), each 32 bytes big-endian. Display as 128-char hex.
5. Copy the signed message text into the verification message field automatically.

#### Verify
1. Guard: if no keypair is loaded, display "No keypair loaded. Generate a keypair before verifying." and abort.
2. Guard: if the signature field is empty, display "No signature to verify. Sign a message first." and abort.
3. Validate signature field: must be exactly 128 lowercase hex characters. If not, display "Invalid signature: must be 128 hex characters (raw r||s)." and abort.
4. Validate public key field: must be exactly 130 hex characters starting with `04`. If not, display "Invalid public key format." and abort.
5. Encode message as UTF-8.
6. Decode signature hex back to `ArrayBuffer`.
7. Call `crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, sigBuffer, msgBuffer)`.
8. Display VALID (green) or INVALID (red).

### 2.4 Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Sign attempted with no keypair | Show error: "No keypair loaded. Generate a keypair before signing." Abort. |
| Verify attempted with no keypair | Show error: "No keypair loaded. Generate a keypair before verifying." Abort. |
| Verify attempted with empty signature field | Show error: "No signature to verify. Sign a message first." Abort. |
| Signature field is not exactly 128 hex chars | Show error: "Invalid signature: must be 128 hex characters (raw r\|\|s)." Abort. |
| Public key field is not 130 hex chars starting with `04` | Show error: "Invalid public key format." Abort. |
| Empty message for hash | Allowed; produces deterministic empty-string hash. |
| `crypto.subtle` unavailable (non-HTTPS in older browsers) | Show banner: "Web Crypto API not available. Open via localhost or https://" |

### 2.5 Security Notes

- All crypto operations use the browser's native implementation — no third-party JS crypto.
- Private key scalar is displayed for demo/educational purposes only. In a production system the private key would never be exported.
- No data leaves the browser; no external network calls.
- Content Security Policy (CSP) header recommended when serving via a local server: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'`.

---

## 3. Assignment 2 — Mobile App

### 3.1 Technology Choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Framework | Flutter stable channel (3.24.0+), Dart 3.5.0+ | Single codebase; strong Android emulator support; no Expo Go dependency |
| Crypto — hashing | `pointycastle` (`SHA256Digest`) | Already required for ECDSA; avoids adding a second crypto dependency |
| Crypto — ECDSA | `pointycastle` (`ECDSASigner`, `ECCurve_secp256r1`) | De-facto standard Dart crypto library; supports P-256 natively |
| Target platform | Android emulator (API 33, Pixel 4 profile) | Cross-platform toolchain is available; iOS requires macOS |
| Android SDK | compileSdk 36, minSdk 21 (Android 5.0) | Required by Flutter 3.41.x; broad device compatibility |
| Java | 17 | Required by Android Gradle Plugin 8.x |

### 3.2 Architecture

```
lib/
├── main.dart                  — MaterialApp entry point
├── screens/
│   └── home_screen.dart       — single-screen UI with two tabs (SHA-256 tab and ECDSA tab)
└── crypto/
    ├── sha256_service.dart    — SHA-256 wrapper
    └── ecdsa_service.dart     — P-256 keygen, sign, verify wrappers
```

### 3.3 Key Flows

#### SHA-256 Hash
1. Convert input string to UTF-8 bytes (`utf8.encode`).
2. Feed into `SHA256Digest` from `pointycastle`.
3. Return hex string via `package:convert` `hex.encode`.

#### Keypair Generation
1. Create `ECKeyGeneratorParameters(ECCurve_secp256r1())`.
2. Seed `FortunaRandom` with platform entropy (`dart:math` `Random.secure`).
3. `ECKeyGenerator().generateKeyPair()` returns `AsymmetricKeyPair<ECPublicKey, ECPrivateKey>`.
4. Public key: uncompressed point `04 || x || y` where x and y are each explicitly left-padded to 64 hex characters: `point.x!.toBigInteger()!.toRadixString(16).padLeft(64, '0')` (and same for y). `toRadixString(16)` alone drops leading zeros — the `padLeft` is mandatory, not optional.
5. Private key: `d` scalar as 64 hex characters — `privateKey.d!.toRadixString(16).padLeft(64, '0')`. Same leading-zero risk as the coordinates above.

#### Sign
1. Guard: if no keypair is loaded, display "No keypair loaded. Generate a keypair before signing." and abort.
2. Create `ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))` — the `HMac` second argument enables RFC 6979 deterministic k per the pointycastle API (the `Mac` parameter, not `HMacDSAKCalculator`).
3. `signer.init(true, PrivateKeyParameter(privateKey))`.
4. `signer.generateSignature(messageBytes)` → `ECSignature(r, s)`.
5. Encode as raw `r || s`: `sig.r.toRadixString(16).padLeft(64, '0') + sig.s.toRadixString(16).padLeft(64, '0')` → 128-char hex string. `padLeft` is mandatory here for the same reason as coordinates.
6. Copy the signed message text into the verification message field automatically.

> RFC 6979 deterministic nonce is used so that signing the same message twice produces the same signature, making test vectors stable.

#### Verify
1. Guard: if no keypair is loaded, display "No keypair loaded. Generate a keypair before verifying." and abort.
2. Guard: if the signature field is empty, display "No signature to verify. Sign a message first." and abort.
3. Validate signature field: must be exactly 128 hex characters. If not, display "Invalid signature: must be 128 hex characters (raw r||s)." and abort.
4. Validate public key field: must be exactly 130 hex characters starting with `04`. If not, display "Invalid public key format." and abort.
5. `ECDSASigner(SHA256Digest()).init(false, PublicKeyParameter(publicKey))`.
6. Decode signature hex → split at midpoint into r and s `BigInt` values (each 32 bytes).
7. `signer.verifySignature(messageBytes, ECSignature(r, s))` → bool.
8. Display VALID or INVALID.

### 3.4 Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Sign attempted with no keypair | Show error: "No keypair loaded. Generate a keypair before signing." Abort. |
| Verify attempted with no keypair | Show error: "No keypair loaded. Generate a keypair before verifying." Abort. |
| Verify attempted with empty signature field | Show error: "No signature to verify. Sign a message first." Abort. |
| Signature field is not exactly 128 hex chars | Show error: "Invalid signature: must be 128 hex characters (raw r\|\|s)." Abort. |
| Public key field is not 130 hex chars starting with `04` | Show error: "Invalid public key format." Abort. |
| Empty message for hash | Allowed; deterministic hash of empty bytes. |
| `pointycastle` internal exception | Caught at service boundary; displayed as generic error message. |

### 3.5 Security Notes

- `FortunaRandom` seeded with `Random.secure()` — uses OS CSPRNG (`/dev/urandom` on Android).
- RFC 6979 deterministic k eliminates nonce reuse risk that plagues naïve ECDSA implementations.
- Private key is held only in the widget state; not written to device storage.
- This is a demo app — key display is intentional for educational purposes.

---

## 4. Shared Design Decisions

### Hex Encoding Convention
All binary outputs (digests, keys, signatures) are lowercase hex, no separators, no `0x` prefix. Lengths are fixed:
- SHA-256 digest: 64 chars
- P-256 public key (uncompressed): 130 chars (`04` + 64 + 64)
- P-256 private key scalar: 64 chars
- ECDSA signature (r || s): 128 chars

### Signature Encoding: Raw vs DER (SG-M3)

ECDSA signatures are mathematically a pair of integers **(r, s)**. There are two common wire formats:

| Property | Raw (r ‖ s) | DER (ASN.1) |
|----------|-------------|-------------|
| Structure | r and s concatenated directly | ASN.1 SEQUENCE wrapping two INTEGERs |
| Length | Always exactly 64 bytes (128 hex chars) | 70–72 bytes typically (140–144 hex chars) |
| r / s padding | Each zero-padded to 32 bytes | Leading zero bytes stripped; 0x00 prepended if high bit set |
| Used by | Web Crypto API (IEEE P1363), this app | TLS, X.509, most PKI standards |

**Raw format byte layout (64 bytes):**

```
[32 bytes r, big-endian, zero-padded] [32 bytes s, big-endian, zero-padded]
```

**DER format byte layout (variable, ~70–72 bytes):**

```
30 <seq-len>          — SEQUENCE
  02 <r-len> <r>      — INTEGER r  (31–33 bytes depending on leading zeros / high bit)
  02 <s-len> <s>      — INTEGER s  (31–33 bytes depending on leading zeros / high bit)
```

The DER INTEGER encoding rule that causes variable length: if the most significant bit of the first byte of r (or s) is **1**, a `0x00` prefix byte is added to signal a positive value. Conversely, leading `0x00` bytes are stripped. This means r and s each encode to 31, 32, or 33 bytes.

The mobile app converts between formats in `EcdsaService.rawToDer` / `EcdsaService.derToRaw`. Verification always uses raw internally; the DER→raw conversion happens in the UI layer before calling `EcdsaService.verify`.

### No Key Persistence
Private keys are intentionally ephemeral. Persisting private key material is outside scope and would require platform secure storage (Keychain / Android Keystore), which adds complexity inconsistent with a PoC.

### Algorithm Identifiers
- Hash: SHA-256 (FIPS 180-4)
- Curve: P-256 / secp256r1 / prime256v1 (NIST SP 800-186)
- Signature scheme: ECDSA (FIPS 186-5), hash-then-sign
- Nonce generation: RFC 6979 (mobile); browser-native (web, implementation detail of the UA)
