# Verification

## 1. Approach

Correctness is verified at three levels:

1. **Known test vectors** — fixed inputs with published expected outputs (SHA-256 from NIST FIPS 180-4; ECDSA from NIST CAVP / RFC 6979).
2. **Round-trip tests** — sign then verify with the same key, and verify that tampered inputs fail.
3. **Manual UI walkthrough** — step-by-step instructions to exercise the app by hand.

---

## 2. SHA-256 Test Vectors

Source: NIST FIPS 180-4, Appendix B.1 and common reference values.

| # | Input (UTF-8 string) | Expected SHA-256 (hex) |
|---|----------------------|------------------------|
| V-H1 | `""` (empty string) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| V-H2 | `"abc"` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| V-H3 | `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"` | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |
| V-H4 | `"The quick brown fox jumps over the lazy dog"` | `d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592` |

All outputs must be exactly 64 lowercase hex characters with no spaces or separators.

### How to verify SHA-256 independently

```bash
# Linux / macOS
echo -n "" | sha256sum
echo -n "abc" | sha256sum
echo -n "The quick brown fox jumps over the lazy dog" | sha256sum

# Windows (PowerShell)
[System.BitConverter]::ToString(
  [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes("abc")
  )
).Replace("-","").ToLower()
```

---

## 3. ECDSA P-256 Test Vectors

### 3.1 RFC 6979 Deterministic Signature Vectors

Source: RFC 6979 §A.2.5 — ECDSA, 256 Bits (Prime Field), with SHA-256.

The private key scalar `d` and message are fixed; the expected `(r, s)` is deterministic.

**Key material:**

```
private key (d, hex):
  c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721

public key (uncompressed, hex):
  0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6
  7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299
```

**Test case 1 — message `"sample"`:**

```
message bytes (UTF-8): 73616d706c65
hash (SHA-256 of message): af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf

r: efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
s: f7cb1c942d657ef404150ea93f47e8d8c4a8e4d0e5a74ceb3bee60bd9b2f75a

signature (r||s, 128 lowercase hex chars):
  efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657ef404150ea93f47e8d8c4a8e4d0e5a74ceb3bee60bd9b2f75a
```

> The mobile app uses RFC 6979 deterministic k, so the signature above should be reproducible exactly. The web app uses browser-native signing (non-deterministic k), so r and s will differ per run — but verification must still return VALID.

**Test case 2 — message `"test"`:**

```
r: f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367
s: 019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083

signature (r||s, 128 lowercase hex chars):
  f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083
```

> Test case 2 is useful for verifying correct leading-zero padding: `s` begins with `01`, meaning its raw `BigInt.toRadixString(16)` produces only 63 characters without `.padLeft(64, '0')`. The app must output all 64 characters.

### 3.2 Round-Trip Tests (any key)

These do not require specific key material and should pass every run:

| # | Steps | Expected result |
|---|-------|-----------------|
| RT-1 | Generate keypair → sign `"hello world"` → verify with same key and message | VALID |
| RT-2 | Generate keypair → sign `"hello world"` → change message to `"Hello world"` → verify | INVALID |
| RT-3 | Generate keypair → sign `"hello world"` → flip one hex char in signature → verify | INVALID |
| RT-4 | Generate keypair A → generate keypair B → sign with B → verify with A's public key | INVALID |

### 3.3 Guard and Validation Tests

| # | Steps | Expected result |
|---|-------|-----------------|
| GV-1 | On fresh app load, attempt to sign without generating a keypair | Error: "No keypair loaded. Generate a keypair before signing." No signature produced. |
| GV-2 | On fresh app load, attempt to verify without generating a keypair | Error: "No keypair loaded. Generate a keypair before verifying." No result shown. |
| GV-3 | Generate keypair, do not sign, attempt to verify with empty signature field | Error: "No signature to verify. Sign a message first." No result shown. |
| GV-4 | Generate keypair, sign a message, manually clear one hex char from the signature to make it 127 chars, attempt to verify | Error: "Invalid signature: must be 128 hex characters (raw r\|\|s)." No result shown. |
| GV-5 | Generate keypair, sign a message, enter a non-hex character (e.g. `Z`) anywhere in the signature field, attempt to verify | Error: "Invalid signature: must be 128 hex characters (raw r\|\|s)." No result shown. |
| GV-6 | Generate keypair, sign a message, truncate the public key field to 128 chars, attempt to verify | Error: "Invalid public key format." No result shown. |
| GV-7 | Generate keypair A, sign `"hello"`, then generate keypair B | Signature field and verification result are both cleared; keypair B keys are displayed. |
| GV-8 | Generate keypair, type `"hello world"`, click Sign | Message `"hello world"` is automatically present in the verification message field without manual re-entry. Field remains editable. |

---

## 4. Manual Verification Steps

### 4.1 Web App

1. Open `app/index.html` in a browser (or `http://localhost:PORT` via local server).
2. **SHA-256 tab:**
   a. Leave input empty → click Hash → confirm output equals V-H1 (64 chars, no spaces).
   b. Type `abc` → click Hash → confirm output equals V-H2 (64 chars).
3. **ECDSA tab — happy path:**
   a. Click Generate Keypair → confirm public key starts with `04` and is 130 chars; private key is 64 chars.
   b. Type `hello world` → click Sign → confirm signature is 128 lowercase hex chars.
   c. Confirm `hello world` is auto-populated in the verification message field (FR-3.4).
   d. Click Verify → confirm green VALID result.
   e. Alter the message by one character → click Verify → confirm red INVALID result.
   f. Restore the message, alter one character in the signature → click Verify → confirm INVALID.
4. **ECDSA tab — error paths:**
   a. Reload the page → attempt to click Sign without generating a keypair → confirm error message matches GV-1.
   b. Generate a keypair → attempt to click Verify with empty signature field → confirm error matches GV-3.
   c. Sign a message → delete one character from the signature → attempt Verify → confirm error matches GV-4.
   d. Sign a message → generate a new keypair → confirm signature field and verify result are cleared (GV-7).
5. Open browser DevTools Network tab → confirm zero outbound network requests during all operations.

### 4.2 Mobile App (Android Emulator)

1. Start emulator: `flutter emulators --launch <emulator_id>`.
2. Run app: `flutter run` from `app/` directory.
3. **SHA-256 section:**
   a. Clear the input field → tap Hash → verify output matches V-H1 (64 chars).
   b. Enter `abc` → tap Hash → verify output matches V-H2 (64 chars).
4. **ECDSA section — happy path:**
   a. Tap Generate Keypair → inspect public key (130 hex chars, starts `04`) and private key (64 hex chars).
   b. Enter `hello world` → tap Sign → confirm signature is 128 lowercase hex chars.
   c. Confirm `hello world` is auto-populated in the verification message field (FR-3.4).
   d. Tap Verify → confirm VALID.
   e. Edit message → tap Verify → confirm INVALID.
   f. Restore message, edit one char of signature → tap Verify → confirm INVALID.
5. **ECDSA section — error paths:**
   a. Restart the app → attempt to tap Sign without generating a keypair → confirm error matches GV-1.
   b. Generate a keypair → attempt to tap Verify with empty signature field → confirm error matches GV-3.
   c. Sign a message → delete one character from the signature → tap Verify → confirm error matches GV-4.
   d. Sign a message → tap Generate Keypair → confirm signature field and verify result are cleared (GV-7).
6. **(Optional — mobile only)** Import RFC 6979 private key from §3.1, sign `"sample"`, confirm the full 128-char r||s matches test case 1 exactly.
7. **(Optional)** Sign `"test"` with the RFC 6979 key → confirm the `s` component starts with `01` and the total output is 128 chars, verifying correct `padLeft(64, '0')` behaviour.

---

## 5. Automated Tests

### Web App

Tests live in `app/tests/` and run with:

```bash
npx jest   # or: node --test tests/sha256.test.js
```

Covered cases:

- `sha256Hash("")` → V-H1
- `sha256Hash("abc")` → V-H2
- `sha256Hash("The quick brown fox...")` → V-H4
- `generateKeypair()` → public key length 130, starts with `04`, private key length 64
- `signMessage` + `verifySignature` round-trip → `true`
- `verifySignature` with wrong message → `false`
- `verifySignature` with flipped signature byte → `false`
- `signMessage` called with no keypair → throws / returns error string matching FR-3.5 message
- `verifySignature` called with 127-char signature → returns validation error matching FR-4.4 message
- `verifySignature` called with non-hex character in signature → returns validation error matching FR-4.4 message
- `verifySignature` called with malformed public key → returns validation error matching FR-4.5 message

### Mobile App

Tests live in `app/test/` and run with:

```bash
flutter test
```

Covered cases:

- `Sha256Service.hash("")` → V-H1
- `Sha256Service.hash("abc")` → V-H2
- `EcdsaService.generateKeypair()` → public key 65 bytes, first byte `0x04`, private key 32 bytes
- Sign `"hello"` + verify same message → `true`
- Sign `"hello"` + verify `"Hell0"` → `false`
- Sign `"test"` with RFC 6979 fixed private key → s component is 64 hex chars starting with `01` (leading-zero padding)
- `EcdsaService.sign()` called with null keypair → throws/returns error matching FR-3.5 message
- `EcdsaService.verify()` with 127-char signature → returns validation error matching FR-4.4 message
- `EcdsaService.verify()` with non-hex signature → returns validation error matching FR-4.4 message
- `EcdsaService.verify()` with malformed public key → returns validation error matching FR-4.5 message

---

## 6. Known Limitations and Edge Cases

| Item | Notes |
|------|-------|
| Web Crypto signature encoding | Browser returns IEEE P1363 (r\|\|s), not DER. The app displays this raw format. |
| Signature non-determinism (web) | Web Crypto does not expose k; signatures differ per run. RFC 6979 vectors from §3.1 cannot be reproduced in the web app. |
| Leading-zero padding | Both r and s must be zero-padded to 32 bytes each. Test case 2 (§3.1) exercises this: `s` begins with `01` and would be 63 chars without explicit `padLeft(64, '0')`. |
| PKCS#8 buffer length (web) | The private key extraction asserts the exported buffer is exactly 138 bytes before slicing. If this assertion ever fires, the error is surfaced to the UI rather than silently corrupting the key. |
| UTF-8 vs other encodings | All text inputs are treated as UTF-8. Inputs with non-ASCII characters will produce different hashes than Latin-1 or UTF-16 interpretations. |
