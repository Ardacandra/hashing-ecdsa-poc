# Requirements

## Scope

This document covers two deliverables:

- **Assignment 1** — local web app (static page)
- **Assignment 2** — mobile app (Android emulator)

Both implement the same two features: SHA-256 hashing and ECDSA P-256 keypair generation, signing, and verification.

---

## Functional Requirements

### FR-1 SHA-256 Hashing

| ID | Requirement |
|----|-------------|
| FR-1.1 | The user can enter arbitrary plain text into an input field. |
| FR-1.2 | On action (button click), the app computes the SHA-256 digest of the UTF-8 encoded input. |
| FR-1.3 | The resulting digest is displayed as a lowercase hexadecimal string (64 characters). |
| FR-1.4 | An empty input is treated as hashing an empty byte string (produces the well-known SHA-256 empty hash). |

### FR-2 ECDSA P-256 Key Generation

| ID | Requirement |
|----|-------------|
| FR-2.1 | The user can trigger keypair generation on demand. |
| FR-2.2 | The app generates a fresh ECDSA keypair on the P-256 (secp256r1) curve. |
| FR-2.3 | The public key is displayed in uncompressed point format (04 || X || Y) as hex (130 characters). |
| FR-2.4 | The private key scalar is displayed as hex (64 characters). |
| FR-2.5 | When a new keypair is generated, the previously displayed keys, signature field, and verification result are all cleared to prevent stale data being verified against the wrong key. |

### FR-3 Signing

| ID | Requirement |
|----|-------------|
| FR-3.1 | With a keypair loaded, the user can enter a message and sign it. |
| FR-3.2 | The signature is computed using ECDSA over P-256 with SHA-256 as the hash function. |
| FR-3.3 | The signature is displayed as raw (r \|\| s) hex — exactly 128 lowercase hex characters (r and s each zero-padded to 32 bytes). |
| FR-3.4 | After signing, the message text is automatically copied into the verification message field (or kept in the same shared field), so the user does not need to re-enter it manually before verifying. The field remains editable so the user can intentionally tamper with it to test INVALID behaviour. |
| FR-3.5 | If the user attempts to sign before a keypair has been generated, the app displays an error message: "No keypair loaded. Generate a keypair before signing." The sign action must not proceed. |

### FR-4 Verification

| ID | Requirement |
|----|-------------|
| FR-4.1 | The user can verify a signature against a message using the current public key. |
| FR-4.2 | If no keypair has been generated, the app displays an error message: "No keypair loaded. Generate a keypair before verifying." The verify action must not proceed. |
| FR-4.3 | If no signature has been produced yet (the signature field is empty), the app displays an error message: "No signature to verify. Sign a message first." The verify action must not proceed. |
| FR-4.4 | If the signature field contains invalid hex (odd length, non-hex characters, or length ≠ 128 characters), the app displays an error message: "Invalid signature: must be 128 hex characters (raw r\|\|s)." Verification must not proceed. |
| FR-4.5 | If the public key field contains invalid hex (not 130 hex characters starting with `04`), the app displays an error message: "Invalid public key format." Verification must not proceed. |
| FR-4.6 | The app displays a clear VALID or INVALID result. |
| FR-4.7 | Altering the message or signature before verification must produce INVALID. |

---

## Acceptance Criteria

| ID | Criterion | Pass condition |
|----|-----------|----------------|
| AC-1 | SHA-256 of known inputs matches expected digests | See `verification.md` for test vectors |
| AC-2 | Keypair generation produces valid curve points | Public key passes P-256 point-on-curve check |
| AC-3 | Sign then verify with same key and message | Returns VALID |
| AC-4 | Verify with tampered message | Returns INVALID |
| AC-5 | Verify with tampered signature | Returns INVALID |
| AC-6 | App runs fully offline | No network requests at runtime |
| AC-7 | Web app loads as a static file or local dev server | No cloud backend |
| AC-8 | Mobile app runs on Android emulator (API 33+) | Launches without errors |

---

## Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR-1 | No required external network services at runtime. |
| NFR-2 | All cryptographic operations use well-audited primitives (platform APIs or reputable libraries). |
| NFR-3 | Private key material is held only in memory for the session; never persisted to disk automatically. |
| NFR-4 | The UI clearly labels all hex outputs (field names, byte lengths). |
| NFR-5 | Run steps are reproducible from a clean clone per the README. |
| NFR-6 | Mobile app targets **Flutter 3.24.0** (stable channel), **Dart SDK 3.5.0**, **Android compileSdk 34** (min API 21), and **Java 17**. |

---

## Stretch Goals

### Assignment 1 — Web App

| ID | Goal | Acceptance criterion |
|----|------|----------------------|
| SG-W1 | **Known test vectors** — add SHA-256 and ECDSA vectors to `verification.md` | At least 3 SHA-256 vectors (including empty string and NIST "abc") and 1 RFC 6979 ECDSA vector are documented and match app output |
| SG-W2 | **Automated tests** — unit and/or integration tests for hashing and signing logic | Test suite runs with a single command (`npx jest` or equivalent); all tests pass |
| SG-W3 | **Export / import keys** — user can copy keys as hex or download/upload a key file | Public and private key hex can be pasted back in to restore a keypair; signing with a restored key and verifying produces VALID |

### Assignment 2 — Mobile App

| ID | Goal | Acceptance criterion |
|----|------|----------------------|
| SG-M1 | **Copy to clipboard** — all hex output fields have a copy button | Tapping the button writes the full hex string to the device clipboard without truncation |
| SG-M2 | **Automated test suite** — unit tests for hash and ECDSA services, including known vectors | `flutter test` passes; covers at least the SHA-256 empty-string vector and a sign/verify round-trip |
| SG-M3 | **Signature encoding toggle** — switch between raw (r \|\| s) and DER encoding with explanation | UI toggle changes displayed signature format; both pass verification; `tech-spec.md` explains the structural difference between the two encodings |

---

## Out of Scope

- Key persistence / secure storage across sessions
- Certificate / PKI workflows
- Any server-side component
- Authentication or user accounts
