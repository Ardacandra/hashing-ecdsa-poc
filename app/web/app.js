'use strict';

/**
 * app.js — UI event handlers for the Hashing + ECDSA P-256 web app.
 *
 * Depends on: crypto-utils.js loaded before this script.
 * All crypto work is delegated to the functions in crypto-utils.js.
 *
 * The sign handler reads the public and private key hex directly from the
 * UI fields on every click, so imported or pasted keys work without any
 * separate "restore keypair" step.
 */

// ---------------------------------------------------------------------------
// Startup: Web Crypto availability check
// ---------------------------------------------------------------------------
(function checkCrypto() {
  if (typeof window.crypto === 'undefined' || !window.crypto.subtle) {
    document.getElementById('crypto-unavailable').classList.remove('hidden');
  }
}());

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
document.querySelectorAll('.tab-btn').forEach(function (btn) {
  btn.addEventListener('click', function () {
    document.querySelectorAll('.tab-btn').forEach(function (b) {
      b.classList.remove('active');
    });
    document.querySelectorAll('.tab-panel').forEach(function (p) {
      p.classList.remove('active');
    });
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

// ---------------------------------------------------------------------------
// SHA-256 section
// ---------------------------------------------------------------------------
document.getElementById('hash-btn').addEventListener('click', async function () {
  const text = document.getElementById('hash-input').value;
  try {
    const hex = await sha256Hash(text);
    document.getElementById('hash-output').value = hex;
  } catch (err) {
    document.getElementById('hash-output').value = 'Error: ' + err.message;
  }
});

// ---------------------------------------------------------------------------
// ECDSA section — Generate Keypair (FR-2.1 – FR-2.5)
// ---------------------------------------------------------------------------
document.getElementById('generate-btn').addEventListener('click', async function () {
  _clearEcdsaError();
  _clearVerifyResult();
  try {
    const keypair = await generateKeypair();
    document.getElementById('public-key').value = keypair.publicKeyHex;
    document.getElementById('private-key').value = keypair.privateKeyHex;
    // FR-2.5: clear stale signature and verification result from the previous keypair
    document.getElementById('signature').value = '';
  } catch (err) {
    _showEcdsaError(err.message);
  }
});

// ---------------------------------------------------------------------------
// SG-W3: Export — copy key hex to clipboard
// ---------------------------------------------------------------------------
document.getElementById('copy-pubkey-btn').addEventListener('click', async function () {
  const hex = document.getElementById('public-key').value.trim();
  if (!hex) { _showEcdsaError('No public key to copy.'); return; }
  await navigator.clipboard.writeText(hex);
});

document.getElementById('copy-privkey-btn').addEventListener('click', async function () {
  const hex = document.getElementById('private-key').value.trim();
  if (!hex) { _showEcdsaError('No private key to copy.'); return; }
  await navigator.clipboard.writeText(hex);
});

// ---------------------------------------------------------------------------
// SG-W3: Import — read key hex from a .txt file into the textarea
// ---------------------------------------------------------------------------
document.getElementById('import-pubkey-btn').addEventListener('click', function () {
  document.getElementById('import-pubkey-file').click();
});
document.getElementById('import-pubkey-file').addEventListener('change', async function () {
  const file = this.files[0];
  if (!file) return;
  document.getElementById('public-key').value = (await file.text()).trim();
  this.value = ''; // reset so the same file can be re-imported
});

document.getElementById('import-privkey-btn').addEventListener('click', function () {
  document.getElementById('import-privkey-file').click();
});
document.getElementById('import-privkey-file').addEventListener('change', async function () {
  const file = this.files[0];
  if (!file) return;
  document.getElementById('private-key').value = (await file.text()).trim();
  this.value = '';
});

// ---------------------------------------------------------------------------
// SG-W3: Export — download key hex as a text file
// ---------------------------------------------------------------------------
document.getElementById('download-pubkey-btn').addEventListener('click', function () {
  const hex = document.getElementById('public-key').value.trim();
  if (!hex) { _showEcdsaError('No public key to download.'); return; }
  _downloadText('public-key.txt', hex);
});

document.getElementById('download-privkey-btn').addEventListener('click', function () {
  const hex = document.getElementById('private-key').value.trim();
  if (!hex) { _showEcdsaError('No private key to download.'); return; }
  _downloadText('private-key.txt', hex);
});

// ---------------------------------------------------------------------------
// ECDSA section — Sign (FR-3.1 – FR-3.5)
// ---------------------------------------------------------------------------
document.getElementById('sign-btn').addEventListener('click', async function () {
  _clearEcdsaError();
  _clearVerifyResult();
  const publicKeyHex  = document.getElementById('public-key').value.trim();
  const privateKeyHex = document.getElementById('private-key').value.trim();
  const message       = document.getElementById('ecdsa-message').value;

  // FR-3.5: both key fields empty — no keypair loaded at all
  if (!publicKeyHex && !privateKeyHex) {
    _showEcdsaError('No keypair loaded. Generate a keypair before signing.');
    return;
  }

  try {
    // Import directly from the key fields so that keys loaded from a file
    // or pasted in are immediately usable for signing (SG-W3).
    const keypair = await importKeypair(publicKeyHex, privateKeyHex);
    const sig = await signMessage(message, keypair.cryptoKeyPair);
    document.getElementById('signature').value = sig;
    // FR-3.4: the message field is shared between sign and verify — no copy needed.
  } catch (err) {
    _showEcdsaError(err.message);
  }
});

// ---------------------------------------------------------------------------
// ECDSA section — Verify (FR-4.1 – FR-4.7)
// ---------------------------------------------------------------------------
document.getElementById('verify-btn').addEventListener('click', async function () {
  _clearEcdsaError();
  _clearVerifyResult();
  const message = document.getElementById('ecdsa-message').value;
  // Trim whitespace from editable hex fields to be lenient about accidental spaces
  const signatureHex = document.getElementById('signature').value.trim();
  const publicKeyHex = document.getElementById('public-key').value.trim();

  try {
    const result = await verifySignature(message, signatureHex, publicKeyHex);
    if (typeof result === 'string') {
      // Guard or validation error — display to user
      _showEcdsaError(result);
    } else if (result === true) {
      _showVerifyResult('VALID', true);
    } else {
      _showVerifyResult('INVALID', false);
    }
  } catch (err) {
    _showEcdsaError(err.message);
  }
});

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------
function _showEcdsaError(msg) {
  const el = document.getElementById('ecdsa-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function _clearEcdsaError() {
  const el = document.getElementById('ecdsa-error');
  el.textContent = '';
  el.classList.add('hidden');
}

function _showVerifyResult(label, valid) {
  const el = document.getElementById('verify-result');
  el.textContent = label;
  el.className = 'verify-result ' + (valid ? 'valid' : 'invalid');
}

function _clearVerifyResult() {
  const el = document.getElementById('verify-result');
  el.textContent = '';
  el.className = 'verify-result hidden';
}

function _downloadText(filename, text) {
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
  a.download = filename;
  a.click();
}
