'use strict';

/**
 * app.js — UI event handlers for the Hashing + ECDSA P-256 web app.
 *
 * Depends on: crypto-utils.js loaded before this script.
 * All crypto work is delegated to the functions in crypto-utils.js.
 *
 * State held here:
 *   currentKeypair — result of the last generateKeypair() call, or null.
 *                    Cleared conceptually when a new keypair is generated
 *                    (the old object is replaced; the signature/result fields
 *                    are cleared per FR-2.5).
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
// Application state
// ---------------------------------------------------------------------------
let currentKeypair = null; // { publicKeyHex, privateKeyHex, cryptoKeyPair }

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
    currentKeypair = await generateKeypair();
    document.getElementById('public-key').value = currentKeypair.publicKeyHex;
    document.getElementById('private-key').value = currentKeypair.privateKeyHex;
    // FR-2.5: clear stale signature and verification result from the previous keypair
    document.getElementById('signature').value = '';
  } catch (err) {
    _showEcdsaError(err.message);
  }
});

// ---------------------------------------------------------------------------
// ECDSA section — Sign (FR-3.1 – FR-3.5)
// ---------------------------------------------------------------------------
document.getElementById('sign-btn').addEventListener('click', async function () {
  _clearEcdsaError();
  _clearVerifyResult();
  const message = document.getElementById('ecdsa-message').value;
  try {
    const result = await signMessage(
      message,
      currentKeypair ? currentKeypair.cryptoKeyPair : null
    );
    // signMessage returns an error string when no keypair is loaded (FR-3.5)
    if (!/^[0-9a-f]{128}$/.test(result)) {
      _showEcdsaError(result);
      return;
    }
    document.getElementById('signature').value = result;
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
