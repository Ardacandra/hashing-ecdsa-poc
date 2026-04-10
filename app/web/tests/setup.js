'use strict';

/**
 * Jest setup: ensure globalThis.crypto (Web Crypto API) is available.
 *
 * Node.js 19+ exposes it as a global automatically.
 * Node.js 18 exposes it via globalThis but it may not be visible as a bare
 * `crypto` identifier in CommonJS modules, so we set it explicitly here.
 */
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  const { webcrypto } = require('node:crypto');
  globalThis.crypto = webcrypto;
}
