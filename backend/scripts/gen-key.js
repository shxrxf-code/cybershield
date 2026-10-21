#!/usr/bin/env node
/**
 * Generate a ThreatGuard API key and its SHA-256 hash.
 *
 * The mobile app sends the plaintext key; the server only ever stores the
 * hash, so the two are printed together exactly once, here.
 *
 * Usage:
 *   npm run --silent gen:key            # one key
 *   npm run --silent gen:key -- 3       # three keys
 *
 * Put the hashes in API_KEY_HASHES (comma separated) and the plaintext key in
 * mobile/src/api/local-config.ts (which is git-ignored).
 */
const crypto = require('node:crypto');

const count = Number(process.argv[2]) || 1;
if (!Number.isInteger(count) || count < 1 || count > 20) {
  console.error('gen:key expects a count between 1 and 20');
  process.exit(1);
}

for (let i = 0; i < count; i += 1) {
  const key = `tg_${crypto.randomBytes(24).toString('base64url')}`;
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  console.log(`key : ${key}`);
  console.log(`hash: ${hash}`);
  console.log('');
}

console.log('Add the hash(es) to API_KEY_HASHES in backend/.env,');
console.log('and the key to mobile/src/api/local-config.ts (git-ignored).');
