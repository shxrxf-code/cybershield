import type { RequestHandler } from 'express';
import type { Env } from '../config/env';
import { sha256Hex, safeEqualHex } from '../utils/hash';
import { ConfigurationError, UnauthorizedError } from '../utils/errors';
import { scopedLogger } from '../utils/logger';

const HEX64 = /^[a-f0-9]{64}$/i;

/**
 * API-key authentication.
 *
 * The mobile app authenticates with `X-API-Key` (or `Authorization: Bearer …`).
 * Only SHA-256 *hashes* of valid keys exist in configuration, so a leaked
 * environment file does not disclose usable keys, and comparisons are
 * constant-time.
 *
 * When no hashes are configured: production refuses to serve protected routes
 * (fail closed); development and test allow them so the app is runnable before
 * keys exist. That behaviour is logged loudly, never silent.
 */
export function apiKeyAuth(env: Env): RequestHandler {
  const log = scopedLogger('auth');
  const hashes = env.API_KEY_HASHES.filter((hash) => HEX64.test(hash));

  if (hashes.length === 0 && env.NODE_ENV === 'production') {
    throw new ConfigurationError(
      'API_KEY_HASHES is empty. Set at least one SHA-256 key hash before running in production.',
    );
  }

  return (req, _res, next) => {
    if (hashes.length === 0) {
      log.warn({ path: req.path }, 'API key authentication disabled (no API_KEY_HASHES configured)');
      next();
      return;
    }

    const header = req.header('x-api-key');
    const bearer = req.header('authorization')?.replace(/^Bearer\s+/i, '');
    const provided = (header ?? bearer ?? '').trim();

    if (provided.length === 0) {
      next(new UnauthorizedError('An API key is required (X-API-Key header)'));
      return;
    }

    const digest = sha256Hex(provided);
    const matches = hashes.some((hash) => safeEqualHex(hash, digest));
    if (!matches) {
      log.warn({ path: req.path }, 'rejected request with invalid API key');
      next(new UnauthorizedError('Invalid API key'));
      return;
    }

    next();
  };
}
