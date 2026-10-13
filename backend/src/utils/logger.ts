import pino, { type Logger } from 'pino';
import { getEnv } from '../config/env';

/**
 * Structured logging.
 *
 * Two rules matter for a security product:
 *   1. Never log secrets, full URLs with tokens, file contents or notification
 *      bodies. Callers pass *redacted* values; `redact()` below helps.
 *   2. In tests, stay silent unless explicitly asked.
 */

let root: Logger | undefined;

export function createLogger(): Logger {
  if (root) return root;
  const env = getEnv();
  root = pino({
    level: env.NODE_ENV === 'test' ? 'silent' : env.LOG_LEVEL,
    base: undefined,
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers["x-api-key"]',
        'res.headers["set-cookie"]',
        'apiKey',
        'key',
        'token',
      ],
      censor: '[redacted]',
    },
  });
  return root;
}

export function getLogger(): Logger {
  return createLogger();
}

/** Create a child logger scoped to a subsystem. */
export function scopedLogger(scope: string): Logger {
  return createLogger().child({ scope });
}

const SENSITIVE_QUERY_KEYS = /(token|key|secret|password|sig|signature|auth|session)/i;

/**
 * Redact a URL for logging: drop the query string entirely and mask any
 * obvious credential-looking userinfo.
 */
export function redactUrl(raw: string): string {
  try {
    const url = new URL(raw);
    const hadQuery = url.search.length > 0;
    url.search = '';
    url.hash = '';
    const path = url.pathname;
    return `${url.origin}${path}${hadQuery ? '?[redacted]' : ''}`;
  } catch {
    return '[unparseable-url]';
  }
}

export function redactToken(value: string | undefined): string {
  if (!value) return '[none]';
  if (value.length <= 8) return '[redacted]';
  return `${value.slice(0, 4)}…[redacted]…${value.slice(-2)}`;
}

export function looksLikeSecretKey(key: string): boolean {
  return SENSITIVE_QUERY_KEYS.test(key);
}
