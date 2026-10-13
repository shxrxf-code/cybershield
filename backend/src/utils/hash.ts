import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Constant-time comparison of two hex digests of equal length. */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufferA = Buffer.from(a, 'hex');
  const bufferB = Buffer.from(b, 'hex');
  if (bufferA.length !== bufferB.length) return false;
  return timingSafeEqual(bufferA, bufferB);
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * Short, stable correlation id. Not a secret – just enough to join logs to a
 * request without leaking anything.
 */
export function newCorrelationId(): string {
  return randomBytes(8).toString('hex');
}

export function sha256HexSafe(input: unknown): string {
  if (typeof input === 'string') return sha256Hex(input);
  if (Buffer.isBuffer(input)) return sha256Hex(input);
  return sha256Hex(JSON.stringify(input ?? ''));
}
