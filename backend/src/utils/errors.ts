/**
 * Application error taxonomy.
 *
 * Every error that reaches the client is rendered through one envelope:
 *
 *   { "error": { "code", "message", "status_code", "correlation_id", "details"? } }
 *
 * There is deliberately no top-level `detail` key. `details` is only ever
 * populated from a validated, non-sensitive source.
 */

export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'PAYLOAD_TOO_LARGE'
  | 'UPSTREAM_UNAVAILABLE'
  | 'UPSTREAM_TIMEOUT'
  | 'CONFIGURATION_ERROR'
  | 'INTERNAL_ERROR';

export interface AppErrorOptions {
  code: ErrorCode;
  statusCode: number;
  message: string;
  details?: unknown;
  cause?: unknown;
  /** Safe to expose to the client; defaults to true for AppError subclasses. */
  expose?: boolean;
}

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly details?: unknown;
  readonly expose: boolean;
  override readonly cause?: unknown;

  constructor(options: AppErrorOptions) {
    super(options.message);
    this.name = new.target.name;
    this.code = options.code;
    this.statusCode = options.statusCode;
    this.details = options.details;
    this.expose = options.expose ?? true;
    this.cause = options.cause;
    Error.captureStackTrace?.(this, new.target);
  }
}

export class ValidationError extends AppError {
  constructor(message = 'Request validation failed', details?: unknown) {
    super({ code: 'VALIDATION_ERROR', statusCode: 400, message, details });
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Missing or invalid API credentials') {
    super({ code: 'UNAUTHORIZED', statusCode: 401, message });
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Not permitted') {
    super({ code: 'FORBIDDEN', statusCode: 403, message });
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super({ code: 'NOT_FOUND', statusCode: 404, message });
  }
}

export class UnsupportedMediaTypeError extends AppError {
  constructor(message = 'Unsupported media type', details?: unknown) {
    super({ code: 'UNSUPPORTED_MEDIA_TYPE', statusCode: 415, message, details });
  }
}

export class PayloadTooLargeError extends AppError {
  constructor(message = 'Payload too large') {
    super({ code: 'PAYLOAD_TOO_LARGE', statusCode: 413, message });
  }
}

export class ConfigurationError extends AppError {
  constructor(message: string) {
    super({ code: 'CONFIGURATION_ERROR', statusCode: 500, message, expose: false });
  }
}

/**
 * An upstream threat-intelligence provider failed. This is expected and
 * recoverable: the caller degrades to whatever other sources answered.
 */
export class UpstreamError extends AppError {
  readonly provider: string;
  readonly timeout: boolean;

  constructor(provider: string, message: string, options: { timeout?: boolean; cause?: unknown } = {}) {
    super({
      code: options.timeout ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_UNAVAILABLE',
      statusCode: options.timeout ? 504 : 502,
      message,
      cause: options.cause,
    });
    this.provider = provider;
    this.timeout = options.timeout === true;
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}
