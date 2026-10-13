import type { ErrorRequestHandler, RequestHandler } from 'express';
import type { Logger } from 'pino';
import { AppError, PayloadTooLargeError, ValidationError } from '../utils/errors';
import { newCorrelationId } from '../utils/hash';

interface HttpishError {
  type?: string;
  status?: number;
  statusCode?: number;
  message?: string;
}

function isBodyParserError(error: unknown): error is HttpishError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'type' in error &&
    typeof (error as { type?: unknown }).type === 'string'
  );
}

function toAppError(error: unknown): AppError {
  if (error instanceof AppError) return error;

  if (isBodyParserError(error)) {
    if (error.type === 'entity.too.large') return new PayloadTooLargeError('Request body is too large');
    if (error.type === 'entity.parse.failed') {
      return new ValidationError('Request body is not valid JSON');
    }
  }

  return new AppError({
    code: 'INTERNAL_ERROR',
    statusCode: 500,
    message: 'An unexpected error occurred',
    expose: false,
    cause: error,
  });
}

/**
 * Terminal error handler. Renders the single error envelope used everywhere:
 *
 *   { "error": { code, message, status_code, correlation_id, details? } }
 *
 * `details` is included only when the error is explicitly client-safe.
 */
export function errorHandler(logger: Logger): ErrorRequestHandler {
  return (error, req, res, _next) => {
    const appError = toAppError(error);
    const correlationId = req.requestId ?? newCorrelationId();
    const statusCode = appError.statusCode;

    const logContext = {
      correlationId,
      statusCode,
      code: appError.code,
      method: req.method,
      path: req.originalUrl.split('?')[0] ?? req.originalUrl,
    };
    if (statusCode >= 500) {
      logger.error({ ...logContext, err: error }, 'request failed');
    } else {
      logger.warn(logContext, 'request rejected');
    }

    if (res.headersSent) {
      res.end();
      return;
    }

    res.status(statusCode).json({
      error: {
        code: appError.code,
        message: appError.expose ? appError.message : 'An unexpected error occurred',
        status_code: statusCode,
        correlation_id: correlationId,
        ...(appError.expose && appError.details !== undefined ? { details: appError.details } : {}),
      },
    });
  };
}

export function notFoundHandler(): RequestHandler {
  return (req, _res, next) => {
    next(
      new AppError({
        code: 'NOT_FOUND',
        statusCode: 404,
        message: `No route matches ${req.method} ${req.path}`,
      }),
    );
  };
}
