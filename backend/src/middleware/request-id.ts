import type { RequestHandler } from 'express';
import { newCorrelationId } from '../utils/hash';

const SAFE_REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * Attach a correlation id to every request. An inbound `X-Request-ID` is
 * honoured only when it looks safe; otherwise we generate one. The id is
 * echoed on the response and used in every log line and error envelope.
 */
export function requestIdMiddleware(): RequestHandler {
  return (req, res, next) => {
    const incoming = req.header('x-request-id');
    const id = incoming && SAFE_REQUEST_ID.test(incoming) ? incoming : newCorrelationId();
    req.requestId = id;
    res.setHeader('X-Request-ID', id);
    next();
  };
}
