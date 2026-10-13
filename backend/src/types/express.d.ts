/**
 * Express request augmentation.
 *
 * `requestId` carries the correlation id set by the request-id middleware.
 * `validated` holds the parsed output of the Zod validators – Express 5 makes
 * `req.query` a read-only getter, so validated values live here instead.
 */
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      requestId?: string;
      validated?: {
        body?: unknown;
        query?: unknown;
        params?: unknown;
      };
    }
  }
}

export {};
