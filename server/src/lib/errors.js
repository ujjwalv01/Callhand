// Error plumbing shared by every route.
//
// The contract: a route that cannot fulfil a request THROWS. It never builds
// an error response itself. One middleware at the bottom of the stack turns
// whatever was thrown into a JSON response, so error shape is identical
// across the whole API and no route can forget to set a status code.

import { ZodError } from 'zod';
import { config } from '../config.js';

/**
 * An error we chose to produce, with an HTTP status attached.
 * Anything else that reaches the handler is treated as a bug -> 500.
 */
export class HttpError extends Error {
  /**
   * @param {number} status  HTTP status code
   * @param {string} message safe to show the client
   * @param {object} [options]
   * @param {string} [options.code]    stable machine-readable string for the client
   * @param {unknown} [options.details] extra context (e.g. field errors)
   * @param {Error}  [options.cause]   the underlying error, kept for logs only
   */
  constructor(status, message, { code, details, cause } = {}) {
    super(message, { cause });
    this.name = 'HttpError';
    this.status = status;
    this.code = code ?? defaultCode(status);
    this.details = details;
  }
}

function defaultCode(status) {
  return {
    400: 'bad_request',
    401: 'unauthorized',
    403: 'forbidden',
    404: 'not_found',
    409: 'conflict',
    422: 'unprocessable',
    429: 'rate_limited',
  }[status] ?? 'internal_error';
}

// Shorthand constructors. Routes read better as `throw notFound('Business not found')`.
export const badRequest   = (msg = 'Bad request', opts)   => new HttpError(400, msg, opts);
export const unauthorized = (msg = 'Unauthorized', opts)  => new HttpError(401, msg, opts);
export const forbidden    = (msg = 'Forbidden', opts)     => new HttpError(403, msg, opts);
export const notFound     = (msg = 'Not found', opts)     => new HttpError(404, msg, opts);
export const conflict     = (msg = 'Conflict', opts)      => new HttpError(409, msg, opts);

/**
 * Express 4 does not catch rejected promises from async handlers: an
 * `await` that throws would hang the request forever instead of responding.
 * Wrapping a handler in this forwards the rejection to next(), which is what
 * the error middleware listens to.
 *
 *   router.get('/x', asyncHandler(async (req, res) => { ... }))
 */
export const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/** Nothing matched the URL. Runs after every route, before the error handler. */
export function notFoundMiddleware(req, _res, next) {
  next(new HttpError(404, `No route for ${req.method} ${req.originalUrl}`, { code: 'route_not_found' }));
}

/**
 * The single place an error becomes a response.
 * Express recognises this as an error handler because it takes FOUR arguments
 * - the `next` parameter must stay even though it is unused.
 */
// eslint-disable-next-line no-unused-vars
export function errorMiddleware(err, req, res, _next) {
  const normalised = normalise(err);

  // 5xx means we broke; log the whole error with its stack. 4xx is the client's
  // problem and is expected traffic, so it stays at debug level.
  if (normalised.status >= 500) {
    req.log?.error({ err, reqId: req.id }, 'request failed');
  } else {
    req.log?.debug({ err: normalised.message, status: normalised.status }, 'request rejected');
  }

  res.status(normalised.status).json({
    error: {
      code: normalised.code,
      // Never leak an internal message (which may contain SQL or file paths)
      // to a client in production.
      message: normalised.status >= 500 && config.isProd ? 'Internal server error' : normalised.message,
      ...(normalised.details !== undefined && { details: normalised.details }),
      requestId: req.id,
    },
  });
}

/** Map known error shapes onto HttpError. Anything unrecognised becomes a 500. */
function normalise(err) {
  if (err instanceof HttpError) return err;

  // A zod schema rejected the request body/query. Report which fields failed.
  if (err instanceof ZodError) {
    return new HttpError(422, 'Validation failed', {
      code: 'validation_failed',
      details: err.issues.map((i) => ({ field: i.path.join('.') || '(root)', message: i.message })),
    });
  }

  // Middleware upstream of us (body-parser, cors) throws errors that already
  // carry an HTTP status and are marked safe to show the client via `expose`.
  // Respect that instead of burying a client mistake as a 500.
  const upstreamStatus = err?.status ?? err?.statusCode;
  if (Number.isInteger(upstreamStatus) && upstreamStatus >= 400 && upstreamStatus < 500) {
    return new HttpError(upstreamStatus, err.expose ? err.message : 'Bad request', {
      code: typeof err.type === 'string' ? err.type.replace(/\./g, '_') : undefined,
      cause: err,
    });
  }

  // node-postgres errors carry a five-character SQLSTATE in err.code.
  switch (err?.code) {
    case '23505': // unique_violation
      return new HttpError(409, 'That record already exists', { code: 'duplicate', cause: err });
    case '23503': // foreign_key_violation
      return new HttpError(409, 'Referenced record does not exist', { code: 'invalid_reference', cause: err });
    case '23514': // check_violation
      return new HttpError(400, 'A value is outside its allowed range', { code: 'check_violation', cause: err });
    case '22P02': // invalid_text_representation, e.g. a malformed uuid in the URL
      return new HttpError(400, 'Malformed identifier', { code: 'malformed_id', cause: err });
    default:
      return new HttpError(500, err?.message ?? 'Internal server error', { cause: err });
  }
}
