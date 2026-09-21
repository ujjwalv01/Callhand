// Server entry point: build the Express app, start listening, shut down cleanly.
//
// Middleware order is the whole story of this file. A request falls through
// the stack top to bottom; a response (or an error) climbs back out.
//
//   request  -> requestId -> logger -> cors -> body parsers -> routes
//                                                                 |
//   response <------------------------ errorMiddleware <- 404 <---+

import { randomUUID } from 'node:crypto';
import express from 'express';
import cors from 'cors';
import pinoHttp from 'pino-http';

import { config } from './config.js';
import { logger } from './lib/logger.js';
import { errorMiddleware, notFoundMiddleware } from './lib/errors.js';
import { ping, closePool } from './db/client.js';

export function createApp() {
  const app = express();

  // Behind a proxy (Render, ngrok) the client IP arrives in X-Forwarded-For.
  // Without this, rate limiting and logs would show the proxy's IP for everyone.
  app.set('trust proxy', 1);
  app.disable('x-powered-by'); // don't advertise the framework

  // 1. Give every request an id, so one call can be traced across many log lines.
  app.use((req, _res, next) => {
    req.id = req.get('x-request-id') ?? randomUUID();
    next();
  });

  // 2. Structured request logging. Attaches a child logger at req.log that
  //    already carries the request id, so routes just call req.log.info(...).
  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => req.id,
      // Health checks fire every few seconds in production; don't drown the log.
      autoLogging: { ignore: (req) => req.url === '/health' },
      customLogLevel: (_req, res, err) => {
        if (err || res.statusCode >= 500) return 'error';
        if (res.statusCode >= 400) return 'warn';
        return 'info';
      },
      serializers: {
        req: (req) => ({ method: req.method, url: req.url }),
        res: (res) => ({ statusCode: res.statusCode }),
      },
    }),
  );

  // 3. CORS. The dashboard runs on a different origin (Vite on :5173), and a
  //    browser will not let it call this API unless we say so explicitly.
  //    Webhooks from Vapi/Twilio are server-to-server and ignore CORS entirely.
  app.use(
    cors({
      origin: config.clientOrigin,
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    }),
  );

  // 4. Body parsing.
  //    `verify` stashes the untouched raw bytes on req.rawBody. Webhook
  //    signatures are computed over the exact bytes sent, so re-serialising
  //    the parsed object would produce a different string and fail validation.
  app.use(
    express.json({
      limit: '1mb',
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    }),
  );
  // Twilio posts application/x-www-form-urlencoded, not JSON.
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));

  // 5. Health check. Hosting platforms poll this to decide if the process is
  //    alive; it also proves the database is reachable, not just Node.
  app.get('/health', async (_req, res) => {
    const startedAt = performance.now();
    let database = 'down';
    try {
      database = (await ping()) ? 'up' : 'down';
    } catch {
      database = 'down';
    }
    const body = {
      status: database === 'up' ? 'ok' : 'degraded',
      env: config.env,
      database,
      latencyMs: Math.round(performance.now() - startedAt),
      uptimeSeconds: Math.round(process.uptime()),
    };
    res.status(body.status === 'ok' ? 200 : 503).json(body);
  });

  // 6. Feature routes get mounted here as we build them (day 2: /api/auth).

  // 7. Nothing matched -> 404, then the single error responder.
  app.use(notFoundMiddleware);
  app.use(errorMiddleware);

  return app;
}

// --- startup ---------------------------------------------------------------
// `import.meta.main` is true only when this file is the entry point, so
// importing createApp() from a test does not start a server.
if (import.meta.main) {
  const app = createApp();
  const server = app.listen(config.port, () => {
    logger.info({ port: config.port, env: config.env, publicBaseUrl: config.publicBaseUrl }, 'callhand server listening');
  });

  // Graceful shutdown. On SIGTERM (a deploy) or SIGINT (Ctrl+C):
  // stop accepting new connections, let in-flight requests finish, close the
  // database pool, then exit. Without this, a deploy can cut off a live call.
  const shutdown = async (signal) => {
    logger.info({ signal }, 'shutting down');
    const force = setTimeout(() => {
      logger.error('forced exit after 10s');
      process.exit(1);
    }, 10_000).unref();

    server.close(async () => {
      await closePool();
      clearTimeout(force);
      logger.info('shutdown complete');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // A bug that escapes every handler should be loud, not silent.
  process.on('unhandledRejection', (reason) => logger.error({ err: reason }, 'unhandled promise rejection'));
  process.on('uncaughtException', (err) => {
    logger.fatal({ err }, 'uncaught exception');
    process.exit(1);
  });
}
