import { createContainer, disposeContainer } from './container';
import { createApp } from './app';
import { getEnv } from './config/env';
import { getLogger } from './utils/logger';

const logger = getLogger();

/** How long in-flight requests may settle before we force-exit. */
const SHUTDOWN_GRACE_MS = 10_000;

/**
 * Backend entrypoint.
 *
 * Starts the HTTP server, wires graceful shutdown (SIGINT/SIGTERM/SIGHUP) and
 * fails loudly at boot instead of half-starting with a broken database or
 * missing production credentials.
 */
async function start(): Promise<void> {
  const env = getEnv();
  const container = await createContainer();

  const app = createApp(container);
  const server = app.listen(env.PORT, env.HOST, () => {
    logger.info(
      { host: env.HOST, port: env.PORT, nodeEnv: env.NODE_ENV },
      'Mobile ThreatGuard backend listening',
    );
  });

  // Keep-alive sockets would otherwise hold `server.close()` open forever.
  server.keepAliveTimeout = 5_000;
  server.headersTimeout = 6_000;

  let draining = false;
  const shutdown = (signal: string): void => {
    if (draining) return;
    draining = true;
    logger.info({ signal }, 'shutting down');

    const forceExit = setTimeout(() => {
      logger.error({ signal }, 'graceful shutdown timed out; forcing exit');
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    forceExit.unref();

    server.close((closeError) => {
      void (async () => {
        if (closeError) logger.warn({ err: closeError }, 'error closing HTTP server');
        await disposeContainer(container);
        logger.info('shutdown complete');
        process.exit(closeError ? 1 : 0);
      })();
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGHUP', () => shutdown('SIGHUP'));

  // A stray async failure must surface rather than leaving the process in an
  // unknown state.
  process.on('unhandledRejection', (reason) => {
    logger.error({ err: reason }, 'unhandled promise rejection');
  });
  process.on('uncaughtException', (error) => {
    logger.error({ err: error }, 'uncaught exception');
    process.exit(1);
  });
}

start().catch((error) => {
  logger.error({ err: error }, 'fatal: backend failed to start');
  process.exit(1);
});