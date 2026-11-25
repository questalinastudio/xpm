import { pino, type Logger, type LoggerOptions } from 'pino';
import { scrubSecrets, scrubValue } from '@xpm/privacy';

export type { Logger };

/** Field paths that must never reach application logs. */
export const REDACT_PATHS = [
  'password',
  '*.password',
  'newPassword',
  '*.newPassword',
  'token',
  '*.token',
  'ticket',
  '*.ticket',
  'csrfToken',
  '*.csrfToken',
  'connectionString',
  '*.connectionString',
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
];

/**
 * Pino options that make logging credential-safe: path redaction plus
 * content scrubbing of every message and logged object (known secret values
 * and credential patterns). Use for any logger, including Fastify's.
 */
export function safeLoggerOptions(name?: string): LoggerOptions {
  return {
    ...(name ? { name } : {}),
    level: process.env.LOG_LEVEL ?? 'info',
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    hooks: {
      logMethod(args, method) {
        const scrubbed = args.map((a) => (typeof a === 'string' ? scrubSecrets(a) : scrubValue(a))) as Parameters<typeof method>;
        method.apply(this, scrubbed);
      },
    },
    serializers: {
      err: (err: unknown) => {
        const e = err as { message?: string; name?: string; stack?: string } | undefined;
        return e ? { name: e.name, message: scrubSecrets(String(e.message ?? '')), stack: e.stack ? scrubSecrets(e.stack) : undefined } : e;
      },
    },
  };
}

export function createLogger(name: string, options: LoggerOptions = {}, destination?: NodeJS.WritableStream): Logger {
  return destination ? pino({ ...safeLoggerOptions(name), ...options }, destination) : pino({ ...safeLoggerOptions(name), ...options });
}
