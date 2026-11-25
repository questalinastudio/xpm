import { pino, type Logger, type LoggerOptions } from 'pino';

export type { Logger };

/**
 * Paths that must never reach application logs. M2 extends this with
 * content-level redaction; this is the credential-safe baseline.
 */
export const REDACT_PATHS = [
  'password',
  '*.password',
  'newPassword',
  '*.newPassword',
  'token',
  '*.token',
  'csrfToken',
  '*.csrfToken',
  'connectionString',
  '*.connectionString',
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
];

export function createLogger(name: string, options: LoggerOptions = {}): Logger {
  return pino({
    name,
    level: process.env.LOG_LEVEL ?? 'info',
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    ...options,
  });
}
