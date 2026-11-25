import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { readSecret } from '@xpm/core';

const bool = z
  .enum(['true', 'false', '1', '0', ''])
  .default('false')
  .transform((v) => v === 'true' || v === '1');

const schema = z.object({
  XPM_LISTEN_HOST: z.string().default('0.0.0.0'),
  XPM_LISTEN_PORT: z.coerce.number().int().positive().default(3000),
  /** Exact browser origin of the dashboard, e.g. https://10.0.0.125. Used for Origin/CSRF checks. */
  XPM_PUBLIC_ORIGIN: z.string().url().transform((u) => new URL(u).origin),
  XPM_SESSION_TTL_HOURS: z.coerce.number().positive().default(12),
  XPM_SESSION_IDLE_MINUTES: z.coerce.number().positive().default(60),
  XPM_LOGIN_MAX_FAILURES_PER_USER: z.coerce.number().int().positive().default(5),
  XPM_LOGIN_MAX_FAILURES_PER_IP: z.coerce.number().int().positive().default(20),
  XPM_LOGIN_WINDOW_MINUTES: z.coerce.number().positive().default(15),
  XPM_SAMPLE_DATA: bool,
  XPM_WEB_DIST: z.string().default(fileURLToPath(new URL('../../web/dist/', import.meta.url))),
  XPM_INTAKE_URL: z.string().url().default('http://intake:4200'),
});

export interface ServerConfig {
  listenHost: string;
  listenPort: number;
  publicOrigin: string;
  sessionTtlMs: number;
  sessionIdleMs: number;
  loginMaxFailuresPerUser: number;
  loginMaxFailuresPerIp: number;
  loginWindowMs: number;
  sampleMode: boolean;
  webDistDir: string;
  /** Internal intake API for manual SMS; the token comes from a secret file. */
  intakeUrl?: string;
  intakeToken?: string;
}

export function loadServerConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const c = schema.parse(env);
  return {
    listenHost: c.XPM_LISTEN_HOST,
    listenPort: c.XPM_LISTEN_PORT,
    publicOrigin: c.XPM_PUBLIC_ORIGIN,
    sessionTtlMs: c.XPM_SESSION_TTL_HOURS * 3_600_000,
    sessionIdleMs: c.XPM_SESSION_IDLE_MINUTES * 60_000,
    loginMaxFailuresPerUser: c.XPM_LOGIN_MAX_FAILURES_PER_USER,
    loginMaxFailuresPerIp: c.XPM_LOGIN_MAX_FAILURES_PER_IP,
    loginWindowMs: c.XPM_LOGIN_WINDOW_MINUTES * 60_000,
    sampleMode: c.XPM_SAMPLE_DATA,
    webDistDir: c.XPM_WEB_DIST,
    intakeUrl: c.XPM_INTAKE_URL,
    intakeToken: readSecret('XPM_INTAKE_SUBMIT_TOKEN', env),
  };
}
