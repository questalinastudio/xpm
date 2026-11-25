import { existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import { z } from 'zod';
import {
  cancelJob,
  enqueue,
  getAttempts,
  getJob,
  listJobs,
  queueCounts,
  REDACT_PATHS,
  retryJob,
  type Job,
  type Pool,
} from '@xpm/core';
import { audit, getSession, login, revokeSession, safeEqual, SESSION_COOKIE, type SessionInfo } from './auth.js';
import type { ServerConfig } from './config.js';

declare module 'fastify' {
  interface FastifyRequest {
    session: SessionInfo | null;
  }
  interface FastifyContextConfig {
    /** Route is reachable without a session (still subject to Origin checks if it mutates). */
    public?: boolean;
  }
}

export interface AppOptions {
  pool: Pool;
  config: ServerConfig;
  logger?: boolean | object;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const WORKER_STALE_MS = 30_000;

function jobView(job: Job) {
  return {
    id: job.id,
    idempotencyKey: job.idempotencyKey,
    type: job.type,
    status: job.status,
    attempts: job.attempts,
    maxAttempts: job.maxAttempts,
    runAt: job.runAt,
    leaseOwner: job.leaseOwner,
    leaseExpiresAt: job.leaseExpiresAt,
    fence: job.fence,
    lastError: job.lastError,
    result: job.result,
    payload: job.payload,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    completedAt: job.completedAt,
  };
}

export async function buildApp({ pool, config, logger = false }: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: logger === true ? { redact: { paths: REDACT_PATHS, censor: '[REDACTED]' } } : logger,
    // Only Caddy can reach this service (it is not published), so trust its X-Forwarded-For.
    trustProxy: true,
    bodyLimit: 256 * 1024,
    genReqId: () => randomUUID(),
  });

  app.decorateRequest('session', null);
  await app.register(cookie);
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    // Browsers ignore HSTS for IP-address hosts; avoid implying protection it does not give.
    strictTransportSecurity: false,
    crossOriginEmbedderPolicy: false,
  });
  await app.register(rateLimit, { max: 600, timeWindow: '1 minute' });

  // -------------------------------------------------------------------------
  // Origin, session, and CSRF enforcement for every /api route
  // -------------------------------------------------------------------------

  const originAllowed = (req: FastifyRequest): boolean => {
    if (req.headers['sec-fetch-site'] === 'cross-site') return false;
    const origin = req.headers.origin;
    if (origin !== undefined) return origin === config.publicOrigin;
    const referer = req.headers.referer;
    return referer !== undefined && (referer === config.publicOrigin || referer.startsWith(`${config.publicOrigin}/`));
  };

  const forbid = (reply: FastifyReply, message: string) => reply.code(403).send({ error: 'forbidden', message });

  app.addHook('preHandler', async (req, reply) => {
    if (!req.url.startsWith('/api/')) return;
    const mutating = !SAFE_METHODS.has(req.method);
    if (mutating && !originAllowed(req)) return forbid(reply, 'Request origin not allowed');

    const token = req.cookies[SESSION_COOKIE];
    req.session = token ? await getSession(pool, config, token) : null;
    if (req.routeOptions.config.public) return;

    if (!req.session) return reply.code(401).send({ error: 'unauthorized' });
    if (mutating) {
      const csrf = req.headers['x-csrf-token'];
      if (typeof csrf !== 'string' || !safeEqual(csrf, req.session.csrfToken)) {
        return forbid(reply, 'Missing or invalid CSRF token');
      }
    }
  });

  app.setErrorHandler((err: { statusCode?: number; message: string }, req, reply) => {
    const status = err.statusCode && err.statusCode >= 400 && err.statusCode < 500 ? err.statusCode : 500;
    if (status === 500) req.log.error({ err: { message: err.message } }, 'request failed');
    reply.code(status).send({ error: status === 500 ? 'internal_error' : 'bad_request', message: status === 500 ? 'Internal error' : err.message });
  });

  // -------------------------------------------------------------------------
  // Health (unauthenticated liveness for container healthchecks only)
  // -------------------------------------------------------------------------

  app.get('/healthz', async () => ({ status: 'ok' }));

  // -------------------------------------------------------------------------
  // Auth
  // -------------------------------------------------------------------------

  const loginBody = z.object({ username: z.string().min(1).max(128), password: z.string().min(1).max(1024) });

  app.post('/api/auth/login', { config: { public: true } }, async (req, reply) => {
    const parsed = loginBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'bad_request', message: 'Username and password required' });
    const result = await login(pool, config, parsed.data.username, parsed.data.password, req.ip, req.headers['user-agent']);
    if (!result.ok) {
      return result.reason === 'rate_limited'
        ? reply.code(429).send({ error: 'rate_limited', message: 'Too many failed attempts. Try again later.' })
        : reply.code(401).send({ error: 'invalid_credentials', message: 'Invalid username or password' });
    }
    if (req.session) await revokeSession(pool, req.session.idHash); // no session fixation
    reply.setCookie(SESSION_COOKIE, result.token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
      maxAge: Math.floor(config.sessionTtlMs / 1000),
    });
    return { username: result.session.username, csrfToken: result.session.csrfToken, expiresAt: result.session.expiresAt };
  });

  app.post('/api/auth/logout', async (req, reply) => {
    await revokeSession(pool, req.session!.idHash);
    await audit(pool, req.session!.username, 'auth.logout');
    reply.clearCookie(SESSION_COOKIE, { path: '/', secure: true, httpOnly: true, sameSite: 'strict' });
    return { ok: true };
  });

  app.get('/api/auth/session', async (req) => ({
    username: req.session!.username,
    csrfToken: req.session!.csrfToken,
    expiresAt: req.session!.expiresAt,
    sampleMode: config.sampleMode,
  }));

  // -------------------------------------------------------------------------
  // System health
  // -------------------------------------------------------------------------

  app.get('/api/system/health', async () => {
    const started = performance.now();
    await pool.query('SELECT 1');
    const dbLatencyMs = Math.round(performance.now() - started);
    const [migration, workers, queue] = await Promise.all([
      pool.query(`SELECT name, applied_at FROM schema_migrations ORDER BY version DESC LIMIT 1`),
      pool.query(`SELECT worker_id, started_at, last_seen_at, details, now() AS db_now FROM worker_heartbeats ORDER BY worker_id`),
      queueCounts(pool),
    ]);
    return {
      database: { ok: true, latencyMs: dbLatencyMs },
      migration: migration.rows[0] ? { name: migration.rows[0].name, appliedAt: migration.rows[0].applied_at } : null,
      workers: workers.rows.map((w) => ({
        workerId: w.worker_id,
        startedAt: w.started_at,
        lastSeenAt: w.last_seen_at,
        healthy: w.db_now.getTime() - w.last_seen_at.getTime() < WORKER_STALE_MS,
        activeJobs: w.details.activeJobs ?? 0,
      })),
      queue,
      sampleMode: config.sampleMode,
      serverTime: new Date(),
    };
  });

  // -------------------------------------------------------------------------
  // Jobs
  // -------------------------------------------------------------------------

  const jobsQuery = z.object({
    status: z.enum(['queued', 'running', 'succeeded', 'failed', 'cancelled']).optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
    beforeCreatedAt: z.coerce.date().optional(),
    beforeId: z.string().uuid().optional(),
  });
  const idParam = z.object({ id: z.string().uuid() });

  app.get('/api/jobs', async (req, reply) => {
    const q = jobsQuery.safeParse(req.query);
    if (!q.success) return reply.code(400).send({ error: 'bad_request', message: 'Invalid query' });
    const before = q.data.beforeCreatedAt && q.data.beforeId ? { createdAt: q.data.beforeCreatedAt, id: q.data.beforeId } : undefined;
    const jobs = await listJobs(pool, { status: q.data.status, limit: q.data.limit + 1, before });
    const page = jobs.slice(0, q.data.limit);
    const last = page.at(-1);
    return {
      jobs: page.map(jobView),
      next: jobs.length > q.data.limit && last ? { beforeCreatedAt: last.createdAt, beforeId: last.id } : null,
    };
  });

  app.get('/api/jobs/:id', async (req, reply) => {
    const p = idParam.safeParse(req.params);
    if (!p.success) return reply.code(404).send({ error: 'not_found' });
    const job = await getJob(pool, p.data.id);
    if (!job) return reply.code(404).send({ error: 'not_found' });
    return { job: jobView(job), attempts: await getAttempts(pool, job.id) };
  });

  app.post('/api/jobs/:id/cancel', async (req, reply) => {
    const p = idParam.safeParse(req.params);
    if (!p.success) return reply.code(404).send({ error: 'not_found' });
    const job = await cancelJob(pool, p.data.id, `cancelled by ${req.session!.username}`);
    if (!job) return reply.code(409).send({ error: 'conflict', message: 'Job is not queued or running' });
    await audit(pool, req.session!.username, 'job.cancel', job.id);
    return { job: jobView(job) };
  });

  app.post('/api/jobs/:id/retry', async (req, reply) => {
    const p = idParam.safeParse(req.params);
    if (!p.success) return reply.code(404).send({ error: 'not_found' });
    const job = await retryJob(pool, p.data.id);
    if (!job) return reply.code(409).send({ error: 'conflict', message: 'Job is not failed or cancelled' });
    await audit(pool, req.session!.username, 'job.retry', job.id);
    return { job: jobView(job) };
  });

  // -------------------------------------------------------------------------
  // Cases
  // -------------------------------------------------------------------------

  app.get('/api/cases', async () => {
    const { rows } = await pool.query(
      `SELECT id, reference, title, kind, status, summary, is_sample, created_at, updated_at
       FROM cases ORDER BY created_at DESC LIMIT 100`,
    );
    return {
      cases: rows.map((r) => ({
        id: r.id,
        reference: r.reference,
        title: r.title,
        kind: r.kind,
        status: r.status,
        summary: r.summary,
        isSample: r.is_sample,
        createdAt: r.created_at,
        updatedAt: r.updated_at,
      })),
    };
  });

  // -------------------------------------------------------------------------
  // Sample-data mode: demo jobs that exercise the queue end to end
  // -------------------------------------------------------------------------

  if (config.sampleMode) {
    const demoBody = z.object({
      kind: z.enum(['echo', 'sleep', 'fail', 'fail_permanent']),
      key: z.string().regex(/^[A-Za-z0-9:_-]{1,100}$/).optional(),
      seconds: z.number().int().min(1).max(600).optional(),
    });
    app.post('/api/demo/jobs', async (req, reply) => {
      const b = demoBody.safeParse(req.body);
      if (!b.success) return reply.code(400).send({ error: 'bad_request', message: 'Invalid demo job' });
      const { job, created } = await enqueue(pool, {
        idempotencyKey: `demo:${b.data.key ?? randomUUID()}`,
        type: `demo.${b.data.kind}`,
        payload: { seconds: b.data.seconds ?? 5, requestedBy: req.session!.username },
        maxAttempts: b.data.kind === 'fail' ? 3 : 5,
      });
      if (created) await audit(pool, req.session!.username, 'demo.enqueue', job.id, { kind: b.data.kind });
      return reply.code(created ? 201 : 200).send({ job: jobView(job), created });
    });
  }

  // -------------------------------------------------------------------------
  // Dashboard (static SPA)
  // -------------------------------------------------------------------------

  const hasWeb = existsSync(`${config.webDistDir}/index.html`);
  if (hasWeb) {
    await app.register(fastifyStatic, { root: config.webDistDir, wildcard: false, index: ['index.html'] });
  }
  app.setNotFoundHandler((req, reply) => {
    if (hasWeb && req.method === 'GET' && !req.url.startsWith('/api/')) return reply.sendFile('index.html');
    return reply.code(404).send({ error: 'not_found' });
  });

  return app;
}
