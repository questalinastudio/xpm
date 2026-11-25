import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { enqueue } from '@xpm/core';
import { startTestDb, type TestDb } from '../../../packages/core/test/helpers.js';
import { buildApp } from '../src/app.js';
import { createAdmin, resetPassword, SESSION_COOKIE } from '../src/auth.js';
import type { ServerConfig } from '../src/config.js';

const ORIGIN = 'https://10.0.0.125';
const PASSWORD = 'a long test password';

let db: TestDb;
let app: FastifyInstance;
const config: ServerConfig = {
  listenHost: '127.0.0.1',
  listenPort: 0,
  publicOrigin: ORIGIN,
  sessionTtlMs: 12 * 3_600_000,
  sessionIdleMs: 60 * 60_000,
  loginMaxFailuresPerUser: 5,
  loginMaxFailuresPerIp: 20,
  loginWindowMs: 15 * 60_000,
  sampleMode: true,
  webDistDir: '/nonexistent',
};

beforeAll(async () => {
  db = await startTestDb();
  await createAdmin(db.pool, 'owner', PASSWORD);
  app = await buildApp({ pool: db.pool, config });
});
afterAll(async () => {
  await app?.close();
  await db?.stop();
});
beforeEach(async () => {
  await db.pool.query('DELETE FROM login_failures');
});

function sessionCookie(res: LightMyRequestResponse): string {
  const c = res.cookies.find((x) => x.name === SESSION_COOKIE);
  if (!c) throw new Error('no session cookie');
  return c.value;
}

async function loginAs(username = 'owner', password = PASSWORD, headers: Record<string, string> = { origin: ORIGIN }) {
  return app.inject({ method: 'POST', url: '/api/auth/login', headers, payload: { username, password } });
}

async function authed() {
  const res = await loginAs();
  expect(res.statusCode).toBe(200);
  return { token: sessionCookie(res), csrf: res.json().csrfToken as string };
}

describe('login', () => {
  it('sets a secure, HTTP-only, SameSite=Strict session cookie', async () => {
    const res = await loginAs();
    expect(res.statusCode).toBe(200);
    const c = res.cookies.find((x) => x.name === SESSION_COOKIE)!;
    expect(c.httpOnly).toBe(true);
    expect(c.secure).toBe(true);
    expect(c.sameSite).toBe('Strict');
    expect(c.path).toBe('/');
    expect(c.value.length).toBeGreaterThanOrEqual(43);
    // Only the hash is stored server-side.
    const { rows } = await db.pool.query(`SELECT id_hash FROM sessions`);
    expect(rows.map((r) => r.id_hash)).not.toContain(c.value);
  });

  it('rejects a wrong password and an unknown user with the same response', async () => {
    const wrong = await loginAs('owner', 'not the password');
    const unknown = await loginAs('nobody', 'not the password');
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(wrong.json()).toEqual(unknown.json());
  });

  it('accepts usernames case-insensitively', async () => {
    expect((await loginAs('OWNER')).statusCode).toBe(200);
  });

  it('rate-limits repeated failures, even for the correct password, persistently', async () => {
    for (let i = 0; i < 5; i++) expect((await loginAs('owner', 'wrong password')).statusCode).toBe(401);
    const blocked = await loginAs('owner', PASSWORD);
    expect(blocked.statusCode).toBe(429);
    expect(blocked.cookies.find((c) => c.name === SESSION_COOKIE)).toBeUndefined();
    const { rows } = await db.pool.query(`SELECT count(*)::int AS n FROM login_failures WHERE username = 'owner'`);
    expect(rows[0].n).toBe(5);
  });

  it('rejects a cross-origin login attempt', async () => {
    expect((await loginAs('owner', PASSWORD, { origin: 'https://evil.example' })).statusCode).toBe(403);
    expect((await loginAs('owner', PASSWORD, {})).statusCode).toBe(403);
  });
});

describe('unauthorized access', () => {
  it('requires a session for every API route', async () => {
    for (const url of ['/api/auth/session', '/api/system/health', '/api/jobs', '/api/cases']) {
      expect((await app.inject({ method: 'GET', url })).statusCode).toBe(401);
    }
  });

  it('rejects a forged or random session cookie', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/jobs', cookies: { [SESSION_COOKIE]: 'forged-token-value' } });
    expect(res.statusCode).toBe(401);
  });

  it('allows the unauthenticated liveness probe only', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });
});

describe('forged-action rejection (CSRF)', () => {
  it('rejects state-changing requests without a CSRF token', async () => {
    const { token } = await authed();
    const res = await app.inject({
      method: 'POST',
      url: '/api/demo/jobs',
      headers: { origin: ORIGIN },
      cookies: { [SESSION_COOKIE]: token },
      payload: { kind: 'echo' },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a wrong CSRF token or a token from another session', async () => {
    const a = await authed();
    const b = await authed();
    for (const csrf of ['wrong', b.csrf]) {
      const res = await app.inject({
        method: 'POST',
        url: '/api/demo/jobs',
        headers: { origin: ORIGIN, 'x-csrf-token': csrf },
        cookies: { [SESSION_COOKIE]: a.token },
        payload: { kind: 'echo' },
      });
      expect(res.statusCode).toBe(403);
    }
  });

  it('rejects cross-site requests even with a valid token', async () => {
    const { token, csrf } = await authed();
    for (const headers of [
      { origin: 'https://evil.example', 'x-csrf-token': csrf },
      { 'x-csrf-token': csrf }, // no Origin or Referer
      { origin: ORIGIN, 'x-csrf-token': csrf, 'sec-fetch-site': 'cross-site' },
    ]) {
      const res = await app.inject({
        method: 'POST',
        url: '/api/demo/jobs',
        headers,
        cookies: { [SESSION_COOKIE]: token },
        payload: { kind: 'echo' },
      });
      expect(res.statusCode).toBe(403);
    }
  });

  it('accepts a same-origin request with the session’s CSRF token, idempotently', async () => {
    const { token, csrf } = await authed();
    const send = () =>
      app.inject({
        method: 'POST',
        url: '/api/demo/jobs',
        headers: { origin: ORIGIN, 'x-csrf-token': csrf },
        cookies: { [SESSION_COOKIE]: token },
        payload: { kind: 'echo', key: 'double-click' },
      });
    const first = await send();
    const second = await send();
    expect(first.statusCode).toBe(201);
    expect(second.statusCode).toBe(200);
    expect(second.json().job.id).toBe(first.json().job.id);
  });
});

describe('logout and expiration', () => {
  it('logout revokes the session server-side', async () => {
    const { token, csrf } = await authed();
    const out = await app.inject({
      method: 'POST',
      url: '/api/auth/logout',
      headers: { origin: ORIGIN, 'x-csrf-token': csrf },
      cookies: { [SESSION_COOKIE]: token },
    });
    expect(out.statusCode).toBe(200);
    expect(out.cookies.find((c) => c.name === SESSION_COOKIE)?.value).toBe('');
    // Replaying the old cookie no longer works.
    expect((await app.inject({ method: 'GET', url: '/api/jobs', cookies: { [SESSION_COOKIE]: token } })).statusCode).toBe(401);
  });

  it('expires sessions at their absolute lifetime', async () => {
    const { token } = await authed();
    await db.pool.query(`UPDATE sessions SET expires_at = now() - interval '1 second'`);
    expect((await app.inject({ method: 'GET', url: '/api/jobs', cookies: { [SESSION_COOKIE]: token } })).statusCode).toBe(401);
  });

  it('expires idle sessions', async () => {
    const { token } = await authed();
    expect((await app.inject({ method: 'GET', url: '/api/jobs', cookies: { [SESSION_COOKIE]: token } })).statusCode).toBe(200);
    await db.pool.query(`UPDATE sessions SET last_seen_at = now() - interval '61 minutes'`);
    expect((await app.inject({ method: 'GET', url: '/api/jobs', cookies: { [SESSION_COOKIE]: token } })).statusCode).toBe(401);
  });

  it('workstation password reset revokes all existing sessions', async () => {
    const { token } = await authed();
    const r = await resetPassword(db.pool, 'owner', 'another long password');
    expect(r.revokedSessions).toBeGreaterThanOrEqual(1);
    expect((await app.inject({ method: 'GET', url: '/api/jobs', cookies: { [SESSION_COOKIE]: token } })).statusCode).toBe(401);
    expect((await loginAs('owner', PASSWORD)).statusCode).toBe(401);
    expect((await loginAs('owner', 'another long password')).statusCode).toBe(200);
    await resetPassword(db.pool, 'owner', PASSWORD);
  });
});

describe('job API', () => {
  it('lists jobs with keyset pagination and shows attempts', async () => {
    const { token } = await authed();
    for (let i = 0; i < 5; i++) await enqueue(db.pool, { idempotencyKey: `page:${i}`, type: 'demo.echo' });
    const get = (url: string) => app.inject({ method: 'GET', url, cookies: { [SESSION_COOKIE]: token } });
    const p1 = (await get('/api/jobs?limit=3')).json();
    expect(p1.jobs).toHaveLength(3);
    const p2 = (
      await get(`/api/jobs?limit=3&beforeCreatedAt=${encodeURIComponent(p1.next.beforeCreatedAt)}&beforeId=${p1.next.beforeId}`)
    ).json();
    const ids = new Set([...p1.jobs, ...p2.jobs].map((j: { id: string }) => j.id));
    expect(ids.size).toBe(p1.jobs.length + p2.jobs.length);
    const detail = (await get(`/api/jobs/${p1.jobs[0].id}`)).json();
    expect(detail.job.id).toBe(p1.jobs[0].id);
    expect(Array.isArray(detail.attempts)).toBe(true);
  });

  it('records owner actions in the audit log', async () => {
    const { rows } = await db.pool.query(`SELECT DISTINCT action FROM audit_log`);
    const actions = rows.map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(['admin.create', 'auth.login', 'auth.login_failed', 'auth.logout']));
  });
});
