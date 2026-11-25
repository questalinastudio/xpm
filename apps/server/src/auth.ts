import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  getDummyHash,
  hashPassword,
  verifyPassword,
  validateNewPassword,
  withTx,
  type Pool,
  type Queryable,
} from '@xpm/core';
import type { ServerConfig } from './config.js';

export const SESSION_COOKIE = '__Host-xpm_session';

export interface SessionInfo {
  idHash: string;
  userId: string;
  username: string;
  csrfToken: string;
  expiresAt: Date;
}

export function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export async function audit(
  db: Queryable,
  actor: string,
  action: string,
  target: string | null = null,
  details: Record<string, unknown> = {},
): Promise<void> {
  await db.query(`INSERT INTO audit_log (actor, action, target, details) VALUES ($1, $2, $3, $4::jsonb)`, [
    actor,
    action,
    target,
    JSON.stringify(details),
  ]);
}

// ---------------------------------------------------------------------------
// Account management (used by the workstation CLI)
// ---------------------------------------------------------------------------

export class AccountError extends Error {}

export async function createAdmin(pool: Pool, rawUsername: string, password: string): Promise<{ id: string }> {
  const username = normalizeUsername(rawUsername);
  if (!/^[a-z0-9._-]{3,64}$/.test(username)) {
    throw new AccountError('Username must be 3-64 characters: lowercase letters, digits, dot, underscore, hyphen');
  }
  const problem = validateNewPassword(password);
  if (problem) throw new AccountError(problem);
  const hash = await hashPassword(password);
  return withTx(pool, async (tx) => {
    const { rows } = await tx.query(
      `INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)
       ON CONFLICT (username) DO NOTHING RETURNING id`,
      [username, hash],
    );
    if (!rows[0]) throw new AccountError(`User ${username} already exists; use reset-password`);
    await audit(tx, 'cli', 'admin.create', username);
    return { id: rows[0].id };
  });
}

/** Sets a new password and revokes every existing session for that user. */
export async function resetPassword(pool: Pool, rawUsername: string, password: string): Promise<{ revokedSessions: number }> {
  const username = normalizeUsername(rawUsername);
  const problem = validateNewPassword(password);
  if (problem) throw new AccountError(problem);
  const hash = await hashPassword(password);
  return withTx(pool, async (tx) => {
    const { rows } = await tx.query(
      `UPDATE admin_users SET password_hash = $2, password_changed_at = now(), disabled_at = NULL
       WHERE username = $1 RETURNING id`,
      [username, hash],
    );
    if (!rows[0]) throw new AccountError(`No user named ${username}`);
    const revoked = await tx.query(
      `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
      [rows[0].id],
    );
    await tx.query(`DELETE FROM login_failures WHERE username = $1`, [username]);
    await audit(tx, 'cli', 'admin.reset_password', username, { revokedSessions: revoked.rowCount });
    return { revokedSessions: revoked.rowCount ?? 0 };
  });
}

export async function listAdmins(db: Queryable): Promise<{ username: string; createdAt: Date; disabled: boolean }[]> {
  const { rows } = await db.query(`SELECT username, created_at, disabled_at FROM admin_users ORDER BY username`);
  return rows.map((r) => ({ username: r.username, createdAt: r.created_at, disabled: r.disabled_at !== null }));
}

// ---------------------------------------------------------------------------
// Login, sessions, logout
// ---------------------------------------------------------------------------

export type LoginResult =
  | { ok: true; token: string; session: SessionInfo }
  | { ok: false; reason: 'invalid' | 'rate_limited' };

export async function login(
  pool: Pool,
  config: ServerConfig,
  rawUsername: string,
  password: string,
  ip: string,
  userAgent: string | undefined,
): Promise<LoginResult> {
  const username = normalizeUsername(rawUsername).slice(0, 128);
  const windowSec = config.loginWindowMs / 1000;
  const { rows: counts } = await pool.query(
    `SELECT
       count(*) FILTER (WHERE username = $1)::int AS by_user,
       count(*) FILTER (WHERE ip = $2)::int AS by_ip
     FROM login_failures
     WHERE at > now() - ($3::double precision * interval '1 second') AND (username = $1 OR ip = $2)`,
    [username, ip, windowSec],
  );
  const c = counts[0]!;
  if (c.by_user >= config.loginMaxFailuresPerUser || c.by_ip >= config.loginMaxFailuresPerIp) {
    await audit(pool, 'anonymous', 'auth.login_rate_limited', username, { ip });
    return { ok: false, reason: 'rate_limited' };
  }

  const { rows } = await pool.query(
    `SELECT id, password_hash FROM admin_users WHERE username = $1 AND disabled_at IS NULL`,
    [username],
  );
  const user = rows[0];
  // Always run one scrypt verification so response time does not reveal whether the user exists.
  const valid = await verifyPassword(password, user ? user.password_hash : await getDummyHash());
  if (!user || !valid) {
    await pool.query(`INSERT INTO login_failures (username, ip) VALUES ($1, $2)`, [username, ip]);
    await pool.query(`DELETE FROM login_failures WHERE at < now() - interval '1 day'`);
    await audit(pool, 'anonymous', 'auth.login_failed', username, { ip });
    return { ok: false, reason: 'invalid' };
  }

  const token = randomBytes(32).toString('base64url');
  const csrfToken = randomBytes(32).toString('base64url');
  const idHash = hashToken(token);
  const { rows: created } = await pool.query(
    `INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at, ip, user_agent)
     VALUES ($1, $2, $3, now() + ($4::double precision * interval '1 millisecond'), $5, $6)
     RETURNING expires_at`,
    [idHash, user.id, csrfToken, config.sessionTtlMs, ip, userAgent?.slice(0, 512) ?? null],
  );
  await pool.query(`DELETE FROM login_failures WHERE username = $1`, [username]);
  await audit(pool, username, 'auth.login', null, { ip });
  return {
    ok: true,
    token,
    session: { idHash, userId: user.id, username, csrfToken, expiresAt: created[0].expires_at },
  };
}

/**
 * Resolve a session token. Enforces absolute expiry, idle timeout,
 * revocation, and disabled accounts. Touches last_seen_at at most once a minute.
 */
export async function getSession(pool: Pool, config: ServerConfig, token: string): Promise<SessionInfo | null> {
  if (!token || token.length > 128) return null;
  const idHash = hashToken(token);
  const { rows } = await pool.query(
    `UPDATE sessions s SET last_seen_at = CASE WHEN s.last_seen_at < now() - interval '1 minute' THEN now() ELSE s.last_seen_at END
     FROM admin_users u
     WHERE s.id_hash = $1 AND u.id = s.user_id
       AND s.revoked_at IS NULL AND u.disabled_at IS NULL
       AND s.expires_at > now()
       AND s.last_seen_at > now() - ($2::double precision * interval '1 millisecond')
     RETURNING s.user_id, u.username, s.csrf_token, s.expires_at`,
    [idHash, config.sessionIdleMs],
  );
  const r = rows[0];
  return r ? { idHash, userId: r.user_id, username: r.username, csrfToken: r.csrf_token, expiresAt: r.expires_at } : null;
}

export async function revokeSession(pool: Pool, idHash: string): Promise<void> {
  await pool.query(`UPDATE sessions SET revoked_at = now() WHERE id_hash = $1 AND revoked_at IS NULL`, [idHash]);
}
