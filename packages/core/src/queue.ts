import { scrubSecrets } from '@xpm/privacy';
import { withTx, type Pool, type PoolClient, type Queryable } from './db.js';

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
export type AttemptStatus =
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'abandoned'
  | 'stale_rejected'
  | 'cancelled'
  | 'interrupted';

export interface Job<P = unknown> {
  id: string;
  idempotencyKey: string;
  type: string;
  payload: P;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  runAt: Date;
  leaseOwner: string | null;
  leaseExpiresAt: Date | null;
  fence: number;
  lastError: string | null;
  result: unknown;
  createdAt: Date;
  updatedAt: Date;
  completedAt: Date | null;
}

export interface JobAttempt {
  id: number;
  jobId: string;
  attemptNo: number;
  fence: number;
  workerId: string;
  status: AttemptStatus;
  error: string | null;
  startedAt: Date;
  finishedAt: Date | null;
}

/** Proof of a claim. Every state change for a running job must present it. */
export interface Lease {
  jobId: string;
  fence: number;
  workerId: string;
}

/** Raised when a worker reports on a job whose lease it no longer holds. */
export class StaleLeaseError extends Error {
  constructor(lease: Lease) {
    super(`Stale lease for job ${lease.jobId} (fence ${lease.fence}, worker ${lease.workerId}); result rejected`);
    this.name = 'StaleLeaseError';
  }
}

export class IdempotencyConflictError extends Error {
  constructor(key: string, existingType: string, requestedType: string) {
    super(`Idempotency key ${key} already used for job type ${existingType}, not ${requestedType}`);
    this.name = 'IdempotencyConflictError';
  }
}

const MAX_ERROR_LENGTH = 4000;
/** Scrub credentials, then bound the length. Applied to every stored error. */
export function truncateError(message: string): string {
  const clean = scrubSecrets(message);
  return clean.length > MAX_ERROR_LENGTH ? `${clean.slice(0, MAX_ERROR_LENGTH)}…[truncated]` : clean;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function rowToJob(r: any): Job {
  return {
    id: r.id,
    idempotencyKey: r.idempotency_key,
    type: r.type,
    payload: r.payload,
    status: r.status,
    attempts: r.attempts,
    maxAttempts: r.max_attempts,
    runAt: r.run_at,
    leaseOwner: r.lease_owner,
    leaseExpiresAt: r.lease_expires_at,
    fence: r.fence,
    lastError: r.last_error,
    result: r.result,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    completedAt: r.completed_at,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function rowToAttempt(r: any): JobAttempt {
  return {
    id: r.id,
    jobId: r.job_id,
    attemptNo: r.attempt_no,
    fence: r.fence,
    workerId: r.worker_id,
    status: r.status,
    error: r.error,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
  };
}

// ---------------------------------------------------------------------------
// Enqueue
// ---------------------------------------------------------------------------

export interface EnqueueInput {
  /** Logical operation key, e.g. `gmail:{mailbox}:{message}`. Duplicate keys return the existing job. */
  idempotencyKey: string;
  type: string;
  /** References to inputs, not bulky content. */
  payload?: unknown;
  runAt?: Date;
  maxAttempts?: number;
}

/**
 * Insert a job unless one with the same idempotency key exists. Pass a
 * transaction client to enqueue atomically with other state changes.
 */
export async function enqueue(db: Queryable, input: EnqueueInput): Promise<{ job: Job; created: boolean }> {
  const inserted = await db.query(
    `INSERT INTO jobs (idempotency_key, type, payload, run_at, max_attempts)
     VALUES ($1, $2, $3::jsonb, coalesce($4, now()), $5)
     ON CONFLICT (idempotency_key) DO NOTHING
     RETURNING *`,
    [input.idempotencyKey, input.type, JSON.stringify(input.payload ?? {}), input.runAt ?? null, input.maxAttempts ?? 5],
  );
  if (inserted.rows[0]) return { job: rowToJob(inserted.rows[0]), created: true };

  const existing = await db.query('SELECT * FROM jobs WHERE idempotency_key = $1', [input.idempotencyKey]);
  const job = rowToJob(existing.rows[0]);
  if (job.type !== input.type) throw new IdempotencyConflictError(input.idempotencyKey, job.type, input.type);
  return { job, created: false };
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

export interface ClaimOptions {
  workerId: string;
  leaseMs: number;
  /** Restrict to these job types (a worker only claims what it can handle). */
  types?: string[];
}

/**
 * Transactionally claim the next runnable job: a queued job whose run time has
 * arrived, or a running job whose lease expired (its worker is presumed dead).
 * Uses SKIP LOCKED so concurrent workers never claim the same row.
 */
export async function claim(pool: Pool, opts: ClaimOptions): Promise<{ job: Job; lease: Lease } | null> {
  // An expired job on its final attempt is failed rather than claimed; loop so
  // that does not starve other runnable work.
  for (let i = 0; i < 10; i++) {
    const outcome = await withTx(pool, async (tx) => {
      const { rows } = await tx.query(
        `SELECT * FROM jobs
         WHERE ((status = 'queued' AND run_at <= now())
             OR (status = 'running' AND lease_expires_at < now()))
           AND ($1::text[] IS NULL OR type = ANY($1::text[]))
         ORDER BY run_at, created_at
         LIMIT 1
         FOR UPDATE SKIP LOCKED`,
        [opts.types ?? null],
      );
      const row = rows[0];
      if (!row) return { kind: 'none' as const };

      if (row.status === 'running') {
        await tx.query(
          `UPDATE job_attempts SET status = 'abandoned', finished_at = now(),
                  error = 'lease expired before the worker reported a result'
           WHERE job_id = $1 AND fence = $2 AND status = 'running'`,
          [row.id, row.fence],
        );
        if (row.attempts >= row.max_attempts) {
          await tx.query(
            `UPDATE jobs SET status = 'failed', lease_owner = NULL, lease_expires_at = NULL,
                    fence = fence + 1, completed_at = now(), updated_at = now(),
                    last_error = 'lease expired on final attempt'
             WHERE id = $1`,
            [row.id],
          );
          return { kind: 'expired' as const };
        }
      }

      const claimed = await tx.query(
        `UPDATE jobs SET status = 'running', attempts = attempts + 1, fence = fence + 1,
                lease_owner = $2, lease_expires_at = now() + ($3::double precision * interval '1 millisecond'),
                updated_at = now()
         WHERE id = $1
         RETURNING *`,
        [row.id, opts.workerId, opts.leaseMs],
      );
      const job = rowToJob(claimed.rows[0]);
      await tx.query(
        `INSERT INTO job_attempts (job_id, attempt_no, fence, worker_id) VALUES ($1, $2, $3, $4)`,
        [job.id, job.attempts, job.fence, opts.workerId],
      );
      return { kind: 'claimed' as const, job };
    });

    if (outcome.kind === 'none') return null;
    if (outcome.kind === 'claimed') {
      return { job: outcome.job, lease: { jobId: outcome.job.id, fence: outcome.job.fence, workerId: opts.workerId } };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Lease renewal and result reporting (all fenced)
// ---------------------------------------------------------------------------

/** Extend a lease. Returns false if the lease was lost (taken over or cancelled). */
export async function renewLease(db: Queryable, lease: Lease, leaseMs: number): Promise<boolean> {
  const { rowCount } = await db.query(
    `UPDATE jobs SET lease_expires_at = now() + ($4::double precision * interval '1 millisecond'), updated_at = now()
     WHERE id = $1 AND fence = $2 AND lease_owner = $3 AND status = 'running'`,
    [lease.jobId, lease.fence, lease.workerId, leaseMs],
  );
  return rowCount === 1;
}

async function markStale(pool: Pool, lease: Lease): Promise<void> {
  await pool.query(
    `UPDATE job_attempts SET status = 'stale_rejected', finished_at = coalesce(finished_at, now()),
            error = coalesce(error, 'result arrived after the lease was lost')
     WHERE job_id = $1 AND fence = $2 AND status IN ('running', 'abandoned')`,
    [lease.jobId, lease.fence],
  );
}

/**
 * Accept a job result. `commit` runs in the same transaction, so workflow
 * state changes and follow-up jobs are committed atomically with the result,
 * or not at all. Throws StaleLeaseError if the fence no longer matches.
 */
export async function completeJob(
  pool: Pool,
  lease: Lease,
  result: unknown = null,
  commit?: (tx: PoolClient) => Promise<void>,
): Promise<Job> {
  try {
    return await withTx(pool, async (tx) => {
      const { rows } = await tx.query(
        `UPDATE jobs SET status = 'succeeded', result = $3::jsonb, lease_owner = NULL, lease_expires_at = NULL,
                last_error = NULL, completed_at = now(), updated_at = now()
         WHERE id = $1 AND fence = $2 AND status = 'running'
         RETURNING *`,
        [lease.jobId, lease.fence, JSON.stringify(result ?? null)],
      );
      if (!rows[0]) throw new StaleLeaseError(lease);
      if (commit) await commit(tx);
      await tx.query(
        `UPDATE job_attempts SET status = 'succeeded', finished_at = now() WHERE job_id = $1 AND fence = $2`,
        [lease.jobId, lease.fence],
      );
      return rowToJob(rows[0]);
    });
  } catch (err) {
    if (err instanceof StaleLeaseError) await markStale(pool, lease);
    throw err;
  }
}

export interface FailOptions {
  /** False for permanent errors: the job fails without further retries. */
  retryable?: boolean;
  /** Override the computed backoff. */
  retryDelayMs?: number;
}

/** Exponential backoff: 5s, 10s, 20s ... capped at 1 hour. */
export function backoffMs(attempt: number): number {
  return Math.min(5_000 * 2 ** Math.max(0, attempt - 1), 3_600_000);
}

export async function failJob(pool: Pool, lease: Lease, error: string, opts: FailOptions = {}): Promise<Job> {
  const message = truncateError(error);
  try {
    return await withTx(pool, async (tx) => {
      const { rows } = await tx.query(
        `SELECT * FROM jobs WHERE id = $1 AND fence = $2 AND status = 'running' FOR UPDATE`,
        [lease.jobId, lease.fence],
      );
      if (!rows[0]) throw new StaleLeaseError(lease);
      const job = rowToJob(rows[0]);
      const retry = (opts.retryable ?? true) && job.attempts < job.maxAttempts;
      const updated = retry
        ? await tx.query(
            `UPDATE jobs SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL, last_error = $2,
                    run_at = now() + ($3::double precision * interval '1 millisecond'), updated_at = now()
             WHERE id = $1 RETURNING *`,
            [job.id, message, opts.retryDelayMs ?? backoffMs(job.attempts)],
          )
        : await tx.query(
            `UPDATE jobs SET status = 'failed', lease_owner = NULL, lease_expires_at = NULL, last_error = $2,
                    completed_at = now(), updated_at = now()
             WHERE id = $1 RETURNING *`,
            [job.id, message],
          );
      await tx.query(
        `UPDATE job_attempts SET status = 'failed', error = $3, finished_at = now() WHERE job_id = $1 AND fence = $2`,
        [lease.jobId, lease.fence, message],
      );
      return rowToJob(updated.rows[0]);
    });
  } catch (err) {
    if (err instanceof StaleLeaseError) await markStale(pool, lease);
    throw err;
  }
}

/**
 * Give a job back without a result (graceful shutdown). The attempt still
 * counts, so a job that keeps getting interrupted cannot retry forever.
 */
export async function releaseJob(pool: Pool, lease: Lease, reason: string): Promise<boolean> {
  return withTx(pool, async (tx) => {
    const { rowCount } = await tx.query(
      `UPDATE jobs SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL, last_error = $3,
              run_at = now(), updated_at = now()
       WHERE id = $1 AND fence = $2 AND status = 'running'`,
      [lease.jobId, lease.fence, truncateError(reason)],
    );
    if (rowCount !== 1) return false;
    await tx.query(
      `UPDATE job_attempts SET status = 'interrupted', error = $3, finished_at = now() WHERE job_id = $1 AND fence = $2`,
      [lease.jobId, lease.fence, truncateError(reason)],
    );
    return true;
  });
}

// ---------------------------------------------------------------------------
// Owner actions
// ---------------------------------------------------------------------------

/**
 * Cancel a queued or running job. Cancelling a running job bumps the fence so
 * any result the worker later reports is rejected.
 */
export async function cancelJob(pool: Pool, jobId: string, reason = 'cancelled by owner'): Promise<Job | null> {
  return withTx(pool, async (tx) => {
    const { rows } = await tx.query(`SELECT * FROM jobs WHERE id = $1 FOR UPDATE`, [jobId]);
    const row = rows[0];
    if (!row || !['queued', 'running'].includes(row.status)) return null;
    if (row.status === 'running') {
      await tx.query(
        `UPDATE job_attempts SET status = 'cancelled', error = $3, finished_at = now()
         WHERE job_id = $1 AND fence = $2 AND status = 'running'`,
        [jobId, row.fence, reason],
      );
    }
    const updated = await tx.query(
      `UPDATE jobs SET status = 'cancelled', lease_owner = NULL, lease_expires_at = NULL, fence = fence + 1,
              last_error = $2, completed_at = now(), updated_at = now()
       WHERE id = $1 RETURNING *`,
      [jobId, reason],
    );
    return rowToJob(updated.rows[0]);
  });
}

/** Re-queue a failed or cancelled job for one more attempt. Idempotent for repeated clicks. */
export async function retryJob(pool: Pool, jobId: string): Promise<Job | null> {
  const { rows } = await pool.query(
    `UPDATE jobs SET status = 'queued', run_at = now(), max_attempts = greatest(max_attempts, attempts + 1),
            completed_at = NULL, updated_at = now()
     WHERE id = $1 AND status IN ('failed', 'cancelled')
     RETURNING *`,
    [jobId],
  );
  return rows[0] ? rowToJob(rows[0]) : null;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export async function getJob(db: Queryable, jobId: string): Promise<Job | null> {
  const { rows } = await db.query('SELECT * FROM jobs WHERE id = $1', [jobId]);
  return rows[0] ? rowToJob(rows[0]) : null;
}

export async function getAttempts(db: Queryable, jobId: string): Promise<JobAttempt[]> {
  const { rows } = await db.query('SELECT * FROM job_attempts WHERE job_id = $1 ORDER BY fence', [jobId]);
  return rows.map(rowToAttempt);
}

export interface ListJobsOptions {
  status?: JobStatus;
  limit?: number;
  /** Keyset pagination: return jobs created before this job. */
  before?: { createdAt: Date; id: string };
}

export async function listJobs(db: Queryable, opts: ListJobsOptions = {}): Promise<Job[]> {
  const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
  const { rows } = await db.query(
    `SELECT * FROM jobs
     WHERE ($1::text IS NULL OR status = $1)
       AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3::uuid))
     ORDER BY created_at DESC, id DESC
     LIMIT $4`,
    [opts.status ?? null, opts.before?.createdAt ?? null, opts.before?.id ?? null, limit],
  );
  return rows.map(rowToJob);
}

export async function queueCounts(db: Queryable): Promise<Record<JobStatus, number>> {
  const { rows } = await db.query(`SELECT status, count(*)::int AS n FROM jobs GROUP BY status`);
  const counts: Record<JobStatus, number> = { queued: 0, running: 0, succeeded: 0, failed: 0, cancelled: 0 };
  for (const r of rows) counts[r.status as JobStatus] = r.n;
  return counts;
}
