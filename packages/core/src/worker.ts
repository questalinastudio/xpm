import { setTimeout as delay } from 'node:timers/promises';
import type { Pool, PoolClient } from './db.js';
import type { Logger } from './logger.js';
import {
  claim,
  completeJob,
  failJob,
  releaseJob,
  renewLease,
  StaleLeaseError,
  type Job,
  type Lease,
} from './queue.js';

export interface JobContext<P = unknown> {
  job: Job<P>;
  lease: Lease;
  /** Aborted when the lease is lost, the job is cancelled, or the worker shuts down. */
  signal: AbortSignal;
  log: Logger;
}

export interface HandlerOutcome {
  result?: unknown;
  /** Runs in the same transaction that accepts the result (advance workflow state, enqueue next jobs). */
  commit?: (tx: PoolClient) => Promise<void>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type JobHandler<P = any> = (ctx: JobContext<P>) => Promise<HandlerOutcome | void>;

/** Throw from a handler to fail the job without further retries. */
export class PermanentJobError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PermanentJobError';
  }
}

export interface WorkerOptions {
  pool: Pool;
  workerId: string;
  handlers: Record<string, JobHandler>;
  log: Logger;
  leaseMs?: number;
  pollMs?: number;
  concurrency?: number;
  /** How long graceful shutdown waits for in-flight jobs before releasing them. */
  shutdownGraceMs?: number;
  heartbeatMs?: number;
}

type AbortReason = 'lease_lost' | 'shutdown';

/**
 * Polls the queue, runs handlers, renews leases while they run, and reports
 * results with the lease fence so stale results are rejected by the database.
 */
export class Worker {
  private readonly leaseMs: number;
  private readonly pollMs: number;
  private readonly concurrency: number;
  private readonly shutdownGraceMs: number;
  private readonly heartbeatMs: number;
  private readonly inFlight = new Map<string, { promise: Promise<void>; abort: AbortController }>();
  private running = false;
  private loopPromise: Promise<void> | undefined;
  private wake = new AbortController();
  private heartbeatTimer: NodeJS.Timeout | undefined;

  constructor(private readonly opts: WorkerOptions) {
    this.leaseMs = opts.leaseMs ?? 30_000;
    this.pollMs = opts.pollMs ?? 1_000;
    this.concurrency = opts.concurrency ?? 2;
    this.shutdownGraceMs = opts.shutdownGraceMs ?? 20_000;
    this.heartbeatMs = opts.heartbeatMs ?? 10_000;
  }

  get activeJobs(): number {
    return this.inFlight.size;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    await this.beat(true);
    this.heartbeatTimer = setInterval(() => void this.beat(false), this.heartbeatMs);
    this.loopPromise = this.loop();
  }

  async stop(): Promise<void> {
    if (!this.running) return;
    this.running = false;
    this.wake.abort();
    clearInterval(this.heartbeatTimer);
    await this.loopPromise;

    const pending = [...this.inFlight.values()];
    const graceful = Promise.all(pending.map((p) => p.promise));
    const timedOut = await Promise.race([
      graceful.then(() => false),
      delay(this.shutdownGraceMs).then(() => true),
    ]);
    if (timedOut) {
      for (const p of this.inFlight.values()) p.abort.abort('shutdown' satisfies AbortReason);
      await Promise.all([...this.inFlight.values()].map((p) => p.promise));
    }
    // A clean exit is not a dead worker. Crashes leave the row behind, which
    // correctly shows as stale on the dashboard.
    await this.opts.pool
      .query('DELETE FROM worker_heartbeats WHERE worker_id = $1', [this.opts.workerId])
      .catch((err) => this.opts.log.warn({ err: { message: (err as Error).message } }, 'could not remove heartbeat'));
  }

  private async beat(initial: boolean): Promise<void> {
    try {
      await this.opts.pool.query(
        `INSERT INTO worker_heartbeats (worker_id, started_at, last_seen_at, details)
         VALUES ($1, now(), now(), $2::jsonb)
         ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = now(), details = excluded.details
           ${initial ? ', started_at = now()' : ''}`,
        [this.opts.workerId, JSON.stringify({ activeJobs: this.inFlight.size, types: Object.keys(this.opts.handlers) })],
      );
    } catch (err) {
      this.opts.log.warn({ err: { message: (err as Error).message } }, 'heartbeat failed');
    }
  }

  private async loop(): Promise<void> {
    const types = Object.keys(this.opts.handlers);
    while (this.running) {
      if (this.inFlight.size >= this.concurrency) {
        await Promise.race([...this.inFlight.values()].map((p) => p.promise));
        continue;
      }
      let claimed: Awaited<ReturnType<typeof claim>> = null;
      try {
        claimed = await claim(this.opts.pool, { workerId: this.opts.workerId, leaseMs: this.leaseMs, types });
      } catch (err) {
        this.opts.log.error({ err: { message: (err as Error).message } }, 'claim failed; backing off');
      }
      if (!claimed) {
        await delay(this.pollMs, undefined, { signal: this.wake.signal }).catch(() => {});
        continue;
      }
      const abort = new AbortController();
      const { job, lease } = claimed;
      const promise = this.run(job, lease, abort).finally(() => this.inFlight.delete(job.id));
      this.inFlight.set(job.id, { promise, abort });
    }
  }

  private async run(job: Job, lease: Lease, abort: AbortController): Promise<void> {
    const log = this.opts.log.child({ jobId: job.id, type: job.type, attempt: job.attempts, fence: lease.fence });
    const handler = this.opts.handlers[job.type];
    const renewEvery = Math.max(Math.floor(this.leaseMs / 3), 50);
    const renewer = setInterval(() => {
      renewLease(this.opts.pool, lease, this.leaseMs)
        .then((ok) => {
          if (!ok && !abort.signal.aborted) {
            log.warn('lease lost; aborting handler');
            abort.abort('lease_lost' satisfies AbortReason);
          }
        })
        .catch((err) => log.warn({ err: { message: (err as Error).message } }, 'lease renewal error'));
    }, renewEvery);

    try {
      if (!handler) throw new PermanentJobError(`No handler for job type ${job.type}`);
      log.info('job started');
      const outcome = (await handler({ job, lease, signal: abort.signal, log })) ?? {};
      if (abort.signal.reason === 'lease_lost') {
        log.warn('handler finished after lease loss; result discarded');
        return;
      }
      await completeJob(this.opts.pool, lease, outcome.result ?? null, outcome.commit);
      log.info('job succeeded');
    } catch (err) {
      clearInterval(renewer);
      await this.handleError(err, lease, abort, log);
    } finally {
      clearInterval(renewer);
    }
  }

  private async handleError(err: unknown, lease: Lease, abort: AbortController, log: Logger): Promise<void> {
    if (err instanceof StaleLeaseError) {
      log.warn('result rejected: lease was lost (job reclaimed or cancelled)');
      return;
    }
    const reason = abort.signal.reason as AbortReason | undefined;
    try {
      if (reason === 'lease_lost') {
        log.warn('handler aborted after lease loss');
      } else if (reason === 'shutdown') {
        await releaseJob(this.opts.pool, lease, 'worker shut down before the job finished');
        log.warn('job released on shutdown');
      } else {
        const message = err instanceof Error ? err.message : String(err);
        const job = await failJob(this.opts.pool, lease, message, { retryable: !(err instanceof PermanentJobError) });
        log.warn({ status: job.status, error: message }, job.status === 'queued' ? 'job failed; will retry' : 'job failed');
      }
    } catch (reportErr) {
      if (reportErr instanceof StaleLeaseError) {
        log.warn('failure report rejected: lease was lost');
      } else {
        // The lease will expire and another worker will retry the job.
        log.error({ err: { message: (reportErr as Error).message } }, 'could not record job failure');
      }
    }
  }
}
