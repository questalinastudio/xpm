import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { pino } from 'pino';
import {
  cancelJob,
  claim,
  completeJob,
  enqueue,
  failJob,
  getAttempts,
  getJob,
  IdempotencyConflictError,
  PermanentJobError,
  releaseJob,
  renewLease,
  retryJob,
  StaleLeaseError,
  Worker,
  type JobHandler,
} from '../src/index.js';
import { resetQueue, sleep, startTestDb, waitFor, type TestDb } from './helpers.js';

let db: TestDb;
const log = pino({ level: 'silent' });

beforeAll(async () => {
  db = await startTestDb();
});
afterAll(async () => {
  await db?.stop();
});
beforeEach(async () => {
  await resetQueue(db.pool);
});

describe('idempotent enqueue', () => {
  it('returns the existing job for a duplicate key', async () => {
    const a = await enqueue(db.pool, { idempotencyKey: 'gmail:inbox:m1', type: 'import', payload: { id: 'm1' } });
    const b = await enqueue(db.pool, { idempotencyKey: 'gmail:inbox:m1', type: 'import', payload: { id: 'm1' } });
    expect(a.created).toBe(true);
    expect(b.created).toBe(false);
    expect(b.job.id).toBe(a.job.id);
  });

  it('creates exactly one job under concurrent duplicate enqueues', async () => {
    const pools = Array.from({ length: 5 }, () => db.newPool());
    const results = await Promise.all(
      Array.from({ length: 40 }, (_, i) =>
        enqueue(pools[i % pools.length]!, { idempotencyKey: 'send:approval-1', type: 'send' }),
      ),
    );
    expect(results.filter((r) => r.created)).toHaveLength(1);
    expect(new Set(results.map((r) => r.job.id)).size).toBe(1);
    const { rows } = await db.pool.query(`SELECT count(*)::int AS n FROM jobs`);
    expect(rows[0].n).toBe(1);
  });

  it('rejects reuse of a key for a different job type', async () => {
    await enqueue(db.pool, { idempotencyKey: 'k', type: 'a' });
    await expect(enqueue(db.pool, { idempotencyKey: 'k', type: 'b' })).rejects.toBeInstanceOf(IdempotencyConflictError);
  });
});

describe('concurrent claims', () => {
  it('never gives the same job to two workers', async () => {
    const N = 60;
    for (let i = 0; i < N; i++) await enqueue(db.pool, { idempotencyKey: `job:${i}`, type: 't' });
    const workers = Array.from({ length: 8 }, (_, i) => ({ id: `w${i}`, pool: db.newPool() }));
    const claimedBy = new Map<string, string[]>();

    await Promise.all(
      workers.map(async (w) => {
        for (;;) {
          const c = await claim(w.pool, { workerId: w.id, leaseMs: 60_000 });
          if (!c) return;
          claimedBy.set(c.job.id, [...(claimedBy.get(c.job.id) ?? []), w.id]);
        }
      }),
    );

    expect(claimedBy.size).toBe(N);
    for (const owners of claimedBy.values()) expect(owners).toHaveLength(1);
  });

  it('does not claim jobs scheduled in the future or of other types', async () => {
    await enqueue(db.pool, { idempotencyKey: 'later', type: 't', runAt: new Date(Date.now() + 60_000) });
    await enqueue(db.pool, { idempotencyKey: 'other', type: 'other' });
    expect(await claim(db.pool, { workerId: 'w', leaseMs: 1000, types: ['t'] })).toBeNull();
  });
});

describe('leases and fencing', () => {
  it('recovers an abandoned job and rejects the stale worker’s late result', async () => {
    const { job } = await enqueue(db.pool, { idempotencyKey: 'turn:d1:1:1:pm', type: 't' });
    const first = await claim(db.pool, { workerId: 'crashed', leaseMs: 100 });
    expect(first?.lease.fence).toBe(1);

    expect(await claim(db.pool, { workerId: 'healthy', leaseMs: 60_000 })).toBeNull(); // lease still valid
    await sleep(150);
    const second = await claim(db.pool, { workerId: 'healthy', leaseMs: 60_000 });
    expect(second?.job.id).toBe(job.id);
    expect(second?.lease.fence).toBe(2);

    // The "crashed" worker comes back and tries to report.
    await expect(completeJob(db.pool, first!.lease, { from: 'stale' })).rejects.toBeInstanceOf(StaleLeaseError);
    await expect(failJob(db.pool, first!.lease, 'late error')).rejects.toBeInstanceOf(StaleLeaseError);
    expect(await renewLease(db.pool, first!.lease, 60_000)).toBe(false);

    await completeJob(db.pool, second!.lease, { from: 'healthy' });
    const final = await getJob(db.pool, job.id);
    expect(final?.status).toBe('succeeded');
    expect(final?.result).toEqual({ from: 'healthy' });
    expect(final?.attempts).toBe(2);

    const attempts = await getAttempts(db.pool, job.id);
    expect(attempts.map((a) => [a.workerId, a.status])).toEqual([
      ['crashed', 'stale_rejected'],
      ['healthy', 'succeeded'],
    ]);
  });

  it('allows exactly one accepted result per job even when both reports race', async () => {
    await enqueue(db.pool, { idempotencyKey: 'race', type: 't' });
    const c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    const results = await Promise.allSettled([
      completeJob(db.newPool(), c!.lease, 1),
      completeJob(db.newPool(), c!.lease, 2),
      completeJob(db.newPool(), c!.lease, 3),
    ]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('renewal keeps a long job from being taken over', async () => {
    await enqueue(db.pool, { idempotencyKey: 'long', type: 't' });
    const c = await claim(db.pool, { workerId: 'w1', leaseMs: 150 });
    for (let i = 0; i < 4; i++) {
      await sleep(80);
      expect(await renewLease(db.pool, c!.lease, 150)).toBe(true);
      expect(await claim(db.pool, { workerId: 'w2', leaseMs: 150 })).toBeNull();
    }
  });

  it('fails a job whose lease expires on the final attempt instead of re-running it', async () => {
    const { job } = await enqueue(db.pool, { idempotencyKey: 'once', type: 't', maxAttempts: 1 });
    const c = await claim(db.pool, { workerId: 'w1', leaseMs: 50 });
    await sleep(100);
    expect(await claim(db.pool, { workerId: 'w2', leaseMs: 1000 })).toBeNull();
    const final = await getJob(db.pool, job.id);
    expect(final?.status).toBe('failed');
    await expect(completeJob(db.pool, c!.lease)).rejects.toBeInstanceOf(StaleLeaseError);
  });

  it('cancelling a running job fences out its worker', async () => {
    const { job } = await enqueue(db.pool, { idempotencyKey: 'cancel-me', type: 't' });
    const c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    expect((await cancelJob(db.pool, job.id))?.status).toBe('cancelled');
    await expect(completeJob(db.pool, c!.lease)).rejects.toBeInstanceOf(StaleLeaseError);
    expect((await getJob(db.pool, job.id))?.status).toBe('cancelled');
    expect((await getAttempts(db.pool, job.id))[0]?.status).toBe('cancelled');
  });
});

describe('retries', () => {
  it('re-queues retryable failures with backoff, then fails after max attempts', async () => {
    const { job } = await enqueue(db.pool, { idempotencyKey: 'flaky', type: 't', maxAttempts: 2 });
    let c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    const afterFirst = await failJob(db.pool, c!.lease, 'timeout');
    expect(afterFirst.status).toBe('queued');
    expect(afterFirst.runAt.getTime()).toBeGreaterThan(Date.now() + 3_000);
    expect(await claim(db.pool, { workerId: 'w', leaseMs: 60_000 })).toBeNull(); // backoff not elapsed

    await db.pool.query(`UPDATE jobs SET run_at = now() WHERE id = $1`, [job.id]);
    c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    const afterSecond = await failJob(db.pool, c!.lease, 'timeout again');
    expect(afterSecond.status).toBe('failed');
    expect(afterSecond.lastError).toBe('timeout again');
    expect((await getAttempts(db.pool, job.id)).map((a) => a.status)).toEqual(['failed', 'failed']);
  });

  it('fails permanently without retry when told to', async () => {
    await enqueue(db.pool, { idempotencyKey: 'bad-input', type: 't' });
    const c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    expect((await failJob(db.pool, c!.lease, 'invalid', { retryable: false })).status).toBe('failed');
  });

  it('manual retry is idempotent across repeated clicks', async () => {
    const { job } = await enqueue(db.pool, { idempotencyKey: 'manual', type: 't', maxAttempts: 1 });
    const c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    await failJob(db.pool, c!.lease, 'boom');
    const clicks = await Promise.all([retryJob(db.pool, job.id), retryJob(db.pool, job.id), retryJob(db.pool, job.id)]);
    expect(clicks.filter(Boolean)).toHaveLength(1);
    const again = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    expect(again?.job.attempts).toBe(2);
    expect(await claim(db.pool, { workerId: 'w', leaseMs: 60_000 })).toBeNull();
  });

  it('release on shutdown re-queues immediately and records an interrupted attempt', async () => {
    const { job } = await enqueue(db.pool, { idempotencyKey: 'shutdown', type: 't' });
    const c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    expect(await releaseJob(db.pool, c!.lease, 'SIGTERM')).toBe(true);
    expect((await getJob(db.pool, job.id))?.status).toBe('queued');
    expect((await getAttempts(db.pool, job.id))[0]?.status).toBe('interrupted');
  });
});

describe('atomic completion', () => {
  it('commits the result, workflow change and follow-up job together', async () => {
    await enqueue(db.pool, { idempotencyKey: 'turn:d1:1:1:pm', type: 'turn' });
    const c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    await completeJob(db.pool, c!.lease, { accepted: true }, async (tx) => {
      await enqueue(tx, { idempotencyKey: 'turn:d1:1:1:dev', type: 'turn' });
    });
    const { rows } = await db.pool.query(`SELECT idempotency_key, status FROM jobs ORDER BY created_at`);
    expect(rows).toEqual([
      { idempotency_key: 'turn:d1:1:1:pm', status: 'succeeded' },
      { idempotency_key: 'turn:d1:1:1:dev', status: 'queued' },
    ]);
  });

  it('rolls back everything if the commit step fails', async () => {
    const { job } = await enqueue(db.pool, { idempotencyKey: 'turn:d2:1:1:pm', type: 'turn' });
    const c = await claim(db.pool, { workerId: 'w', leaseMs: 60_000 });
    await expect(
      completeJob(db.pool, c!.lease, { accepted: true }, async (tx) => {
        await enqueue(tx, { idempotencyKey: 'turn:d2:1:1:dev', type: 'turn' });
        throw new Error('state transition invalid');
      }),
    ).rejects.toThrow('state transition invalid');
    expect((await getJob(db.pool, job.id))?.status).toBe('running');
    const { rows } = await db.pool.query(`SELECT count(*)::int AS n FROM jobs`);
    expect(rows[0].n).toBe(1);
  });
});

describe('Worker runtime', () => {
  it('runs jobs, renews leases for slow handlers, and records results', async () => {
    const handlers: Record<string, JobHandler> = {
      slow: async ({ signal }) => {
        await sleep(500);
        if (signal.aborted) throw new Error('aborted');
        return { result: 'done' };
      },
    };
    const w1 = new Worker({ pool: db.newPool(), workerId: 'w1', handlers, log, leaseMs: 150, pollMs: 20 });
    const w2 = new Worker({ pool: db.newPool(), workerId: 'w2', handlers, log, leaseMs: 150, pollMs: 20 });
    const { job } = await enqueue(db.pool, { idempotencyKey: 'slow-1', type: 'slow' });
    await w1.start();
    await waitFor(async () => (await getJob(db.pool, job.id))?.status === 'running');
    await w2.start();
    const done = await waitFor(async () => {
      const j = await getJob(db.pool, job.id);
      return j?.status === 'succeeded' ? j : null;
    });
    await Promise.all([w1.stop(), w2.stop()]);
    expect(done.attempts).toBe(1); // w2 never took it over
    expect(done.result).toBe('done');
  });

  it('retries a retryable handler error and stops on a permanent one', async () => {
    let calls = 0;
    const handlers: Record<string, JobHandler> = {
      flaky: async () => {
        calls++;
        if (calls === 1) throw new Error('transient');
        return { result: calls };
      },
      broken: async () => {
        throw new PermanentJobError('cannot ever work');
      },
    };
    const w = new Worker({ pool: db.newPool(), workerId: 'w', handlers, log, pollMs: 20 });
    const flaky = await enqueue(db.pool, { idempotencyKey: 'flaky', type: 'flaky' });
    const broken = await enqueue(db.pool, { idempotencyKey: 'broken', type: 'broken' });
    await w.start();
    await waitFor(async () => (await getJob(db.pool, flaky.job.id))?.status === 'queued' && (await getJob(db.pool, broken.job.id))?.status === 'failed');
    await db.pool.query(`UPDATE jobs SET run_at = now() WHERE id = $1`, [flaky.job.id]); // skip backoff
    const done = await waitFor(async () => {
      const j = await getJob(db.pool, flaky.job.id);
      return j?.status === 'succeeded' ? j : null;
    });
    await w.stop();
    expect(done.attempts).toBe(2);
    expect((await getJob(db.pool, broken.job.id))?.attempts).toBe(1);
  });

  it('aborts the handler and discards its result when the job is cancelled mid-run', async () => {
    let sawAbort = false;
    const handlers: Record<string, JobHandler> = {
      long: async ({ signal }) => {
        await new Promise<void>((resolve) => {
          const t = setTimeout(resolve, 5_000);
          signal.addEventListener('abort', () => {
            sawAbort = true;
            clearTimeout(t);
            resolve();
          });
        });
        return { result: 'should be discarded' };
      },
    };
    const w = new Worker({ pool: db.newPool(), workerId: 'w', handlers, log, leaseMs: 150, pollMs: 20 });
    const { job } = await enqueue(db.pool, { idempotencyKey: 'long', type: 'long' });
    await w.start();
    await waitFor(async () => (await getJob(db.pool, job.id))?.status === 'running');
    await cancelJob(db.pool, job.id);
    await waitFor(async () => sawAbort, 3_000);
    await waitFor(async () => w.activeJobs === 0);
    await w.stop();
    const final = await getJob(db.pool, job.id);
    expect(final?.status).toBe('cancelled');
    expect(final?.result).toBeNull();
  });

  it('records a heartbeat', async () => {
    const w = new Worker({ pool: db.newPool(), workerId: 'hb', handlers: {}, log, pollMs: 20 });
    await w.start();
    await w.stop();
    const { rows } = await db.pool.query(`SELECT worker_id FROM worker_heartbeats`);
    expect(rows).toEqual([{ worker_id: 'hb' }]);
  });
});
