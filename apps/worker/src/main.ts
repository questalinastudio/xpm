import { hostname } from 'node:os';
import { randomBytes } from 'node:crypto';
import { createLogger, createPool, dbOptionsFromEnv, Worker } from '@xpm/core';
import { demoHandlers } from './handlers.js';

const log = createLogger('worker');
const pool = createPool(dbOptionsFromEnv(process.env, 'xpm-worker'));
const sampleMode = ['true', '1'].includes(process.env.XPM_SAMPLE_DATA ?? '');

// Unique per process so a restarted container never reuses a dead lease owner's identity.
const workerId = `${process.env.XPM_WORKER_NAME ?? hostname()}-${randomBytes(4).toString('hex')}`;

const worker = new Worker({
  pool,
  workerId,
  log,
  handlers: sampleMode ? { ...demoHandlers } : {},
  leaseMs: Number(process.env.XPM_JOB_LEASE_MS ?? 30_000),
  concurrency: Number(process.env.XPM_WORKER_CONCURRENCY ?? 2),
});

await worker.start();
log.info({ workerId, sampleMode }, 'worker started');

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, async () => {
    log.info({ signal }, 'stopping worker');
    await worker.stop();
    await pool.end();
    process.exit(0);
  });
}
