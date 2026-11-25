import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { createPool, migrate, type Pool } from '../src/index.js';

export const POSTGRES_IMAGE = 'postgres:17-bookworm';

export interface TestDb {
  container: StartedPostgreSqlContainer;
  pool: Pool;
  /** Open another pool, e.g. to act as a separate worker process or a service role. */
  newPool(user?: string, password?: string): Pool;
  stop(): Promise<void>;
}

export async function startTestDb(): Promise<TestDb> {
  const container = await new PostgreSqlContainer(POSTGRES_IMAGE).start();
  const pools: Pool[] = [];
  const newPool = (user = container.getUsername(), password = container.getPassword()) => {
    const p = createPool({
      host: container.getHost(),
      port: container.getPort(),
      database: container.getDatabase(),
      user,
      password,
      max: 20,
    });
    pools.push(p);
    return p;
  };
  const pool = newPool();
  await migrate(pool);
  return {
    container,
    pool,
    newPool,
    async stop() {
      await Promise.all(pools.map((p) => p.end().catch(() => {})));
      await container.stop();
    },
  };
}

export async function resetQueue(pool: Pool): Promise<void> {
  await pool.query('TRUNCATE jobs, job_attempts, checkpoints, worker_heartbeats CASCADE');
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function waitFor<T>(fn: () => Promise<T | null | undefined | false>, timeoutMs = 10_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error('waitFor timed out');
    await sleep(50);
  }
}
