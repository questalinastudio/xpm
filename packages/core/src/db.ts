import pg from 'pg';
import { requireSecret } from './secrets.js';

export type Pool = pg.Pool;
export type PoolClient = pg.PoolClient;
/** Anything that can run a query: a pool or a client inside a transaction. */
export type Queryable = Pick<pg.Pool, 'query'> | Pick<pg.PoolClient, 'query'>;

// Return bigint columns (fence, counts) as JS numbers; values stay far below 2^53.
pg.types.setTypeParser(pg.types.builtins.INT8, (v) => Number.parseInt(v, 10));

export interface DbConnectionOptions {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  max?: number;
  applicationName?: string;
}

export function dbOptionsFromEnv(env: NodeJS.ProcessEnv = process.env, applicationName?: string): DbConnectionOptions {
  return {
    host: env.PGHOST ?? 'localhost',
    port: Number.parseInt(env.PGPORT ?? '5432', 10),
    database: env.PGDATABASE ?? 'xpm',
    user: env.PGUSER ?? 'xpm_owner',
    password: requireSecret('PGPASSWORD', env),
    applicationName,
  };
}

export function createPool(options: DbConnectionOptions): Pool {
  const pool = new pg.Pool({
    host: options.host,
    port: options.port,
    database: options.database,
    user: options.user,
    password: options.password,
    max: options.max ?? 10,
    application_name: options.applicationName,
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
  });
  // Idle-client errors (e.g. DB restart) must not crash the process; the next
  // checkout reconnects.
  pool.on('error', () => {});
  return pool;
}

export async function withTx<T>(pool: Pool, fn: (tx: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
