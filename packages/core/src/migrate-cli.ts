import { createPool, dbOptionsFromEnv } from './db.js';
import { createLogger } from './logger.js';
import { configureServiceRoles, migrate } from './migrate.js';
import { requireSecret } from './secrets.js';

const log = createLogger('migrate');
const pool = createPool(dbOptionsFromEnv(process.env, 'xpm-migrate'));

try {
  const result = await migrate(pool);
  log.info({ applied: result.applied, current: result.current }, 'migrations complete');
  await configureServiceRoles(pool, [
    { name: 'xpm_web', password: requireSecret('XPM_WEB_DB_PASSWORD') },
    { name: 'xpm_worker', password: requireSecret('XPM_WORKER_DB_PASSWORD') },
  ]);
  log.info('service roles configured');
} catch (err) {
  log.error({ err: { message: (err as Error).message } }, 'migration failed');
  process.exitCode = 1;
} finally {
  await pool.end();
}
