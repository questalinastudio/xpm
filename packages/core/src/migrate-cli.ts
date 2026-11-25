import { createPool, dbOptionsFromEnv } from './db.js';
import { createLogger } from './logger.js';
import { configureServiceRoles, migrate, type ServiceRole } from './migrate.js';
import { readSecret } from './secrets.js';

const log = createLogger('migrate');
const pool = createPool(dbOptionsFromEnv(process.env, 'xpm-migrate'));

/** Service role → secret name. Roles without a provided password stay NOLOGIN. */
const SERVICE_ROLES: Record<string, string> = {
  xpm_web: 'XPM_WEB_DB_PASSWORD',
  xpm_worker: 'XPM_WORKER_DB_PASSWORD',
  xpm_vault: 'XPM_VAULT_DB_PASSWORD',
  xpm_gateway: 'XPM_GATEWAY_DB_PASSWORD',
  xpm_pm_tools: 'XPM_PM_TOOLS_DB_PASSWORD',
  xpm_dev_tools: 'XPM_DEV_TOOLS_DB_PASSWORD',
};

try {
  const result = await migrate(pool);
  log.info({ applied: result.applied, current: result.current }, 'migrations complete');
  const roles: ServiceRole[] = [];
  for (const [name, secret] of Object.entries(SERVICE_ROLES)) {
    const password = readSecret(secret);
    if (password) roles.push({ name, password });
    else log.warn({ role: name }, 'no password provided; role left without login');
  }
  await configureServiceRoles(pool, roles);
  log.info({ roles: roles.map((r) => r.name) }, 'service roles configured');
} catch (err) {
  log.error({ err }, 'migration failed');
  process.exitCode = 1;
} finally {
  await pool.end();
}
