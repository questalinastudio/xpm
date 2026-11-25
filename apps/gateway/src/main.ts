import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createLogger, createPool, dbOptionsFromEnv, requireSecret } from '@xpm/core';
import { buildGateway } from './app.js';
import { ObedientSimulatedProvider } from './provider.js';

const log = createLogger('gateway');
const env = process.env;
const dbFor = (user: string, secret: string, name: string) =>
  createPool({ ...dbOptionsFromEnv({ ...env, PGUSER: user, PGPASSWORD_FILE: env[`${secret}_FILE`] }, name), max: 5 });

if ((env.XPM_AI_PROVIDER ?? 'simulated') !== 'simulated') {
  throw new Error('Only the simulated provider exists before Milestone 4');
}
const snapshotDir = env.XPM_SNAPSHOT_DIR ?? '/snapshot';
const manifestPath = join(snapshotDir, '.snapshot-manifest.json');
const sourceRef = existsSync(manifestPath) ? (JSON.parse(readFileSync(manifestPath, 'utf8')).sourceRef as string) : undefined;

const app = await buildGateway({
  pool: dbFor('xpm_gateway', 'XPM_GATEWAY_DB_PASSWORD', 'xpm-gateway'),
  toolEnv: {
    pmPool: dbFor('xpm_pm_tools', 'XPM_PM_TOOLS_DB_PASSWORD', 'xpm-gateway-pm-tools'),
    devPool: dbFor('xpm_dev_tools', 'XPM_DEV_TOOLS_DB_PASSWORD', 'xpm-gateway-dev-tools'),
    snapshotDir,
  },
  tokens: { pm: requireSecret('XPM_PM_RUNTIME_TOKEN'), dev: requireSecret('XPM_DEV_RUNTIME_TOKEN') },
  provider: new ObedientSimulatedProvider(),
  sourceRef,
  logger: true,
});
await app.listen({ host: '0.0.0.0', port: Number(env.XPM_GATEWAY_PORT ?? 4100) });
log.info({ sourceRef: sourceRef ?? 'none', provider: 'simulated' }, 'gateway ready');

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, async () => {
    await app.close();
    process.exit(0);
  });
}
