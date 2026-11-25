import { createLogger, createPool, dbOptionsFromEnv } from '@xpm/core';
import { buildApp } from './app.js';
import { loadServerConfig } from './config.js';
import { seedSampleData } from './sample.js';

const log = createLogger('server');
const config = loadServerConfig();
const pool = createPool(dbOptionsFromEnv(process.env, 'xpm-server'));

if (config.sampleMode) {
  const n = await seedSampleData(pool);
  log.warn({ inserted: n }, 'SAMPLE DATA MODE is on');
}

const app = await buildApp({ pool, config, logger: true });
await app.listen({ host: config.listenHost, port: config.listenPort });

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, async () => {
    log.info({ signal }, 'shutting down');
    await app.close();
    await pool.end();
    process.exit(0);
  });
}
