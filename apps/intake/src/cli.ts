/**
 * Intake tool. Milestone 3 turns this into a long-running Gmail/SMS service;
 * for now it ingests the synthetic dataset in sample-data mode.
 *
 *   docker compose run --rm intake ingest-synthetic
 */
import { createLogger, createPool, dbOptionsFromEnv, loadMasterKey } from '@xpm/core';
import { ingestSynthetic } from './vault.js';

const log = createLogger('intake');

async function main(command: string | undefined): Promise<number> {
  if (command !== 'ingest-synthetic') {
    console.log('Usage: intake ingest-synthetic');
    return 2;
  }
  if (!['true', '1'].includes(process.env.XPM_SAMPLE_DATA ?? '')) {
    console.error('Refusing: synthetic data is only allowed when XPM_SAMPLE_DATA=true');
    return 1;
  }
  const mk = loadMasterKey(process.env.XPM_MASTER_KEY_FILE ?? '/run/secrets/protected_master_key');
  const pool = createPool(dbOptionsFromEnv(process.env, 'xpm-intake'));
  try {
    for (const r of await ingestSynthetic(pool, mk)) log.info(r, 'ingested');
    return 0;
  } finally {
    await pool.end();
  }
}

try {
  process.exitCode = await main(process.argv[2]);
} catch (err) {
  log.error({ err }, 'intake failed');
  process.exitCode = 1;
}
