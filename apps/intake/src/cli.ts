/**
 * Intake service and tools. The only component holding the master key, the
 * vault role, and the Gmail read-only authorization.
 *
 *   serve                                   Long-running Gmail polling + SMS submission API
 *   gmail-connect --account <email> [--port 8765]
 *                                           One-time sign-in (run over an SSH tunnel)
 *   gmail-status                            Show connection states
 *   gmail-disconnect --account <email>      Revoke at Google and stop reading
 *   ingest-synthetic                        Load fictional sample mail (sample mode only)
 */
import { existsSync, readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { createLogger, createPool, dbOptionsFromEnv, loadMasterKey, requireSecret } from '@xpm/core';
import { runConnectHelper } from './connect.js';
import { GOOGLE_ENDPOINTS, GoogleHttp, loadOAuthClient, revokeToken, type GoogleEndpoints } from './google.js';
import { listConnections, loadRefreshToken, setConnectionStatus } from './gmailSync.js';
import { FakeGoogle } from './fakeGoogle.js';
import { IntakeService } from './service.js';
import { ingestSynthetic } from './vault.js';

const log = createLogger('intake');
const env = process.env;

/** Test installations may point at a fake Google; production uses Google's real endpoints. */
function endpoints(): GoogleEndpoints {
  return {
    authUrl: env.XPM_GOOGLE_AUTH_URL ?? GOOGLE_ENDPOINTS.authUrl,
    tokenUrl: env.XPM_GOOGLE_TOKEN_URL ?? GOOGLE_ENDPOINTS.tokenUrl,
    revokeUrl: env.XPM_GOOGLE_REVOKE_URL ?? GOOGLE_ENDPOINTS.revokeUrl,
    gmailBase: env.XPM_GMAIL_API_BASE ?? GOOGLE_ENDPOINTS.gmailBase,
  };
}

function google() {
  const file = env.XPM_GMAIL_CLIENT_FILE ?? '/run/secrets/gmail_reader_client';
  if (!existsSync(file) || readFileSync(file, 'utf8').trim() === '') return undefined;
  return { http: new GoogleHttp(endpoints()), client: loadOAuthClient(file) };
}

async function main(): Promise<number> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { account: { type: 'string' }, port: { type: 'string', default: '8765' } },
  });
  const command = positionals[0];
  const mk = () => loadMasterKey(env.XPM_MASTER_KEY_FILE ?? '/run/secrets/protected_master_key');
  const pool = () => createPool(dbOptionsFromEnv(env, 'xpm-intake'));

  switch (command) {
    case 'serve': {
      const g = google();
      if (!g) log.warn('No Gmail client file; Gmail intake disabled until it is provided');
      const p = pool();
      const service = new IntakeService({
        pool: p,
        mk: mk(),
        log,
        google: g,
        customerAddresses: (env.XPM_CUSTOMER_ADDRESSES ?? '').split(',').map((s) => s.trim()).filter(Boolean),
        pollMs: Number(env.XPM_GMAIL_POLL_SECONDS ?? 60) * 1000,
        submitToken: requireSecret('XPM_INTAKE_SUBMIT_TOKEN'),
        port: Number(env.XPM_INTAKE_PORT ?? 4200),
      });
      await service.start();
      log.info({ gmail: Boolean(g) }, 'intake service started');
      await new Promise<void>((resolve) => {
        for (const s of ['SIGTERM', 'SIGINT'] as const) process.once(s, () => resolve());
      });
      await service.stop();
      await p.end();
      return 0;
    }

    case 'gmail-connect': {
      const g = google();
      if (!g) throw new Error('Gmail client file is missing (secrets/gmail_reader_client.json)');
      if (!values.account) throw new Error('--account is required');
      const p = pool();
      try {
        const port = Number(values.port);
        const result = await runConnectHelper({
          pool: p,
          mk: mk(),
          ...g,
          account: values.account,
          port,
          log,
          onAuthUrl: (url) => {
            console.log(`\nOn your laptop, keep this SSH tunnel open in another terminal:\n\n  ssh -N -L ${port}:127.0.0.1:${port} eko@<workstation>\n`);
            console.log(`Then open this link in the laptop's browser and approve read-only access:\n\n  ${url}\n`);
            console.log('Waiting for Google (10 minutes)…');
          },
        });
        console.log(`\n✔ ${result.reconnected ? 'Reconnected' : 'Connected'} ${result.account}. Only mail arriving from now on is imported.`);
        return 0;
      } finally {
        await p.end();
      }
    }

    case 'gmail-status': {
      const p = pool();
      try {
        const { rows } = await p.query(
          `SELECT account, status, status_reason, activated_at, last_success_at, imported_count, skipped_count, last_error FROM connections ORDER BY account`,
        );
        if (rows.length === 0) console.log('No Gmail connection yet. Run gmail-connect.');
        for (const r of rows) {
          console.log(`${r.account}: ${r.status}${r.status_reason ? ` (${r.status_reason})` : ''}`);
          console.log(`  activated ${r.activated_at.toISOString()}, last success ${r.last_success_at?.toISOString() ?? 'never'}`);
          console.log(`  imported ${r.imported_count}, skipped ${r.skipped_count}${r.last_error ? `, last error: ${r.last_error}` : ''}`);
        }
        return 0;
      } finally {
        await p.end();
      }
    }

    case 'gmail-disconnect': {
      if (!values.account) throw new Error('--account is required');
      const g = google();
      const p = pool();
      try {
        const conn = (await listConnections(p, ['active', 'degraded', 'paused'])).find((c) => c.account === values.account!.toLowerCase());
        if (!conn) throw new Error(`No connection for ${values.account}`);
        if (g) await revokeToken(g.http, await loadRefreshToken(p, mk(), conn.id)).catch(() => {});
        await setConnectionStatus(p, conn.id, 'disconnected', 'Disconnected by the owner');
        console.log(`Disconnected ${conn.account}; Google access revoked.`);
        return 0;
      } finally {
        await p.end();
      }
    }

    case 'fake-google': {
      // Acceptance testing only: a stand-in for Google's endpoints.
      if (env.XPM_ALLOW_FAKE_GOOGLE !== 'true') throw new Error('fake-google is for acceptance tests only');
      const fake = new FakeGoogle();
      fake.controlEnabled = true;
      fake.account = env.XPM_FAKE_ACCOUNT ?? fake.account;
      fake.pageSize = 50;
      await fake.start(Number(values.port), '0.0.0.0');
      console.log(`fake google listening on ${values.port}`);
      await new Promise<void>((resolve) => {
        for (const s of ['SIGTERM', 'SIGINT'] as const) process.once(s, () => resolve());
      });
      await fake.stop();
      return 0;
    }

    case 'ingest-synthetic': {
      if (!['true', '1'].includes(env.XPM_SAMPLE_DATA ?? '')) {
        console.error('Refusing: synthetic data is only allowed when XPM_SAMPLE_DATA=true');
        return 1;
      }
      const p = pool();
      try {
        for (const r of await ingestSynthetic(p, mk())) log.info(r, 'ingested');
        return 0;
      } finally {
        await p.end();
      }
    }

    default:
      console.log('Usage: intake serve | gmail-connect --account <email> | gmail-status | gmail-disconnect --account <email> | ingest-synthetic');
      return command === undefined || command === 'help' ? 0 : 2;
  }
}

try {
  process.exitCode = await main();
} catch (err) {
  log.error({ err }, 'intake command failed');
  console.error(`Error: ${(err as Error).message}`);
  process.exitCode = 1;
}
