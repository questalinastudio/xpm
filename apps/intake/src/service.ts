import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import type { Logger, MasterKey, Pool } from '@xpm/core';
import { scrubSecrets } from '@xpm/privacy';
import type { GoogleHttp, OAuthClient } from './google.js';
import { listConnections, syncAndRecord } from './gmailSync.js';
import { ingestSms, smsSubmissionSchema } from './sms.js';

export interface IntakeServiceOptions {
  pool: Pool;
  mk: MasterKey;
  log: Logger;
  /** Absent until the Gmail client file is provided. */
  google?: { http: GoogleHttp; client: OAuthClient };
  customerAddresses: string[];
  pollMs: number;
  submitToken: string;
  port: number;
}

/**
 * Long-running intake: polls Gmail connections and accepts manual SMS
 * submissions from the dashboard server over the internal network.
 */
export class IntakeService {
  private running = false;
  private loop?: Promise<void>;
  private server?: Server;
  private readonly wake = new AbortController();

  constructor(private readonly opts: IntakeServiceOptions) {}

  async start(): Promise<void> {
    this.running = true;
    this.server = this.createApi();
    await new Promise<void>((resolve) => this.server!.listen(this.opts.port, '0.0.0.0', resolve));
    this.loop = this.pollLoop();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.wake.abort();
    await this.loop;
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }

  /** One pass over all active connections (exposed for tests). */
  async syncOnce(): Promise<void> {
    if (!this.opts.google) return;
    for (const conn of await listConnections(this.opts.pool)) {
      await syncAndRecord(this.opts.pool, this.opts.mk, this.opts.google.http, this.opts.google.client, conn, {
        customerAddresses: this.opts.customerAddresses,
        log: this.opts.log,
      });
    }
  }

  private async pollLoop(): Promise<void> {
    while (this.running) {
      try {
        await this.syncOnce();
      } catch (err) {
        this.opts.log.error({ err }, 'intake poll failed');
      }
      await delay(this.opts.pollMs, undefined, { signal: this.wake.signal }).catch(() => {});
    }
  }

  private createApi(): Server {
    const expected = createHash('sha256').update(this.opts.submitToken).digest();
    const authorized = (h: string | undefined) => {
      if (!h?.startsWith('Bearer ')) return false;
      return timingSafeEqual(createHash('sha256').update(h.slice(7)).digest(), expected);
    };
    return createServer(async (req, res) => {
      const json = (status: number, body: unknown): void => {
        res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
      };
      if (req.method === 'GET' && req.url === '/healthz') return json(200, { status: 'ok' });
      if (req.method !== 'POST' || req.url !== '/v1/sms') return json(404, { error: 'not_found' });
      if (!authorized(req.headers.authorization)) return json(401, { error: 'unauthorized' });
      let raw = '';
      for await (const chunk of req) {
        raw += chunk;
        if (raw.length > 64 * 1024) return json(413, { error: 'too_large' });
      }
      try {
        const parsed = smsSubmissionSchema.safeParse(JSON.parse(raw));
        if (!parsed.success) return json(400, { error: 'bad_request', message: parsed.error.issues.map((i) => i.message).join('; ') });
        const r = await ingestSms(this.opts.pool, this.opts.mk, parsed.data);
        return json(r.created ? 201 : 200, r);
      } catch (err) {
        this.opts.log.error({ err }, 'sms submission failed');
        return json(500, { error: 'internal_error', message: scrubSecrets((err as Error).message) });
      }
    });
  }
}
