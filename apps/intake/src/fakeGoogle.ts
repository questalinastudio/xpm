import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { GMAIL_READONLY_SCOPE, type GmailMessage, type GoogleEndpoints } from './google.js';

/**
 * A fake of the Google OAuth and Gmail endpoints the reader uses. Test and
 * acceptance use only. It can simulate outages, expired history, revocation,
 * deletions, and mail arriving in the middle of a sync.
 */

interface StoredMessage {
  msg: GmailMessage;
  addedAtHistory: number;
}

export interface FakeMailInput {
  from: string;
  to?: string;
  cc?: string;
  deliveredTo?: string;
  subject?: string;
  text?: string;
  html?: string;
  labels?: string[];
  internalDate?: number;
  threadId?: string;
  attachment?: { filename: string; mimeType: string; size: number };
}

export class FakeGoogle {
  account = 'owner@questalina.example';
  historyId = 1000;
  /** Requests with startHistoryId below this get 404 (history expired). */
  oldestHistory = 0;
  pageSize = 2;
  grantedScope = GMAIL_READONLY_SCOPE;
  profileEmail?: string;
  readonly requests: { method: string; path: string }[] = [];
  readonly messages = new Map<string, StoredMessage>();
  private readonly codes = new Map<string, string>();
  private readonly refreshTokens = new Set<string>();
  private readonly accessTokens = new Set<string>();
  private failures: { count: number; status: number; match: RegExp }[] = [];
  /** Called when a message is fetched; lets tests add mail mid-sync. */
  onMessageGet?: (id: string) => void;
  private server?: Server;
  baseUrl = '';
  /** Expose /__test control endpoints (container acceptance only). */
  controlEnabled = false;

  async start(port = 0, host = '127.0.0.1'): Promise<GoogleEndpoints> {
    this.server = createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((r) => this.server!.listen(port, host, r));
    const addr = this.server.address() as AddressInfo;
    this.baseUrl = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${addr.port}`;
    return this.endpoints(this.baseUrl);
  }

  endpoints(base: string): GoogleEndpoints {
    return { authUrl: `${base}/o/oauth2/v2/auth`, tokenUrl: `${base}/token`, revokeUrl: `${base}/revoke`, gmailBase: base };
  }

  async stop(): Promise<void> {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }

  /** Simulate the owner approving consent: returns a one-time authorization code. */
  issueCode(): string {
    const code = `code-${randomBytes(8).toString('hex')}`;
    const refresh = `refresh-${randomBytes(16).toString('hex')}`;
    this.codes.set(code, refresh);
    return code;
  }

  revokeAll(): void {
    this.refreshTokens.clear();
    this.accessTokens.clear();
  }

  failNext(count: number, status: number, match = /\/gmail\//): void {
    this.failures.push({ count, status, match });
  }

  addMessage(input: FakeMailInput): string {
    const id = randomBytes(8).toString('hex');
    this.historyId += 1;
    const headers = [
      { name: 'From', value: input.from },
      { name: 'To', value: input.to ?? this.account },
      ...(input.cc ? [{ name: 'Cc', value: input.cc }] : []),
      ...(input.deliveredTo ? [{ name: 'Delivered-To', value: input.deliveredTo }] : []),
      { name: 'Subject', value: input.subject ?? '(no subject)' },
    ];
    const enc = (s: string) => Buffer.from(s, 'utf8').toString('base64url');
    const parts = [
      ...(input.text !== undefined ? [{ partId: '0', mimeType: 'text/plain', headers: [{ name: 'Content-Type', value: 'text/plain; charset="UTF-8"' }], body: { size: input.text.length, data: enc(input.text) } }] : []),
      ...(input.html !== undefined ? [{ partId: '1', mimeType: 'text/html', headers: [{ name: 'Content-Type', value: 'text/html; charset="UTF-8"' }], body: { size: input.html.length, data: enc(input.html) } }] : []),
      ...(input.attachment
        ? [{ partId: '2', mimeType: input.attachment.mimeType, filename: input.attachment.filename, body: { size: input.attachment.size, attachmentId: 'att-1' } }]
        : []),
    ];
    this.messages.set(id, {
      addedAtHistory: this.historyId,
      msg: {
        id,
        threadId: input.threadId ?? `t-${id}`,
        labelIds: input.labels ?? ['INBOX', 'UNREAD'],
        internalDate: String(input.internalDate ?? Date.now()),
        historyId: String(this.historyId),
        payload: { mimeType: 'multipart/mixed', headers, parts },
      },
    });
    return id;
  }

  deleteMessage(id: string): void {
    this.messages.delete(id);
  }

  private async handle(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://fake');
    this.requests.push({ method: req.method ?? '', path: url.pathname });
    const json = (status: number, body: unknown): void => {
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    };
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const form = new URLSearchParams(raw);

    const failure = this.failures.find((f) => f.count > 0 && f.match.test(url.pathname));
    if (failure) {
      failure.count--;
      return json(failure.status, { error: { code: failure.status, message: 'simulated failure' } });
    }

    // Consent screen stand-in: approves immediately and redirects with a code.
    if (req.method === 'GET' && url.pathname === '/o/oauth2/v2/auth') {
      const redirect = new URL(url.searchParams.get('redirect_uri') ?? '');
      redirect.searchParams.set('code', this.issueCode());
      redirect.searchParams.set('state', url.searchParams.get('state') ?? '');
      res.writeHead(302, { location: redirect.href }).end();
      return;
    }
    if (this.controlEnabled && url.pathname.startsWith('/__test/')) {
      if (req.method === 'POST' && url.pathname === '/__test/messages') return json(201, { id: this.addMessage(JSON.parse(raw) as FakeMailInput) });
      if (req.method === 'POST' && url.pathname === '/__test/revoke') {
        this.revokeAll();
        return json(200, {});
      }
      if (req.method === 'GET' && url.pathname === '/__test/requests') return json(200, this.requests);
    }
    if (req.method === 'POST' && url.pathname === '/token') {
      if (form.get('grant_type') === 'authorization_code') {
        const refresh = this.codes.get(form.get('code') ?? '');
        if (!refresh || !form.get('code_verifier')) return json(400, { error: 'invalid_grant' });
        this.codes.delete(form.get('code')!);
        this.refreshTokens.add(refresh);
        const access = `access-${randomBytes(12).toString('hex')}`;
        this.accessTokens.add(access);
        return json(200, { access_token: access, expires_in: 3599, refresh_token: refresh, scope: this.grantedScope, token_type: 'Bearer' });
      }
      if (form.get('grant_type') === 'refresh_token') {
        if (!this.refreshTokens.has(form.get('refresh_token') ?? '')) return json(400, { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
        const access = `access-${randomBytes(12).toString('hex')}`;
        this.accessTokens.add(access);
        return json(200, { access_token: access, expires_in: 3599, scope: this.grantedScope, token_type: 'Bearer' });
      }
      return json(400, { error: 'unsupported_grant_type' });
    }
    if (req.method === 'POST' && url.pathname === '/revoke') {
      const t = form.get('token') ?? '';
      this.refreshTokens.delete(t);
      this.accessTokens.delete(t);
      return json(200, {});
    }

    if (!url.pathname.startsWith('/gmail/v1/users/me/')) return json(404, { error: 'not_found' });
    if (req.method !== 'GET') return json(405, { error: 'method not allowed in fake' });
    const auth = req.headers.authorization?.replace(/^Bearer /, '') ?? '';
    if (!this.accessTokens.has(auth)) return json(401, { error: { code: 401, message: 'Invalid Credentials' } });
    const path = url.pathname.slice('/gmail/v1/users/me/'.length);

    if (path === 'profile') return json(200, { emailAddress: this.profileEmail ?? this.account, historyId: String(this.historyId) });

    if (path === 'history') {
      const start = Number(url.searchParams.get('startHistoryId'));
      if (start < this.oldestHistory) return json(404, { error: { code: 404, message: 'Requested entity was not found.' } });
      const added = [...this.messages.values()].filter((m) => m.addedAtHistory > start).sort((a, b) => a.addedAtHistory - b.addedAtHistory);
      const offset = Number(url.searchParams.get('pageToken') ?? 0);
      const page = added.slice(offset, offset + this.pageSize);
      return json(200, {
        history: page.map((m) => ({ id: String(m.addedAtHistory), messagesAdded: [{ message: { id: m.msg.id, threadId: m.msg.threadId } }] })),
        historyId: String(this.historyId),
        ...(offset + this.pageSize < added.length ? { nextPageToken: String(offset + this.pageSize) } : {}),
      });
    }

    if (path === 'messages') {
      const after = Number(/after:(\d+)/.exec(url.searchParams.get('q') ?? '')?.[1] ?? 0) * 1000;
      const ids = [...this.messages.values()]
        .filter((m) => Number(m.msg.internalDate) > after && !m.msg.labelIds?.some((l) => l === 'SPAM' || l === 'TRASH'))
        .map((m) => ({ id: m.msg.id, threadId: m.msg.threadId }));
      return json(200, { messages: ids, resultSizeEstimate: ids.length });
    }

    const m = /^messages\/([^/]+)$/.exec(path);
    if (m) {
      this.onMessageGet?.(m[1]!);
      const stored = this.messages.get(m[1]!);
      return stored ? json(200, stored.msg) : json(404, { error: { code: 404, message: 'Not Found' } });
    }
    return json(404, { error: 'not_found' });
  }
}
