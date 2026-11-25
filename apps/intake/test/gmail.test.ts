import { randomUUID } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { configureServiceRoles, createLogger, generateMasterKey, getCheckpoint, type Pool } from '@xpm/core';
import { startTestDb, waitFor, type TestDb } from '../../../packages/core/test/helpers.js';
import {
  FakeGoogle,
  GMAIL_READONLY_SCOPE,
  GoogleHttp,
  IntakeService,
  listConnections,
  runConnectHelper,
  syncAndRecord,
  type GoogleEndpoints,
} from '../src/index.js';

const VAULT_PW = 'vault-test-pw-0001';
const SUBMIT_TOKEN = 'intake-submit-token-test-000000001';
const CUSTOMER = 'info@questalina.example';
const mk = generateMasterKey();
const client = { clientId: 'test-client.apps.googleusercontent.com', clientSecret: 'GOCSPX-test-client-secret' };

let db: TestDb;
let pool: Pool;
let fake: FakeGoogle;
let endpoints: GoogleEndpoints;
let http: GoogleHttp;
const logs: string[] = [];
const stream = new PassThrough();
stream.on('data', (d) => logs.push(d.toString()));
const log = createLogger('test', { level: 'debug' }, stream);

async function connect(opts: { account?: string } = {}) {
  let authUrl = '';
  const port = 20000 + Math.floor(Math.random() * 20000);
  const done = runConnectHelper({ pool, mk, http, client, account: opts.account ?? fake.account, port, listenHost: '127.0.0.1', log, onAuthUrl: (u) => (authUrl = u) });
  done.catch(() => {}); // observed below
  await waitFor(async () => authUrl);
  const u = new URL(authUrl);
  const cb = new URL(u.searchParams.get('redirect_uri')!);
  cb.searchParams.set('state', u.searchParams.get('state')!);
  cb.searchParams.set('code', fake.issueCode());
  const page = await (await fetch(cb)).text();
  return { done, page, authUrl: u };
}

async function sync() {
  const [conn] = await listConnections(pool, ['active', 'degraded']);
  if (!conn) return null;
  return syncAndRecord(pool, mk, http, client, conn, { customerAddresses: [CUSTOMER], log });
}

async function connection() {
  return (await pool.query(`SELECT * FROM connections`)).rows[0];
}

async function importedSubjects(): Promise<string[]> {
  const { rows } = await pool.query(`SELECT subject FROM messages WHERE source = 'email' ORDER BY received_at, subject`);
  return rows.map((r) => r.subject);
}

beforeAll(async () => {
  db = await startTestDb();
  await configureServiceRoles(db.pool, [{ name: 'xpm_vault', password: VAULT_PW }]);
  pool = db.newPool('xpm_vault', VAULT_PW);
}, 120_000);

afterAll(async () => {
  await fake?.stop();
  await db?.stop();
});

beforeEach(async () => {
  await fake?.stop();
  fake = new FakeGoogle();
  endpoints = await fake.start();
  http = new GoogleHttp(endpoints);
  await db.pool.query(`TRUNCATE messages, vault.originals, vault.identities, vault.connection_secrets, connections, checkpoints CASCADE`);
});

describe('one-time sign-in', () => {
  it('requests only gmail.readonly with PKCE, offline access, and the expected account', async () => {
    const { done, authUrl } = await connect();
    await done;
    expect(authUrl.searchParams.get('scope')).toBe(GMAIL_READONLY_SCOPE);
    expect(authUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authUrl.searchParams.get('access_type')).toBe('offline');
    expect(authUrl.searchParams.get('login_hint')).toBe(fake.account);
    expect(authUrl.searchParams.get('redirect_uri')).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/oauth\/callback$/);
  });

  it('stores the refresh token only encrypted and sets the activation boundary', async () => {
    const { done, page } = await connect();
    const result = await done;
    expect(page).toContain('Connected');
    const conn = await connection();
    expect(conn.status).toBe('active');
    expect(conn.activation_ref).toBe(String(fake.historyId));
    const cp = await getCheckpoint<{ historyId: string }>(pool, `gmail:${result.connectionId}:history`);
    expect(cp?.value.historyId).toBe(String(fake.historyId));
    const secret = (await db.pool.query(`SELECT ciphertext FROM vault.connection_secrets`)).rows[0].ciphertext as Buffer;
    expect(secret.includes(Buffer.from('refresh-'))).toBe(false);
    const everything = JSON.stringify((await db.pool.query(`SELECT * FROM connections`)).rows) + JSON.stringify((await db.pool.query(`SELECT * FROM audit_log`)).rows) + logs.join('');
    expect(everything).not.toMatch(/refresh-[0-9a-f]{32}/);
    expect(everything).not.toContain(client.clientSecret);
  });

  it('rejects a forged callback without ending the session', async () => {
    let authUrl = '';
    const port = 20000 + Math.floor(Math.random() * 20000);
    const done = runConnectHelper({ pool, mk, http, client, account: fake.account, port, listenHost: '127.0.0.1', log, onAuthUrl: (u) => (authUrl = u) });
    await waitFor(async () => authUrl);
    const forged = await fetch(`http://127.0.0.1:${port}/oauth/callback?state=wrong&code=${fake.issueCode()}`);
    expect(forged.status).toBe(400);
    const u = new URL(authUrl);
    await fetch(`http://127.0.0.1:${port}/oauth/callback?state=${u.searchParams.get('state')}&code=${fake.issueCode()}`);
    await expect(done).resolves.toMatchObject({ account: fake.account });
  });

  it('refuses a different Google account and revokes what it was given', async () => {
    fake.profileEmail = 'someone.else@questalina.example';
    const { done } = await connect();
    await expect(done).rejects.toThrow(/Signed in as someone\.else/);
    expect(await connection()).toBeUndefined();
  });

  it('refuses broader scopes than read-only', async () => {
    fake.grantedScope = `${GMAIL_READONLY_SCOPE} https://www.googleapis.com/auth/gmail.send`;
    const { done } = await connect();
    await expect(done).rejects.toThrow(/Unexpected extra scopes/);
    expect(await connection()).toBeUndefined();
  });
});

describe('incremental sync', () => {
  it('never imports historical mail, only mail after activation', async () => {
    fake.addMessage({ from: 'Old Customer <old@example.net>', subject: 'old 1', text: 'before', internalDate: Date.now() - 86_400_000 });
    fake.addMessage({ from: 'Old Customer <old@example.net>', subject: 'old 2', text: 'before' });
    await (await connect()).done;
    expect((await sync())?.imported).toBe(0);
    fake.addMessage({ from: 'New Customer <new@example.net>', subject: 'new 1', text: 'after' });
    expect((await sync())?.imported).toBe(1);
    expect(await importedSubjects()).toEqual(['new 1']);
  });

  it('imports each new message exactly once across repeated passes and pagination', async () => {
    await (await connect()).done;
    for (let i = 1; i <= 5; i++) fake.addMessage({ from: `C${i} <c${i}@example.net>`, subject: `msg ${i}`, text: 'hello' });
    expect((await sync())?.imported).toBe(5);
    expect((await sync())?.imported).toBe(0);
    expect((await importedSubjects()).length).toBe(5);
  });

  it('catches mail that arrives during a sync on the next pass, without duplicates', async () => {
    await (await connect()).done;
    fake.addMessage({ from: 'A <a@example.net>', subject: 'first', text: 'x' });
    let injected = false;
    fake.onMessageGet = () => {
      if (!injected) {
        injected = true;
        fake.addMessage({ from: 'B <b@example.net>', subject: 'arrived mid-sync', text: 'y' });
      }
    };
    await sync();
    await sync();
    await sync();
    expect(await importedSubjects()).toEqual(['first', 'arrived mid-sync']);
  });

  it('recovers from an outage mid-sync without skipping or duplicating', async () => {
    await (await connect()).done;
    for (let i = 1; i <= 3; i++) fake.addMessage({ from: `C <c@example.net>`, subject: `outage ${i}`, text: 'x' });
    let gets = 0;
    fake.onMessageGet = () => {
      if (++gets === 2) fake.failNext(1, 503, /messages\//);
    };
    expect(await sync()).toBeNull();
    const degraded = await connection();
    expect(degraded.status).toBe('degraded');
    expect(degraded.last_error).toMatch(/503/);
    await sync();
    expect((await connection()).status).toBe('active');
    expect(await importedSubjects()).toEqual(['outage 1', 'outage 2', 'outage 3']);
  });

  it('recovers when Gmail has expired the saved history, still excluding pre-activation mail', async () => {
    fake.addMessage({ from: 'Old <old@example.net>', subject: 'historical', text: 'x', internalDate: Date.now() - 600_000 });
    await (await connect()).done;
    fake.addMessage({ from: 'New <new@example.net>', subject: 'missed while history expired', text: 'y' });
    fake.oldestHistory = fake.historyId + 1; // everything before now has expired
    const r = await sync();
    expect(r?.recovered).toBe(true);
    expect(await importedSubjects()).toEqual(['missed while history expired']);
    fake.addMessage({ from: 'Later <later@example.net>', subject: 'after recovery', text: 'z' });
    fake.oldestHistory = 0;
    await sync();
    expect(await importedSubjects()).toEqual(['missed while history expired', 'after recovery']);
  });

  it('skips sent mail, drafts, spam, trash, and deleted messages', async () => {
    await (await connect()).done;
    fake.addMessage({ from: 'Me <owner@questalina.example>', subject: 'sent', text: 'x', labels: ['SENT'] });
    fake.addMessage({ from: 'Me <owner@questalina.example>', subject: 'draft', text: 'x', labels: ['DRAFT'] });
    fake.addMessage({ from: 'Spammer <s@example.net>', subject: 'spam', text: 'x', labels: ['SPAM'] });
    fake.addMessage({ from: 'X <x@example.net>', subject: 'trash', text: 'x', labels: ['TRASH'] });
    const gone = fake.addMessage({ from: 'X <x@example.net>', subject: 'deleted', text: 'x' });
    fake.addMessage({ from: 'Me <owner@questalina.example>', subject: 'note to self', text: 'x', labels: ['SENT', 'INBOX'] });
    fake.deleteMessage(gone);
    const r = await sync();
    expect(r?.skipped).toMatchObject({ outgoing: 1, draft: 1, spam: 1, trash: 1 });
    expect(await importedSubjects()).toEqual(['note to self']);
  });

  it('marks mail sent to the info@ alias as likely customer correspondence', async () => {
    await (await connect()).done;
    fake.addMessage({ from: 'Cust <cust@example.net>', to: `Questalina <${CUSTOMER}>`, subject: 'help please', text: 'x' });
    fake.addMessage({ from: 'Vendor <v@example.net>', subject: 'invoice', text: 'x' });
    await sync();
    const { rows } = await pool.query(`SELECT subject, metadata FROM messages ORDER BY subject`);
    expect(rows.map((r) => [r.subject, r.metadata.likelyCustomer, r.metadata.deliveredVia])).toEqual([
      ['help please', true, CUSTOMER],
      ['invoice', false, null],
    ]);
  });

  it('applies the privacy pipeline and records attachments by type only', async () => {
    await (await connect()).done;
    fake.addMessage({
      from: '"Hayes, Marisol" <marisol.hayes@gmail.com>',
      subject: '=?UTF-8?B?Q2FsbCBtZSwgTWFyaXNvbA==?=',
      text: 'Hi team,\nPlease call 415-555-0142.\n\nThanks,\nMarisol Hayes',
      attachment: { filename: 'marisol-passport.pdf', mimeType: 'application/pdf', size: 52_000 },
    });
    await sync();
    const { rows } = await pool.query(`SELECT subject, body, sender_placeholder, metadata FROM messages`);
    const text = JSON.stringify(rows);
    for (const leak of ['Marisol', 'marisol', 'Hayes', '555-0142', 'passport']) expect(text).not.toContain(leak);
    expect(rows[0].subject).toBe('Call me, [PERSON_1]');
    expect(rows[0].metadata.attachments).toEqual([{ mimeType: 'application/pdf', size: 52_000 }]);
  });
});

describe('revocation and reconnection', () => {
  it('pauses visibly when access is revoked and resumes after reconnecting, without losing mail', async () => {
    await (await connect()).done;
    fake.addMessage({ from: 'A <a@example.net>', subject: 'before revoke', text: 'x' });
    await sync();
    fake.revokeAll();
    fake.addMessage({ from: 'B <b@example.net>', subject: 'while paused', text: 'y' });
    expect(await sync()).toBeNull();
    const paused = await connection();
    expect(paused.status).toBe('paused');
    expect(paused.status_reason).toMatch(/Reconnect/);
    expect(await sync()).toBeNull(); // paused connections are not polled
    const again = await (await connect()).done;
    expect(again.reconnected).toBe(true);
    await sync();
    expect(await importedSubjects()).toEqual(['before revoke', 'while paused']);
    expect((await connection()).activated_at.getTime()).toBe(paused.activated_at.getTime()); // boundary unchanged
  });
});

describe('read-only guarantees', () => {
  it('only ever reads Gmail; POSTs go solely to the OAuth token endpoint', async () => {
    await (await connect()).done;
    fake.addMessage({ from: 'A <a@example.net>', subject: 'x', text: 'x' });
    await sync();
    const nonGet = fake.requests.filter((r) => r.method !== 'GET');
    expect(nonGet.every((r) => r.path === '/token')).toBe(true);
    expect(fake.requests.filter((r) => r.path.startsWith('/gmail/')).every((r) => r.method === 'GET')).toBe(true);
  });

  it('the HTTP client refuses writes to Gmail and requests to other hosts', async () => {
    await expect(http.request('POST', `${endpoints.gmailBase}/gmail/v1/users/me/messages/send`)).rejects.toThrow(/read-only/);
    await expect(http.request('GET', 'https://evil.example/steal')).rejects.toThrow(/non-Google host/);
    await expect(http.request('POST', `${endpoints.gmailBase}/other`)).rejects.toThrow(/POST is only allowed/);
    await expect(http.request('POST', `${endpoints.gmailBase}/gmail/v1/users/me/messages/abc/modify`)).rejects.toThrow(/read-only/);
  });
});

describe('manual SMS entry', () => {
  let service: IntakeService;
  let url: string;
  beforeAll(async () => {
    const port = 20000 + Math.floor(Math.random() * 20000);
    service = new IntakeService({ pool, mk, log, customerAddresses: [], pollMs: 60_000, submitToken: SUBMIT_TOKEN, port });
    await service.start();
    url = `http://127.0.0.1:${port}/v1/sms`;
  });
  afterAll(async () => {
    await service?.stop();
  });
  const submit = (body: unknown, token = SUBMIT_TOKEN) =>
    fetch(url, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  it('runs the privacy pipeline and imports a repeated submission once', async () => {
    const body = {
      submissionId: randomUUID(),
      from: '+1 (206) 555-0199',
      fromName: 'Tomasz Wierzbicki',
      text: 'Hi, this is Tomasz. The app crashes when I upload a photo.',
      receivedAt: new Date().toISOString(),
      context: 'Customer from the Seattle group',
    };
    expect((await submit(body)).status).toBe(201);
    expect((await submit(body)).status).toBe(200);
    const { rows } = await pool.query(`SELECT * FROM messages WHERE source = 'sms'`);
    expect(rows).toHaveLength(1);
    const text = JSON.stringify(rows);
    for (const leak of ['Tomasz', 'Wierzbicki', '555-0199', '2065550199']) expect(text).not.toContain(leak);
    expect(rows[0].thread_key).toMatch(/^sms:[0-9a-f]{16}$/);
    expect(rows[0].body).toContain('[Owner note]');
    expect(rows[0].metadata.channel).toBe('manual_sms');
  });

  it('groups texts from the same number into one thread without storing the number', async () => {
    const base = { from: '415-555-0100', text: 'hello', receivedAt: new Date().toISOString() };
    await submit({ ...base, submissionId: randomUUID() });
    await submit({ ...base, from: '+1 415 555 0100', submissionId: randomUUID() });
    const { rows } = await pool.query(`SELECT DISTINCT thread_key FROM messages WHERE source = 'sms' AND body = 'hello'`);
    expect(rows).toHaveLength(1);
  });

  it('rejects unauthenticated or malformed submissions', async () => {
    expect((await submit({ submissionId: randomUUID(), from: '415-555-0100', text: 'x', receivedAt: new Date().toISOString() }, 'wrong')).status).toBe(401);
    expect((await submit({ submissionId: 'not-a-uuid', from: 'abc', text: '', receivedAt: 'yesterday' })).status).toBe(400);
  });
});
