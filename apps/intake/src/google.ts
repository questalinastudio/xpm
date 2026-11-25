import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Minimal Google OAuth + Gmail client for read-only intake.
 *
 * Safety properties, enforced here rather than trusted to callers:
 * - Requests go only to the configured Google hosts.
 * - Gmail API calls are GET only. The client has no code path that can send,
 *   modify, label, mark read, or delete mail, and the only scope it ever
 *   requests is gmail.readonly.
 * - POST is used only for the OAuth token and revocation endpoints.
 */

export const GMAIL_READONLY_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';

export interface GoogleEndpoints {
  authUrl: string;
  tokenUrl: string;
  revokeUrl: string;
  gmailBase: string;
}

export const GOOGLE_ENDPOINTS: GoogleEndpoints = {
  authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  revokeUrl: 'https://oauth2.googleapis.com/revoke',
  gmailBase: 'https://gmail.googleapis.com',
};

export interface OAuthClient {
  clientId: string;
  clientSecret: string;
}

/** Reads a Desktop-app client file downloaded from Google Cloud. */
export function loadOAuthClient(path: string): OAuthClient {
  const d = JSON.parse(readFileSync(path, 'utf8'));
  const c = d.installed;
  if (!c) throw new Error('OAuth client file must be a Desktop app ("installed") client');
  return { clientId: c.client_id, clientSecret: c.client_secret };
}

/** Authorization revoked, expired, or insufficient: needs the owner to reconnect. */
export class GoogleAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GoogleAuthError';
  }
}

/** Temporary failure (network, rate limit, 5xx): retry later. */
export class GoogleTransientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GoogleTransientError';
  }
}

/** The message was deleted between being listed and being fetched. */
export class GmailNotFoundError extends Error {
  constructor(id: string) {
    super(`Gmail message ${id} no longer exists`);
    this.name = 'GmailNotFoundError';
  }
}

/** Gmail no longer has history from the checkpoint; a recovery listing is needed. */
export class HistoryExpiredError extends Error {
  constructor() {
    super('Gmail history for the saved checkpoint is no longer available');
    this.name = 'HistoryExpiredError';
  }
}

export class GoogleHttp {
  private readonly allowedHosts: Set<string>;

  constructor(readonly endpoints: GoogleEndpoints = GOOGLE_ENDPOINTS) {
    this.allowedHosts = new Set(Object.values(endpoints).map((u) => new URL(u).host));
  }

  async request(method: 'GET' | 'POST', url: string, init: { headers?: Record<string, string>; form?: Record<string, string> } = {}): Promise<Response> {
    const u = new URL(url);
    if (!this.allowedHosts.has(u.host)) throw new Error(`Refusing request to non-Google host ${u.host}`);
    const gmail = u.href.startsWith(`${this.endpoints.gmailBase}/gmail/`);
    if (gmail && method !== 'GET') throw new Error('Gmail API access is read-only (GET only)');
    if (!gmail && method === 'POST' && u.href !== this.endpoints.tokenUrl && u.href !== this.endpoints.revokeUrl) {
      throw new Error('POST is only allowed to the OAuth token and revoke endpoints');
    }
    try {
      return await fetch(u, {
        method,
        headers: { ...(init.form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...init.headers },
        body: init.form ? new URLSearchParams(init.form).toString() : undefined,
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      throw new GoogleTransientError(`Network error contacting ${u.host}: ${(err as Error).message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// OAuth (authorization code + PKCE, loopback redirect)
// ---------------------------------------------------------------------------

export interface PkceSession {
  state: string;
  verifier: string;
  redirectUri: string;
  url: string;
}

export function buildAuthUrl(endpoints: GoogleEndpoints, client: OAuthClient, redirectUri: string, account: string): PkceSession {
  const state = randomBytes(24).toString('base64url');
  const verifier = randomBytes(48).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: client.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: GMAIL_READONLY_SCOPE,
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'false',
    login_hint: account,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  return { state, verifier, redirectUri, url: `${endpoints.authUrl}?${params}` };
}

export interface TokenSet {
  accessToken: string;
  expiresAt: number;
  refreshToken?: string;
  scope: string;
}

async function tokenRequest(http: GoogleHttp, form: Record<string, string>): Promise<TokenSet> {
  const res = await http.request('POST', http.endpoints.tokenUrl, { form });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    const code = String(body.error ?? res.status);
    if (code === 'invalid_grant' || code === 'unauthorized_client' || code === 'invalid_client') {
      throw new GoogleAuthError(`Google refused the authorization (${code}); reconnect is required`);
    }
    if (res.status >= 500 || res.status === 429) throw new GoogleTransientError(`Token endpoint returned ${res.status}`);
    throw new GoogleAuthError(`Token request failed (${code})`);
  }
  return {
    accessToken: String(body.access_token),
    expiresAt: Date.now() + Number(body.expires_in ?? 3600) * 1000,
    refreshToken: body.refresh_token ? String(body.refresh_token) : undefined,
    scope: String(body.scope ?? ''),
  };
}

export function exchangeCode(http: GoogleHttp, client: OAuthClient, session: PkceSession, code: string): Promise<TokenSet> {
  return tokenRequest(http, {
    grant_type: 'authorization_code',
    code,
    client_id: client.clientId,
    client_secret: client.clientSecret,
    redirect_uri: session.redirectUri,
    code_verifier: session.verifier,
  });
}

export function refreshAccessToken(http: GoogleHttp, client: OAuthClient, refreshToken: string): Promise<TokenSet> {
  return tokenRequest(http, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: client.clientId,
    client_secret: client.clientSecret,
  });
}

export async function revokeToken(http: GoogleHttp, token: string): Promise<void> {
  await http.request('POST', http.endpoints.revokeUrl, { form: { token } });
}

/** Granted scopes must be exactly gmail.readonly (Google may add identity scopes; nothing broader). */
export function checkGrantedScopes(scope: string): string | null {
  const granted = scope.split(/\s+/).filter(Boolean);
  if (!granted.includes(GMAIL_READONLY_SCOPE)) return 'gmail.readonly was not granted';
  const extra = granted.filter((s) => s !== GMAIL_READONLY_SCOPE && !['openid', 'email', 'profile'].includes(s) && !s.endsWith('/userinfo.email'));
  return extra.length > 0 ? `Unexpected extra scopes granted: ${extra.join(' ')}` : null;
}

// ---------------------------------------------------------------------------
// Gmail (read-only)
// ---------------------------------------------------------------------------

export interface GmailHeader {
  name: string;
  value: string;
}

export interface GmailPart {
  partId?: string;
  mimeType: string;
  filename?: string;
  headers?: GmailHeader[];
  body?: { size: number; data?: string; attachmentId?: string };
  parts?: GmailPart[];
}

export interface GmailMessage {
  id: string;
  threadId: string;
  labelIds?: string[];
  internalDate: string;
  historyId: string;
  payload: GmailPart;
}

export class GmailClient {
  private token: TokenSet | null = null;

  constructor(
    private readonly http: GoogleHttp,
    private readonly client: OAuthClient,
    private readonly refreshToken: string,
  ) {}

  private async accessToken(): Promise<string> {
    if (!this.token || this.token.expiresAt - Date.now() < 60_000) {
      this.token = await refreshAccessToken(this.http, this.client, this.refreshToken);
    }
    return this.token.accessToken;
  }

  private async get<T>(path: string, query: Record<string, string | string[] | undefined> = {}): Promise<T> {
    const url = new URL(`${this.http.endpoints.gmailBase}/gmail/v1/users/me/${path}`);
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined) continue;
      for (const item of Array.isArray(v) ? v : [v]) url.searchParams.append(k, item);
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await this.http.request('GET', url.href, { headers: { authorization: `Bearer ${await this.accessToken()}` } });
      if (res.ok) return (await res.json()) as T;
      if (res.status === 401 && attempt === 0) {
        this.token = null; // refresh once, then give up
        continue;
      }
      if (res.status === 401 || res.status === 403) throw new GoogleAuthError(`Gmail returned ${res.status}; access was revoked or is insufficient`);
      if (res.status === 404 && path === 'history') throw new HistoryExpiredError();
      if (res.status === 404 && path.startsWith('messages/')) throw new GmailNotFoundError(path.slice(9));
      if (res.status === 429 || res.status >= 500) throw new GoogleTransientError(`Gmail returned ${res.status}`);
      throw new GoogleTransientError(`Gmail returned unexpected status ${res.status}`);
    }
    throw new GoogleAuthError('Gmail authorization failed after refresh');
  }

  profile(): Promise<{ emailAddress: string; historyId: string }> {
    return this.get('profile');
  }

  /** IDs of messages added since startHistoryId, plus the mailbox's current historyId. */
  async messagesAddedSince(startHistoryId: string): Promise<{ ids: string[]; historyId: string }> {
    const ids: string[] = [];
    let pageToken: string | undefined;
    let historyId = startHistoryId;
    do {
      const page = await this.get<{ history?: { messagesAdded?: { message: { id: string } }[] }[]; historyId: string; nextPageToken?: string }>(
        'history',
        { startHistoryId, historyTypes: 'messageAdded', maxResults: '500', pageToken },
      );
      for (const h of page.history ?? []) for (const m of h.messagesAdded ?? []) ids.push(m.message.id);
      historyId = page.historyId;
      pageToken = page.nextPageToken;
    } while (pageToken);
    return { ids: [...new Set(ids)], historyId };
  }

  /** Recovery listing: message IDs received after a time (seconds since epoch). */
  async messageIdsAfter(epochSeconds: number): Promise<string[]> {
    const ids: string[] = [];
    let pageToken: string | undefined;
    do {
      const page = await this.get<{ messages?: { id: string }[]; nextPageToken?: string }>('messages', {
        q: `after:${Math.floor(epochSeconds)}`,
        maxResults: '500',
        pageToken,
      });
      for (const m of page.messages ?? []) ids.push(m.id);
      pageToken = page.nextPageToken;
    } while (pageToken);
    return ids;
  }

  message(id: string): Promise<GmailMessage> {
    return this.get(`messages/${encodeURIComponent(id)}`, { format: 'full' });
  }
}
