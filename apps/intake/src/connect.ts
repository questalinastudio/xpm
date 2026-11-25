import { createServer, type Server } from 'node:http';
import type { Logger, MasterKey, Pool } from '@xpm/core';
import { scrubSecrets } from '@xpm/privacy';
import { buildAuthUrl, checkGrantedScopes, exchangeCode, GmailClient, revokeToken, type GoogleHttp, type OAuthClient } from './google.js';
import { saveConnection } from './gmailSync.js';

/**
 * One-time Gmail sign-in for a headless workstation.
 *
 * The helper listens on a loopback port (published only on the workstation's
 * 127.0.0.1). The owner forwards that port from a laptop over SSH, opens the
 * printed Google URL in the laptop's browser, and approves. Google redirects
 * to http://127.0.0.1:<port>/oauth/callback, which the SSH tunnel delivers to
 * this helper. No public callback and no LAN-reachable listener exist.
 */

export interface ConnectOptions {
  pool: Pool;
  mk: MasterKey;
  http: GoogleHttp;
  client: OAuthClient;
  account: string;
  port: number;
  listenHost?: string;
  log: Logger;
  timeoutMs?: number;
  onAuthUrl: (url: string) => void;
}

export interface ConnectResult {
  connectionId: string;
  account: string;
  reconnected: boolean;
}

const page = (title: string, body: string) =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font-family:system-ui;max-width:36rem;margin:4rem auto;padding:0 1rem"><h1>${title}</h1><p>${body}</p></body>`;

export function runConnectHelper(opts: ConnectOptions): Promise<ConnectResult> {
  const redirectUri = `http://127.0.0.1:${opts.port}/oauth/callback`;
  const session = buildAuthUrl(opts.http.endpoints, opts.client, redirectUri, opts.account);
  let server: Server;
  let settled = false;

  return new Promise<ConnectResult>((resolve, reject) => {
    const finish = (err: Error | null, result?: ConnectResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.close();
      if (err) reject(err);
      else resolve(result!);
    };
    const timer = setTimeout(() => finish(new Error('Timed out waiting for Google sign-in')), opts.timeoutMs ?? 10 * 60_000);

    server = createServer(async (req, res) => {
      const url = new URL(req.url ?? '/', redirectUri);
      if (url.pathname !== '/oauth/callback') {
        res.writeHead(404).end();
        return;
      }
      const send = (status: number, title: string, body: string) => {
        res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(page(title, body));
      };
      if (url.searchParams.get('state') !== session.state) {
        send(400, 'Sign-in rejected', 'The request did not match this sign-in session. Start again from the workstation.');
        return; // a stray or forged request does not end the session
      }
      const error = url.searchParams.get('error');
      if (error) {
        send(400, 'Sign-in cancelled', `Google returned: ${error.replace(/[<>&"]/g, '')}`);
        finish(new Error(`Google sign-in was not completed (${error})`));
        return;
      }
      const code = url.searchParams.get('code');
      if (!code) {
        send(400, 'Sign-in failed', 'No authorization code was returned.');
        finish(new Error('No authorization code returned'));
        return;
      }
      try {
        const tokens = await exchangeCode(opts.http, opts.client, session, code);
        const scopeProblem = checkGrantedScopes(tokens.scope);
        if (scopeProblem) {
          await revokeToken(opts.http, tokens.refreshToken ?? tokens.accessToken).catch(() => {});
          throw new Error(scopeProblem);
        }
        if (!tokens.refreshToken) throw new Error('Google did not return a refresh token; remove the app from your Google account and try again');
        const profile = await new GmailClient(opts.http, opts.client, tokens.refreshToken).profile();
        if (profile.emailAddress.toLowerCase() !== opts.account.toLowerCase()) {
          await revokeToken(opts.http, tokens.refreshToken).catch(() => {});
          throw new Error(`Signed in as ${profile.emailAddress}, but this connection is for ${opts.account}`);
        }
        const saved = await saveConnection(opts.pool, opts.mk, { account: opts.account, refreshToken: tokens.refreshToken, historyId: profile.historyId });
        send(200, 'Connected', `Questalina Desk can now read new mail for ${opts.account} (read-only). You can close this tab.`);
        finish(null, { connectionId: saved.id, account: opts.account.toLowerCase(), reconnected: saved.reconnected });
      } catch (err) {
        const message = scrubSecrets((err as Error).message);
        send(400, 'Sign-in failed', message.replace(/[<>&"]/g, ''));
        finish(new Error(message));
      }
    });
    server.listen(opts.port, opts.listenHost ?? '0.0.0.0', () => opts.onAuthUrl(session.url));
    server.on('error', (err) => finish(err));
  });
}
